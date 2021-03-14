#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "fec_srv6.h"
#include "libseg6.c"

#define DEBUG 1
#define BPF_ERROR BPF_DROP  // Choose action when an error occurs in the process

#define MAX_BLOCK 5  // Number of blocks we can simultaneously store
#define MAX_SOURCE_SYMBOLS 25  // Number of source symbols per block
#define DEBUG 1

/* Structures */
struct sourceSymbol_t {
    struct coding_source_t tlv;
    unsigned char packet[MAX_PACKET_SIZE];
    u16 packet_length;
} BPF_PACKET_HEADER;

struct repairSymbol_t {
    unsigned char packet[MAX_PACKET_SIZE];
    int packet_length; // TODO: change to u16 ?
    struct coding_repair2_t tlv;
};

struct sourceBlock_t {
    unsigned short blockID;
    unsigned char receivedSource;
    unsigned char receivedRepair;
    unsigned char nss;
    unsigned char nrs;
};

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct sourceSymbol_t);
} sourceSymbolBuffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCK);
    __type(key, u32);
    __type(value, struct repairSymbol_t);
} repairSymbolBuffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCK);
    __type(key, u32);
    __type(value, struct sourceBlock_t);
} blockBuffer SEC(".maps");

static inline int decodingSourceXOR_on_the_line(struct __sk_buff *skb, struct sourceSymbol_t *sourceSymbol) {
    int err;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Get the IPv6 header of the packet */
    struct ip6_t *ip6 = seg6_get_ipv6(skb);
    if (!ip6) {
        if (DEBUG) bpf_printk("Receiver: impossible to get the IPv6 header\n");
        return -1;
    }

    
}

static inline u16 fecFrameworkSource(struct __sk_buff *skb, int tlv_offset, struct ip6_srh_t *srh) {
    int err;
    int k = 0;

    /* Get a pointer to the source symbol structure from map */
    struct sourceSymbol_t *sourceSymbol = bpf_map_lookup_elem(&sourceSymbolBuffer, &k);
    if (!sourceSymbol) {
        if (DEBUG) bpf_printk("Receiver: impossible to get pointer to source symbol");
        return -1;
    }

    /* Load the TLV in the structure */
    struct coding_source_t tlv = sourceSymbol->tlv;
    err = bpf_skb_load_bytes(skb, tlv_offset, &tlv, sizeof(struct coding_source_t));
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load the source TLV\n");
        return -1;
    }

    /* Get information about the source symbol */
    u16 sourceBlockNb = tlv.sourceBlockNb;
    u16 sourceSymbolNb = tlv.sourceSymbolNb;

    /* Get index of the repair symbol based on the block */
    int k_block = sourceBlockNb % MAX_BLOCK;
    if (k_block < 0 || k_block >= MAX_BLOCK) { // TODO: remove this block because should be useless
        if (DEBUG) bpf_printk("Receiver: wrong block index from source framework\n");
        return -1;
    }

    /* Get information about this block number and update the structure */
    struct sourceBlock_t *sourceBlock = bpf_map_lookup_elem(&blockBuffer, &k_block);
    if (!sourceBlock) {
        bpf_printk("Receiver: impossible to get a pointer to the source block (source framework)\n");
        return -1;
    }

    /* If we already have information about this source block
     *      => Just increment the number of received source symbols for this block ID
     * Else => Reset the structure for this new block
     */
    if (sourceBlock->blockID == sourceBlockNb) {
        ++sourceBlock->blockID;
    } else {
        sourceBlock->blockID = sourceBlockNb;
        sourceBlock->receivedSource = 1; // We have received this first source symbol for this block !
        sourceBlock->receivedRepair = 0;
        sourceBlock->nss = 0;
        sourceBlock->nrs = 0;
    }

    /* If this is the first received source symbol and we did not received yet
     * the repair symbol for this block, we reset the memory of the repair symbol
     * of this block to 0
     */
    if (sourceBlock->receivedSource == 1 && sourceBlock->receivedRepair == 0) {
        // First load the repair symbol pointer
        struct repairSymbol_t *repairSymbol = bpf_map_lookup_elem(&repairSymbolBuffer, &k_block);
        if (!repairSymbol) {
            if (DEBUG) bpf_printk("Receiver: impossible to get a pointer to the repair symbol (fec source)\n");
            return -1;
        }
        memset(repairSymbol, 0, sizeof(struct repairSymbol_t));
    }

    // Remove the TLV from the packet as we have a local copy
    err = seg6_delete_tlv2(skb, srh, tlv_offset);
    if (err != 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to remove the source TLV from the packet\n");
        return -1;
    }
    
    /* Call decoding function. This function:
     * 1) Stores the source symbol for decoding (or directly decodes if XOR-on-the-line)
     */
    err = decodingSourceXOR_on_the_line(skb, sourceSymbol);
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: error confirmed from decodingXOR\n");
        return -1;
    }

    return sourceBlockNb;
}

static inline u16 fecFrameworkRepair(struct __sk_buff *skb, int tlv_offset, struct ip6_srh_t *srh) {
    return 0;
}

static inline bool canDecodeXOR(u16 blockID) {
    int k = blockID % MAX_BLOCK;
    struct sourceBlock_t *sourceBlock = bpf_map_lookup_elem(&blockBuffer, &k);
    if (!sourceBlock) return 0;

    /* Still not received the repair symbol */
    if (!sourceBlock->receivedRepair) {
        if (DEBUG) bpf_printk("Receiver: waiting for the repair symbol\n");
        return 0;
    }

    /* Count the number of lost packets
     * If no loss, no need for recovery;
     * If more than one loss in this repair block, cannot recover
     * TODO: if we disable the tracing, we can make only one if condition
     */
    int total_loss = sourceBlock->nss - sourceBlock->receivedSource;
    if (total_loss == 0) {
        if (DEBUG) bpf_printk("Receiver: no loss, no need for recovery\n");
        return 0;
    } else if (total_loss > 1) {
        if (DEBUG) bpf_printk("Receiver: too much loss for recovery\n");
        return 0;
    }

    /* At this point, we know we can send a recovered packet */
    if (DEBUG) bpf_printk("Receiver: can recover from a lost packet\n");
    return 1;

}

static inline bool canDecode(u16 blockID) {
    return canDecodeXOR(blockID);
}

SEC("lwt_seg6local")
int decode(struct __sk_buff *skb) {
    if (DEBUG) bpf_printk("Receiver: BPF triggered from packet with SRv6!\n");
    int err;
    int k = 0;
    
    /* Get the Segment Routing Header of the packet */
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (!srh) {
        if (DEBUG) bpf_printk("Receiver: impossible to get the SRH\n");
        return BPF_ERROR;
    }

    /* Get the TLV from the SRH */
    int tlv_type = 0; // Know whether the packet is a source or a repair symbol
    long cursor = seg6_find_tlv2(skb, srh, &tlv_type, sizeof(struct coding_source_t), sizeof(struct coding_repair2_t));
    if (cursor < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to get the TLV\n");
        return BPF_ERROR;
    }
    if (tlv_type != TLV_CODING_SOURCE && tlv_type != TLV_CODING_REPAIR) { // Should not enter in this condition
        if (DEBUG) bpf_printk("Receiver: does not contain a source/repair TLV\n");
        return BPF_ERROR;
    }

    /* Call FEC framework depending on the type of packet */
    u16 blockID; // Block number of the received packet
    if (tlv_type == TLV_CODING_SOURCE) {
        blockID = fecFrameworkSource(skb, cursor, srh);
    } else {
        blockID = fecFrameworkRepair(skb, cursor, srh);
    }
    if (blockID < 0) {
        if (DEBUG) bpf_printk("Receiver: fec framework fail confirmed\n");
        return BPF_ERROR;
    }

    /* If we can recover from a loss, send the decoded information 
     * to user space to send new packet */
    if (canDecode(blockID)) {
        // TODO: make it convertible for multiple coding functions
        k = blockID % MAX_BLOCK;
        struct repairSymbol_t *repairSymbol = bpf_map_lookup_elem(&repairSymbolBuffer, &k);
        if (!repairSymbol) {
            if (DEBUG) bpf_printk("Receiver: impossible to get repairSymbol pointer from sending\n");
            return BPF_ERROR;
        }

        // TODO: Send to user space information
    }

    /* The repair symbol(s) must be dropped because not useful for the rest of the network */
    if (tlv_type == TLV_CODING_REPAIR) {
        return BPF_DROP;
    }

    if (DEBUG) bpf_printk("Receiver: done FEC\n");
    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";