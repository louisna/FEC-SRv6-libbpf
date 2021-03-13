#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "fec_srv6.h"
#include "libseg6.c"

#define DEBUG 1
#define BPF_ERROR BPF_DROP  // Choose action when an error occurs in the process

/* Structures */
struct sourceSymbol_t {
    unsigned char packet[MAX_PACKET_SIZE];
    uint16_t packet_length;
} BPF_PACKET_HEADER;

struct repairSymbol_t {
    unsigned char packet[MAX_PACKET_SIZE];
    int packet_length;
    unsigned char tlv[sizeof(struct coding_repair2_t)];
};

/* Maps */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, u16);
} indexTable SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct sourceSymbol_t);
} sourceSymbolBuffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct repairSymbol_t);
} repairSymbolBuffer SEC(".maps");

// TODO: perf output map

static __always_inline int loadAndDoXOR(struct __sk_buff *skb, struct repairSymbol_t *repairSymbol)
{
    if (DEBUG) bpf_printk("Sender: call doXOR\n");

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    int err;
    int k = 0;

    /* Get pointer to the IPv6 header of the packet, i.e. the beginning of the source symbol */
    struct ip6_t *ip6 = seg6_get_ipv6(skb);
    if (!ip6) {
        if (DEBUG) bpf_printk("Sender: impossible to get the IPv6 header\n");
        return -1;
    }

    /* Get the packet length from the IPv6 header to the end of the payload */
    u32 packet_len = ((long)data_end) - ((long)(void *)ip6);
    if ((void *)ip6 + packet_len > data_end) {
        if (DEBUG) bpf_printk("Sender: inconsistent payload length\n");
        return -1;
    }

    /* Ensures that we do not try to protect a too big packet */
    if (packet_len > MAX_PACKET_SIZE) {
        if (DEBUG) bpf_printk("Sender: too big packet, does not protect\n");
        return 1;
    }

    /* Get the source symbol from the buffer to store a copy of the packet */
    struct sourceSymbol_t *sourceSymbol =  bpf_map_lookup_elem(&sourceSymbolBuffer, &k);
    if (!sourceSymbol) {
        if (DEBUG) bpf_printk("Sender: impossible to get a pointer to store the source symbol\n");
        return -1;
    }
    memset(sourceSymbol, 0, sizeof(struct sourceSymbol_t)); // Clean the source symbol from previous packet

    u32 ipv6_offset = (long)ip6 - (long)data;
    if (ipv6_offset < 0) return -1;
    
    /* Load the payload of the packet and store it in sourceSymbol */
    const u16 size = packet_len - 1; // Small trick here because the verifier thinks the value can be negative
    if (size < sizeof(sourceSymbol->packet) && ipv6_offset + size <= (long)data_end) {
        // TODO: 0xffff should be set as global => ensures that the size is the max classic size of IPv6 packt
        err = bpf_skb_load_bytes(skb, ipv6_offset, (void *)sourceSymbol->packet, (size & 0xffff) + 1);
    } else {
        if (DEBUG) bpf_printk("Sender: Wrong ipv6_offset\n");
        return -1;
    }
    if (err < 0) {
        if (DEBUG) bpf_printk("Sender: impossible to load bytes from packet\n");
        return -1;
    }

    bpf_printk("Sender: Done storing of packet with bigger size ! %d\n", packet_len);
    
    /* Store the length of the packet that will be XORed */
    sourceSymbol->packet_length = packet_len;

    /* The maximal length of the source symbols of this block is also kept to know the size of the repair symbol.
     * This is done without branching. See:
     * https://www.geeksforgeeks.org/compute-the-minimum-or-maximum-max-of-two-integers-without-branching/ 
     */
    repairSymbol->packet_length = repairSymbol->packet_length ^ ((repairSymbol->packet_length ^ sourceSymbol->packet_length) & -(repairSymbol->packet_length < sourceSymbol->packet_length));

    /* Get the IPv6 header from the sourceSymbol pointer.
     * We must put the fields that may vary in the network to 0 because coding to ensure that the
     * decoded values on the decoder will be the same.
     * Destination address
     * Hot Limit
     */
    struct ip6_t *source_ipv6 = (struct ip6_t *)sourceSymbol;
    source_ipv6->dst_hi    = 0;
    source_ipv6->dst_lo    = 0;
    source_ipv6->hop_limit = 0;

    /* PERFORM XOR using 64 bits to have less iterations */
    u64 *source_long = (u64 *)sourceSymbol->packet;
    u64 *repair_long = (u64 *)repairSymbol->packet;
    int j;
    for (j = 0; j < MAX_PACKET_SIZE / sizeof(u64); ++j) {
        repair_long[j] = repair_long[j] ^ source_long[j];
    }

    /* Perform the XOR also on the length of the packet to be retrieved. This value belongs in the TLV */
    struct coding_repair2_t *repair_tlv = (struct coding_repair2_t *)&(repairSymbol->tlv);
    repair_tlv->payload_len = repair_tlv->payload_len ^ sourceSymbol->packet_length;

    if (DEBUG) bpf_printk("Sender: coded on the line a packet\n");

    return 0;
}

static __always_inline int codingXOR_on_the_line(struct __sk_buff *skb, u16 sourceBlock, u16 sourceSymbolCount) 
{
    int err;
    int k0 = 0;

    /* Load the unique repair symbol pointer from map */
    struct repairSymbol_t *repairSymbol = bpf_map_lookup_elem(&repairSymbolBuffer, &k0);
    if (!repairSymbol) {
        if (DEBUG) bpf_printk("Sender: impossible to get pointer to repairSymbol pointer\n");
        return -1;
    }

    /* Reset the repair symbol from previous block if this is new block */
    if (sourceSymbolCount == 0) {
        memset(repairSymbol, 0, sizeof(struct repairSymbol_t));
    }

    /* Do the XOR on the packet starting from the IPv6 header */
    err = loadAndDoXOR(skb, repairSymbol);
    if (err < 0) {
        if (DEBUG) bpf_printk("Sender: codingXOR error confirmed\n");
        return -1;
    } else if (err == 1) { // Cannot protect the packet because too big size
        if (DEBUG) bpf_printk("Sender: too big packet confirmed\n");
        return 2;
    }

    /* Creates the repair symbol TLV if the repair symbol must be sent */
    if (sourceSymbolCount == NB_SOURCE_SYMBOLS - 1) { // -1 to convert from number to index
        // Get the TLV from the repairSymbol pointer
        struct coding_repair2_t *repairTLV = (struct coding_repair2_t *)&(repairSymbol->tlv);
        repairTLV->tlv_type = TLV_CODING_REPAIR;
        repairTLV->len = sizeof(struct coding_repair2_t) - 2; // Does not include tlv_type and len
        repairTLV->sourceBlockNb = sourceBlock;
        repairTLV->repairSymbolNb = 0; // There is only one repair symbol
        repairTLV->nrs = 1;
        repairTLV->nss = NB_SOURCE_SYMBOLS;

        return 1;
    }

    return 0;
}
 
static __always_inline int fecFramework(struct __sk_buff *skb, struct coding_source_t *csh)
{
    int err;
    int k0 = 0; int k1 = 1;
    u16 *sourceBlock_p       = bpf_map_lookup_elem(&indexTable, &k0);
    u16 *sourceSymbolCount_p = bpf_map_lookup_elem(&indexTable, &k1);
    u16 sourceBlock; u16 sourceSymbolCount;

    /* Get current values of source block */
    if (!sourceBlock_p)
        sourceBlock = 0;
    else
        sourceBlock = *sourceBlock_p;
    if (!sourceSymbolCount_p)
        sourceSymbolCount = 0;
    else
        sourceSymbolCount = *sourceSymbolCount_p;
    
    /* Complete the source symbol TLV */
    memset(csh, 0, sizeof(struct coding_source_t));
    csh->tlv_type = TLV_CODING_SOURCE;
    csh->len = sizeof(struct coding_source_t) - 2; // Does not include tlv_type and len
    csh->sourceBlockNb = sourceBlock;
    csh->sourceSymbolNb = sourceSymbolCount;

    /* Call coding function. This function:
     * 1) Stores the source symbol for coding (or directly codes if XOR-on-the-line)
     * 2) Creates the repair symbols TLV if needed
     * 3) Returns: 1 to notify that repair symbols must be sent, 
     *            -1 in case of error,
     *             2 if the packet cannot be protected,
     *             0 otherwise
     */
    err = codingXOR_on_the_line(skb, sourceBlock, sourceSymbolCount);
    if (err < 0) { // Error
        if (DEBUG) bpf_printk("Sender fewFramework: error confirmed\n");
        return -1;
    } else if (err == 2) {
        if (DEBUG) bpf_printk("Sender: too big packet confirmed 2\n");
        return -1;
    }
    
    /* Update index counts */
    if (err == 1) { // Repair symbols must be sent
        ++sourceBlock; // Next packet will belong to another source block
        sourceSymbolCount = 0;
    } else {
        ++sourceSymbolCount;
    }

    /* Update map with new values */
    bpf_map_update_elem(&indexTable, &k0, &sourceBlock, BPF_ANY);
    bpf_map_update_elem(&indexTable, &k1, &sourceSymbolCount, BPF_ANY);

    return 0;
}

SEC("lwt_seg6local")
int notify_ok(struct __sk_buff *skb)
{
    bpf_printk("BPF triggered from packet with SRv6 !\n");

    int err;
    int k = 0;  // Key for hashmap

    /* Get Segment Routing Header */
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (!srh) {
        if (DEBUG) bpf_printk("Sender: impossible to get the SRH\n");
        return BPF_ERROR;
    }

    /* Create TLV structure and call FEC Framework */
    struct coding_source_t tlv;
    err = fecFramework(skb, &tlv);
    if (err < 0) {
        if (DEBUG) bpf_printk("Sender: Error in FEC Framework\n");
        return BPF_ERROR;
    }

    /* Send repair symbol(s) */
    if (err == 1) {
        struct repairSymbol_t *repair = bpf_map_lookup_elem(&repairSymbolBuffer, &k);
        if (!repair) {
            if (DEBUG) bpf_printk("Sender: impossible to get full repair symbol from buffer\n");
            return BPF_ERROR;
        }

        /* Submit repair symbol(s) to User Space using perf events */
        // TODO
    }

    /* Add the TLV to the current source symbol and forward */
    u16 tlv_length = sizeof(struct coding_source_t);
    err = seg6_add_tlv(skb, srh, (srh->hdrlen + 1) << 3, (struct sr6_tlv_t *)&tlv, tlv_length);
    if (DEBUG) bpf_printk("Sender: return value of TLV add: %d\n", err);
    return (err) ? BPF_ERROR : BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";