#ifndef VMLINUX_H_
#define VMLINUX_H_
#include <linux/bpf.h>
#endif
#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_
#include <bpf/bpf_helpers.h>
#endif
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "libseg6.c"
#include "encoder.h"

#define DEBUG 1
#define BPF_ERROR BPF_DROP  // Choose action when an error occurs in the process

/* Map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, mapStruct_t);
} fecBuffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, fecConvolution_t);
} fecConvolutionInfoMap SEC(".maps");

/* Perf even buffer */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline int storePacket(struct __sk_buff *skb, struct sourceSymbol_t *sourceSymbol) {

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
    __u32 packet_len = ((long)data_end) - ((long)(void *)ip6);
    if ((void *)ip6 + packet_len > data_end) {
        if (DEBUG) bpf_printk("Sender: inconsistent payload length\n");
        return -1;
    }

    /* Ensures that we do not try to protect a too big packet */
    if (packet_len > MAX_PACKET_SIZE) {
        if (DEBUG) bpf_printk("Sender: too big packet, does not protect\n");
        return 1;
    }

    __u32 ipv6_offset = (long)ip6 - (long)data;
    if (ipv6_offset < 0) return -1;

    /* Load the payload of the packet and store it in sourceSymbol */
    const __u16 size = packet_len - 1; // Small trick here because the verifier thinks the value can be negative
    if (size < sizeof(sourceSymbol->packet) && ipv6_offset + size <= (long)data_end) {
        // TODO: 0xffff should be set as global => ensures that the size is the max classic size of IPv6 packt
        err = bpf_skb_load_bytes(skb,    ipv6_offset, (void *)sourceSymbol->packet, (size & 0xffff) + 1);
    } else {
        if (DEBUG) bpf_printk("Sender: Wrong ipv6_offset\n");
        return -1;
    }
    if (err < 0) {
        if (DEBUG) bpf_printk("Sender: impossible to load bytes from packet\n");
        return -1;
    }

    if (DEBUG) bpf_printk("Sender: Done storing of packet with big size ! %d\n", packet_len);

    /* Store the length of the packet that will also be coded */
    sourceSymbol->packet_length = packet_len;

    /* Get the IPv6 header from the sourceSymbol pointer.
     * We must put the fields that may vary in the network to 0 because coding to ensure that the
     * decoded values on the decoder will be the same.
     * Destination address
     * Hot Limit */
    struct ip6_t *source_ipv6 = (struct ip6_t *)sourceSymbol->packet;
    source_ipv6->dst_hi    = 0;
    source_ipv6->dst_lo    = 0;
    source_ipv6->hop_limit = 0;

    /* Also get the Segment Routing header. We must set the value of segment_left to 0
     * as it will also be modified for the decoder */
    if (40 + sizeof(struct ip6_srh_t) > sizeof(sourceSymbol->packet)) {
        if (DEBUG) bpf_printk("Sender: cannot get the SRH from the sourceSymbol\n");
        return -1;
    }
    struct ip6_srh_t *srh = (struct ip6_srh_t *)(sourceSymbol->packet + 40);
    srh->segments_left = 0;

    if (DEBUG) bpf_printk("Sender: storePacket done");
    return 0;
}

static __always_inline int loadAndDoXOR(struct __sk_buff *skb, struct repairSymbol_t *repairSymbol, mapStruct_t *mapStruct)
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
    __u32 packet_len = ((long)data_end) - ((long)(void *)ip6);
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
    struct sourceSymbol_t *sourceSymbol = &mapStruct->sourceSymbol;
    memset(sourceSymbol, 0, sizeof(struct sourceSymbol_t)); // Clean the source symbol from previous packet

    __u32 ipv6_offset = (long)ip6 - (long)data;
    if (ipv6_offset < 0) return -1;
    
    /* Load the payload of the packet and store it in sourceSymbol */
    const __u16 size = packet_len - 1; // Small trick here because the verifier thinks the value can be negative
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

    if (DEBUG) bpf_printk("Sender: Done storing of packet with bigger size ! %d\n", packet_len);
    
    /* Store the length of the packet that will be XORed */
    sourceSymbol->packet_length = packet_len;

    /* The maximal length of the source symbols of this block is also kept to know the size of the repair symbol.
     * This is done without branching. See:
     * https://www.geeksforgeeks.org/compute-the-minimum-or-maximum-max-of-two-integers-without-branching/ */
    repairSymbol->packet_length = repairSymbol->packet_length ^ ((repairSymbol->packet_length ^ sourceSymbol->packet_length) & -(repairSymbol->packet_length < sourceSymbol->packet_length));

    /* Get the IPv6 header from the sourceSymbol pointer.
     * We must put the fields that may vary in the network to 0 because coding to ensure that the
     * decoded values on the decoder will be the same.
     * Destination address
     * Hot Limit */
    struct ip6_t *source_ipv6 = (struct ip6_t *)sourceSymbol->packet;
    source_ipv6->dst_hi    = 0;
    source_ipv6->dst_lo    = 0;
    source_ipv6->hop_limit = 0;

    /* Also get the Segment Routing header. We must set the value of segment_left to 0
     * as it will also be modified for the decoder */
    if (40 + sizeof(struct ip6_srh_t) > sizeof(sourceSymbol->packet)) {
        if (DEBUG) bpf_printk("Sender: cannot get the SRH from the sourceSymbol\n");
        return -1;
    }
    struct ip6_srh_t *srh = (struct ip6_srh_t *)(sourceSymbol->packet + 40);
    srh->segments_left = 0;

    /* PERFORM XOR using 64 bits to have less iterations */
    __u64 *source_long = (__u64 *)sourceSymbol->packet;
    __u64 *repair_long = (__u64 *)repairSymbol->packet;

    #pragma clang loop unroll(full)
    for (int j = 0; j < MAX_PACKET_SIZE / sizeof(__u64); ++j) {
        repair_long[j] = repair_long[j] ^ source_long[j];
    }

    /* Perform the XOR also on the length of the packet to be retrieved. This value belongs in the TLV */
    struct tlvRepair__block_t *repair_tlv = (struct tlvRepair__block_t *)&(repairSymbol->tlv);
    repair_tlv->payload_len = repair_tlv->payload_len ^ sourceSymbol->packet_length;

    if (DEBUG) bpf_printk("Sender: coded on the line a packet\n");

    return 0;
}

static __always_inline int codingXOR_on_the_line(struct __sk_buff *skb, mapStruct_t *mapStruct) 
{
    int err;
    int k0 = 0;

    __u16 sourceBlock = mapStruct->soubleBlock; 
    __u16 sourceSymbolCount = mapStruct->sourceSymbolCount;

    /* Load the unique repair symbol pointer from map */
    struct repairSymbol_t *repairSymbol = &mapStruct->repairSymbol;

    /* Reset the repair symbol from previous block if this is new block */
    if (sourceSymbolCount == 0) {
        memset(repairSymbol, 0, sizeof(struct repairSymbol_t));
    }

    /* Do the XOR on the packet starting from the IPv6 header */
    err = loadAndDoXOR(skb, repairSymbol, mapStruct);
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
        struct tlvRepair__block_t *repairTLV = (struct tlvRepair__block_t *)&(repairSymbol->tlv);
        repairTLV->tlv_type = TLV_CODING_REPAIR;
        repairTLV->len = sizeof(struct tlvRepair__block_t) - 2; // Does not include tlv_type and len
        repairTLV->sourceBlockNb = sourceBlock;
        repairTLV->repairSymbolNb = 0; // There is only one repair symbol
        repairTLV->nrs = 1;
        repairTLV->nss = NB_SOURCE_SYMBOLS;

        return 1;
    }

    return 0;
}
 
static __always_inline int fecFramework(struct __sk_buff *skb, struct tlvSource__block_t *csh, mapStruct_t *mapStruct)
{
    int err;
    __u16 sourceBlock = mapStruct->soubleBlock; 
    __u16 sourceSymbolCount = mapStruct->sourceSymbolCount;
    
    /* Complete the source symbol TLV */
    memset(csh, 0, sizeof(struct tlvSource__block_t));
    csh->tlv_type = TLV_CODING_SOURCE;
    csh->len = sizeof(struct tlvSource__block_t) - 2; // Does not include tlv_type and len
    csh->sourceBlockNb = sourceBlock;
    csh->sourceSymbolNb = sourceSymbolCount;

    /* Call coding function. This function:
     * 1) Stores the source symbol for coding (or directly codes if XOR-on-the-line)
     * 2) Creates the repair symbols TLV if needed
     * 3) Returns: 1 to notify that repair symbols must be sent, 
     *            -1 in case of error,
     *             2 if the packet cannot be protected,
     *             0 otherwise */
    err = codingXOR_on_the_line(skb, mapStruct);
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

    /* Update with new values */
    mapStruct->soubleBlock = sourceBlock;
    mapStruct->sourceSymbolCount = sourceSymbolCount;

    return err;
}

static __always_inline int fecScheme__convoRLC(struct __sk_buff *skb, fecConvolution_t *fecConvolution) {
    int err;
    __u32 encodingSymbolID = fecConvolution->encodingSymbolID;
    __u8 repairKey = fecConvolution->repairKey;
    __u8 ringBuffSize = fecConvolution->ringBuffSize;


    /* Get pointer in the ring buffer to store the source symbol */
    __u32 ringBufferIndex = encodingSymbolID % RLC_WINDOW_SIZE;
    if (ringBufferIndex < 0 || ringBufferIndex >= RLC_WINDOW_SIZE) { // Check for the eBPF verifier
        if (DEBUG) bpf_printk("Sender: RLC index to ring buffer\n");
        return -1;
    }
    // If verifier complains: try fecConvolution->sourceRingBuffer + ringBufferIndex
    struct sourceSymbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[ringBufferIndex & 0xff];
    memset(sourceSymbol, 0, sizeof(struct sourceSymbol_t)); // Optimization: not use memset but use packet_length for all ?

    /* Store source symbol */
    err = storePacket(skb, sourceSymbol);
    if (err < 0) { // Error
        if (DEBUG) bpf_printk("Sender: error from storePacket confirmed\n");
        return -1;
    } else if (err > 0) {
        if (DEBUG) bpf_printk("Sender: confirmed packet too big for protection\n");
        return -1;
    }

    /* The ring buffer contains a new source symbol */
    ++ringBuffSize;

    //bpf_printk("Oui oui est-ce que ca a fonctionne: %d %d %d\n", ringBufferIndex, sourceSymbol->packet_length, ringBuffSize);

    /* Compute the repair symbol if needed */
    if (ringBuffSize == RLC_WINDOW_SIZE) {
        ++repairKey;
        /* Start to complete the TLV for the repair symbol. The remaining will be done in US */
        struct tlvRepair__convo_t *repairTlv = (struct tlvRepair__convo_t *)&fecConvolution->repairTlv;
        // memset(repairTlv, 0, sizeof(tlvRepair__convo_t));
        repairTlv->tlv_type = TLV_CODING_REPAIR; // TODO: change also ?
        repairTlv->len = sizeof(struct tlvRepair__convo_t) - 2;
        repairTlv->encodingSymbolID = encodingSymbolID; // Set to the value of the last source symbol of the window
        repairTlv->repairFecInfo = (0 << 24) + repairKey;
        // repairTlv->payload_len = 0; // TODO: compute the coded length 
        repairTlv->nss = RLC_WINDOW_SIZE;
        repairTlv->nrs = 1;

        /* Reset parameters for the next window */
        fecConvolution->ringBuffSize = ringBuffSize - RLC_WINDOW_SLIDE; // For next window, already some symbols
        fecConvolution->repairKey = repairKey; // Increment the repair key seed

        /* Indicate to the FEC Framework that a repair symbol has been generated */
        return 1;
    }

    fecConvolution->ringBuffSize = ringBuffSize;

    /* Indicate to the FEC Framework that no repair symbol has been generated */
    return 0;
}

static __always_inline int fecFramework__convolution(struct __sk_buff *skb, struct tlvSource__convo_t *tlv, fecConvolution_t *fecConvolution) {
    int ret;
    __u32 encodingSymbolID = fecConvolution->encodingSymbolID;
    __u8 repairKey = fecConvolution->repairKey;
    __u8 ringBuffSize = fecConvolution->ringBuffSize;
    __u8 DT = 5; // TODO find good value

    /* Complete the source symbol TLV */
    memset(tlv, 0, sizeof(struct tlvSource__convo_t));
    tlv->tlv_type = TLV_CODING_SOURCE; // TODO: other value to distinguish ??
    tlv->len = sizeof(struct tlvSource__convo_t) - 2;
    tlv->encodingSymbolID = encodingSymbolID;

    /* Call coding function */
    ret = fecScheme__convoRLC(skb, fecConvolution);
    if (ret < 0) {
        return -1;
    }

    /* A repair symbol must be generated
     * Forward all data to user space for computation */
    if (ret) {
        //bpf_printk("Send data to user space for repair symbol generation\n");
        bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, fecConvolution, sizeof(fecConvolution_t));
    }

    /* Update encodingSymbolID: wraps to zero after 2^32 - 1 */
    fecConvolution->encodingSymbolID = encodingSymbolID + 1;

    return ret;
}

SEC("lwt_seg6local")
int notify_ok(struct __sk_buff *skb)
{
    if (DEBUG) bpf_printk("BPF triggered from packet with SRv6 !\n");
    //val[0] = 1;
    //bpf_printk("Value de val: %d\n", val[0]);

    int err;
    int k = 0;  // Key for hashmap

    /* Get Segment Routing Header */
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (!srh) {
        if (DEBUG) bpf_printk("Sender: impossible to get the SRH\n");
        return BPF_ERROR;
    }

    /* Get pointer to structure of the plugin
    mapStruct_t *mapStruct = bpf_map_lookup_elem(&fecBuffer, &k);
    if (!mapStruct) {
        if (DEBUG) bpf_printk("Sender: impossible to get global pointer\n");
        return BPF_ERROR;
    } */

    /* Create TLV structure and call FEC Framework
    struct tlvSource__block_t tlv;
    err = fecFramework(skb, &tlv, mapStruct);
    if (err < 0) {
        if (DEBUG) bpf_printk("Sender: Error in FEC Framework\n");
        return BPF_ERROR;
    } */

    fecConvolution_t *fecConvolution = bpf_map_lookup_elem(&fecConvolutionInfoMap, &k);
    if (!fecConvolution) return BPF_ERROR;

    struct tlvSource__convo_t tlv;
    err = fecFramework__convolution(skb, &tlv, fecConvolution);
    if (err < 0) {
        if (DEBUG) bpf_printk("Sender: Error in FEC Framework\n");
        return BPF_ERROR;
    }

    /* Add the TLV to the current source symbol and forward */
    __u16 tlv_length = sizeof(struct tlvSource__convo_t);
    err = seg6_add_tlv(skb, srh, (srh->hdrlen + 1) << 3, (struct sr6_tlv_t *)&tlv, tlv_length);
    bpf_printk("Sender: return value of TLV add: %d\n", err);
    return (err) ? BPF_ERROR : BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";
