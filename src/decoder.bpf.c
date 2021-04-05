#ifndef BPF_H_
#define BPF_H_
#include <linux/bpf.h>
#endif
#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_
#include <bpf/bpf_helpers.h>
#endif
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "libseg6_decoder.c"
#include "decoder.h"

#define DEBUG 1

typedef struct xorStruct {
    struct sourceSymbol_t sourceSymbol;
    struct repairSymbol_t repairSymbols;
    struct sourceBlock_t sourceBlocks;
} xorStruct_t;

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCK);
    __type(key, __u32);
    __type(value, xorStruct_t);
} xorBuffer SEC(".maps");

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

static __always_inline int decodingSourceXOR_on_the_line(struct __sk_buff *skb, struct tlvSource__block_t *tlv, struct sourceBlock_t *sourceBlock, int k_block, xorStruct_t *xorStruct) {
    int err;
    int k = 0;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Get a pointer to the source symbol structure from map */
    struct sourceSymbol_t *sourceSymbol = &(xorStruct->sourceSymbol);
    memset(sourceSymbol, 0, sizeof(struct sourceSymbol_t)); // Clean the source symbol from previous packet

    /* Copy the TLV in the pointer */
    memcpy(&(sourceSymbol->tlv), tlv, sizeof(struct tlvSource__block_t));

    /* Get pointer to the repair symbol for decoding */
    struct repairSymbol_t *repairSymbol = &(xorStruct->repairSymbols);

    /* If this is the first received source symbol and we did not received yet
     * the repair symbol for this block, we reset the memory of the repair symbol
     * of this block to 0
     */
    if (sourceBlock->receivedSource == 1 && sourceBlock->receivedRepair == 0) {
        memset(repairSymbol, 0, sizeof(struct repairSymbol_t));
    }

    /* Get the IPv6 header of the packet, i.e. the beginning of the source symbol */
    struct ip6_t *ip6 = seg6_get_ipv6(skb);
    if (!ip6) {
        if (DEBUG) bpf_printk("Receiver: impossible to get the IPv6 header\n");
        return -1;
    }

    /* Get the packet length from the IPv6 header to the end of the payload */
    __u32 packet_len = ((long)data_end) - ((long)(void *)ip6);
    if ((void *)ip6 + packet_len > data_end) {
        if (DEBUG) bpf_printk("Receiver: inconsistent payload length\n");
        return -1;
    }

    /* Ensures that we do not try to protect a too big packet */
    if (packet_len > MAX_PACKET_SIZE) {
        if (DEBUG) bpf_printk("Receiver: too big packet, does not protect\n");
        return 1;
    }

    __u32 ipv6_offset = (long)ip6 - (long)data;
    if (ipv6_offset < 0) return -1;

    /* Load the payload of the packet and store it in sourceSymbol */
    const __u16 size = packet_len - 1; // Small trick here because the verifier thinks the value can be negative
    if (size < sizeof(sourceSymbol->packet) && ipv6_offset + size <= (long)data_end) {
        // TODO: 0xffff should be set as global => ensures that the size is the max classic size of IPv6 packt
        err = bpf_skb_load_bytes(skb, ipv6_offset, (void *)sourceSymbol->packet, (size & 0xffff) + 1);
    } else {
        if (DEBUG) bpf_printk("Receiver: Wrong ipv6_offset\n");
        return -1;
    }
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load bytes from packet\n");
        return -1;
    }

    if (DEBUG) bpf_printk("Receiver: Done storing of packet with bigger size ! %d\n", packet_len);

    /* Store the length of the packet that will be de-XORed */
    sourceSymbol->packet_length = packet_len;

    /* Get the IPv6 header from the sourceSymbol pointer.
     * We must put the fields that may vary in the network to 0 because coding to ensure that the
     * decoded values on the decoder will be the same.
     * Destination address
     * Hot Limit
     */
    struct ip6_t *source_ipv6 = (struct ip6_t *)sourceSymbol->packet;
    source_ipv6->dst_hi    = 0;
    source_ipv6->dst_lo    = 0;
    source_ipv6->hop_limit = 0;

    /* Unfortunately, the seg6_delete_tlv function does not update the length of the SRH when we
     * remove the TLV. We need to locally update this value in the sourceSymbol version of the packet.
     * We cannot use seg6_get_srh because we work with local structure and not with __sk_buff
     */
    if (40 + sizeof(struct ip6_srh_t) > sizeof(sourceSymbol->packet)) {
        if (DEBUG) bpf_printk("Receiver: cannot get the SRH from the sourceSymbol\n");
        return -1;
    }
    struct ip6_srh_t *srh = (struct ip6_srh_t *)(sourceSymbol->packet + 40); // Skip IPv6 header
    srh->hdrlen -= 1; // TODO: more clean ?

    /* Also remove the segment_left entry of the Segment Routing header as it varied from the encoder */
    srh->segments_left = 0;

    /* PERFORM XOR using 64 bites to have less iterations */
    __u64 *source_long = (__u64 *)sourceSymbol->packet;
    __u64 *repair_long = (__u64 *)repairSymbol->packet;

    #pragma clang loop unroll(full)
    for (int j = 0; j < MAX_PACKET_SIZE / sizeof(__u64); ++j) {
        repair_long[j] = repair_long[j] ^ source_long[j];
    }

    /* Get the repair TLV (which can contain only 0 if no repair symbol is received)
     * and perform the XOR on the length of the packet to be retrieved
     */
    struct tlvRepair__block_t *repair_tlv = (struct tlvRepair__block_t *)&(repairSymbol->tlv);
    repair_tlv->payload_len = repair_tlv->payload_len ^ sourceSymbol->packet_length;

    if (DEBUG) bpf_printk("Receiver: decoded on the line a packet\n");
    
    return 0;
}

static __always_inline int decodingRepairXOR_on_the_line(struct __sk_buff *skb, struct ip6_srh_t *srh, struct tlvRepair__block_t *tlv, struct sourceBlock_t *sourceBlock, int k_block, xorStruct_t *xorStruct) {
    int err;
    int k = 0;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    /* Load the repair symbol structure pointer */
    struct repairSymbol_t *repairSymbol = &(xorStruct->repairSymbols);

    /* Load the source symbol structure and reset it to clean from previous source symbol */
    struct sourceSymbol_t *sourceSymbol = &(xorStruct->sourceSymbol);

    /* If no source symbol is received at this point, reset the repairSymbol from previous block */
    if (sourceBlock->receivedSource == 0) {
        memset(repairSymbol, 0, sizeof(struct repairSymbol_t));
    }

    /* Copy the TLV in the pointer */
    memcpy(&(repairSymbol->tlv), tlv, sizeof(struct tlvRepair__block_t));

    /* Get the payload of the packet which contains the repair symbol */
    void *payload_pointer = seg6_find_payload(skb, srh);
    if (!payload_pointer) {
        if (DEBUG) bpf_printk("Receiver: impossible to get the Repair Symbol payload\n");
        return -2;
    }

    /* The payload contains the repair symbol, but also the transport header which must be skipped
     * By construction, this transport header is a simple UDP transport header
     */
    if (payload_pointer + 8 > data_end) {
        if (DEBUG) bpf_printk("Receiver: cannot get passed the transport header\n");
        return -1;
    }
    payload_pointer += 8 * sizeof(char);

    /* Get the packet payload length */
    __u32 payload_len = ((long)data_end) - ((long)payload_pointer);
    if (payload_pointer + payload_len > data_end) {
        if (DEBUG) bpf_printk("Receiver: inconsistent payload\n");
        return -1;
    }

    /* We use a small trick here. We cannot use the repairSymbol to store the repair symbol of the packet
     * because it may contain already decoded information. So we store it in sourceSymbol_t structure
     */
    __u32 payload_offset = (long)payload_pointer - (long)data;
    const __u16 size = payload_len - 1;
    if (size < sizeof(sourceSymbol->packet) && payload_offset + size <= (long)data_end) {
        err = bpf_skb_load_bytes(skb, payload_offset, (void *)sourceSymbol->packet, (size & 0xffff) + 1);
    } else {
        if (DEBUG) bpf_printk("Receiver: Wrong offset\n");
        return -1;
    }
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load bytes\n");
        return -1;
    }

    /* Continue the decoding. Could be more performant if only memcpy if no source symbo received yet */
    repairSymbol->packet_length = repairSymbol->packet_length ^ tlv->payload_len;
    
    /* PERFORM XOR using 64 bites to have less iterations */
    __u64 *repair_long = (__u64 *)repairSymbol->packet;
    __u64 *stored_long = (__u64 *)sourceSymbol->packet;

    #pragma clang loop unroll(full)
    for (int j = 0; j < MAX_PACKET_SIZE / sizeof(__u64); ++j) {
        repair_long[j] = repair_long[j] ^ stored_long[j];
    }

    if (DEBUG) bpf_printk("Receiver: performed de-XORing with a repair symbol\n");

    return 0;
}

static __always_inline xorStruct_t *fecFrameworkSource(struct __sk_buff *skb, int tlv_offset, struct ip6_srh_t *srh) {
    int err;
    int k = 0;

    /* Load the TLV in the structure */
    struct tlvSource__block_t tlv;
    err = bpf_skb_load_bytes(skb, tlv_offset, &tlv, sizeof(struct tlvSource__block_t));
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load the source TLV\n");
        return 0;
    }

    /* Get information about the source symbol */
    __u16 sourceBlockNb = tlv.sourceBlockNb;
    __u16 sourceSymbolNb = tlv.sourceSymbolNb;

    /* Get index of the repair symbol based on the block */
    __u32 k_block = sourceBlockNb % MAX_BLOCK;
    if (k_block < 0 || k_block >= MAX_BLOCK) { // TODO: remove this block because should be useless
        if (DEBUG) bpf_printk("Receiver: wrong block index from source framework\n");
        return 0;
    }

    xorStruct_t *xorStruct = bpf_map_lookup_elem(&xorBuffer, &k_block);
    if (!xorStruct) {
        if (DEBUG) bpf_printk("Receiver: impossible to get pointer to globla structure\n");
        return 0;
    }

    /* Get information about this block number and update the structure */
    struct sourceBlock_t *sourceBlock = &(xorStruct->sourceBlocks);

    /* If we already have information about this source block
     *      => Just increment the number of received source symbols for this block ID
     * Else => Reset the structure for this new block
     */
    if (sourceBlock->blockID == sourceBlockNb) {
        ++sourceBlock->receivedSource;
    } else {
        sourceBlock->blockID = sourceBlockNb;
        sourceBlock->receivedSource = 1; // We have received this first source symbol for this block !
        sourceBlock->receivedRepair = 0;
        sourceBlock->nss = 0;
        sourceBlock->nrs = 0;
    }

    // Remove the TLV from the packet as we have a local copy
    err = seg6_delete_tlv2(skb, srh, tlv_offset);
    if (err != 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to remove the source TLV from the packet\n");
        return 0;
    }
    
    /* Call decoding function. This function:
     * 1) Stores the source symbol for decoding (or directly decodes if XOR-on-the-line)
     * 2) If this is the first source for this block, re-init the corresponding repair block
     * 3) Keep a copy of the TLV
     */
    err = decodingSourceXOR_on_the_line(skb, &tlv, sourceBlock, k_block, xorStruct);
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: error confirmed from decodingXOR\n");
        return 0;
    }

    return xorStruct;
}

static __always_inline xorStruct_t *fecFrameworkRepair(struct __sk_buff *skb, int tlv_offset, struct ip6_srh_t *srh) {
    int err;
    int k0 = 0;

    if (DEBUG) bpf_printk("Receiver: TRIGGERED FROM REPAIR SYMBOL\n");

    /* Here must first load the repair TLV to know the source block, to load the good repair pointer */
    struct tlvRepair__block_t tlv;
    err = bpf_skb_load_bytes(skb, tlv_offset, &tlv, sizeof(struct tlvRepair__block_t));
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load the repair TLV\n");
        return 0;
    }

    /* Retrieve the block number and the corresponding index */
    __u16 blockID = tlv.sourceBlockNb;
    int k_block = blockID % MAX_BLOCK;

    xorStruct_t *xorStruct = bpf_map_lookup_elem(&xorBuffer, &k_block);
    if (!xorStruct) {
        if (DEBUG) bpf_printk("Receiver: impossible to get pointer to globla structure\n");
        return 0;
    }

    /* Get information about this block number and update the structure */
    struct sourceBlock_t *sourceBlock = &(xorStruct->sourceBlocks);

    /* If we already have information about this source block
     *      => Just add information about the repair symbol
     * Else => Reset the structure for this new block
     */
    if (sourceBlock->blockID != blockID) {
        sourceBlock->blockID = blockID;
        sourceBlock->receivedSource = 0;
    }
    sourceBlock->receivedRepair = 1; // TODO: make +1 instead ?
    sourceBlock->nss = tlv.nss;
    sourceBlock->nrs = tlv.nrs;

    // Here no need to remove the TLV from the packet because it will be dropped anyway

    /* Call the decoding function. This function:
     * 1) Stores the repair symbol for decoding (or directly decodes if XOR-on-the-line)
     * 2) If this is the first symbol for this block, re-init the corresponding repair block
     */
    err = decodingRepairXOR_on_the_line(skb, srh, &tlv, sourceBlock, k_block, xorStruct);
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: error confirmed from decodingXOR repair\n");
        return 0;
    }

    return xorStruct;

}

static __always_inline int canDecodeXOR(xorStruct_t *xorStruct) {
    struct sourceBlock_t *sourceBlock = &(xorStruct->sourceBlocks);

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
    if (DEBUG) bpf_printk("Receiver: receivedSource: %d and nss: %d\n", sourceBlock->receivedSource, sourceBlock->nss);
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

static __always_inline int canDecode(xorStruct_t *xorStruct) {
    return canDecodeXOR(xorStruct);
}

static __always_inline int storePacket(struct __sk_buff *skb, struct sourceSymbol_t *sourceSymbol) {
    int err;

    void *data = (void *)(long)(skb->data);
    void *data_end = (void *)(long)(skb->data_end);

    /* Get pointer to the IPv6 header of the packet, i.e. the beginning of the source symbol */
    struct ip6_t *ip6 = seg6_get_ipv6(skb);
    if (!ip6) {
        if (DEBUG) bpf_printk("Receiver: impossible to get the IPv6 header\n");
        return -1;
    }

    /* Get the packet length from the IPv6 header to the end of the payload */
    __u32 packet_len = ((long)data_end) - ((long)(void *)ip6);
    if ((void *)ip6 + packet_len > data_end) {
        if (DEBUG) bpf_printk("Receiver: inconsistent payload length\n");
        return -1;
    }

    /* Ensures that we do not try to protect a too big packet */
    if (packet_len > MAX_PACKET_SIZE) {
        if (DEBUG) bpf_printk("Receiver: too big packet, does not protect\n");
        return 1;
    }

    __u32 ipv6_offset = (long)ip6 - (long)data;
    if (ipv6_offset < 0) return -1;

    /* Load the payload of the packet and store it in sourceSymbol */
    const __u16 size = packet_len - 1; // Small trick here because the verifier thinks the value can be negative
    if (size < sizeof(sourceSymbol->packet) && ipv6_offset + size <= (long)data_end) {
        // TODO: 0xffff should be set as global => ensures that the size is the max classic size of IPv6 packt
        err = bpf_skb_load_bytes(skb, ipv6_offset, (void *)sourceSymbol->packet, (size & 0xffff) + 1);
    } else {
        if (DEBUG) bpf_printk("Receiver: Wrong ipv6_offset\n");
        return -1;
    }
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load bytes from packet\n");
        return -1;
    }

    if (DEBUG) bpf_printk("Receiver: Done storing of packet with big size ! %d\n", packet_len);

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
        if (DEBUG) bpf_printk("Receiver: cannot get the SRH from the sourceSymbol\n");
        return -1;
    }
    struct ip6_srh_t *srh = (struct ip6_srh_t *)(sourceSymbol->packet + 40);
    srh->segments_left = 0;
    /* Unfortunately, the seg6_delete_tlv function does not update the length of the SRH when we
     * remove the TLV. We need to locally update this value in the sourceSymbol version of the packet.
     * We cannot use seg6_get_srh because we work with local structure and not with __sk_buff */
    srh->hdrlen -= 1; // TODO: more clean ?

    if (DEBUG) bpf_printk("Receiver: storePacket done\n");
    return 0;
}

static __always_inline int receiveSourceSymbol__convolution(struct __sk_buff *skb, struct ip6_srh_t *srh, int tlv_offset) {
    int err;
    int k = 0;

    struct tlvSource__convo_t tlv;
    err = bpf_skb_load_bytes(skb, tlv_offset, &tlv, sizeof(struct tlvSource__convo_t));
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load the source TLV\n");
        return 0;
    }

    /* Remove the TLV from the packet as we have a local copy */
    err = seg6_delete_tlv2(skb, srh, tlv_offset);
    if (err != 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to remove the source TLV from the packet\n");
        return 0;
    }

    /* Get information about the source symbol */
    __u32 encodingSymbolID = tlv.encodingSymbolID;
    if (encodingSymbolID < 0) return -1;

    /* Get pointer to global stucture */
    fecConvolution_t *fecConvolution = bpf_map_lookup_elem(&fecConvolutionInfoMap, &k);
    if (!fecConvolution) {
        if (DEBUG) bpf_printk("Receiver: impossible to get pointer to the structure\n");
        return BPF_ERROR;
    }

    /* Get index in the ring buffer based on the encodingSymbolID value */
    __u8 ringBufferIndex = encodingSymbolID % RLC_RECEIVER_BUFFER_SIZE;
    if (ringBufferIndex < 0 || ringBufferIndex >= RLC_RECEIVER_BUFFER_SIZE) {
        if (DEBUG) bpf_printk("Receiver: impossible index\n");
        return -1;
    }

    /* Get pointer to place in ring buffer for the source symbol */
    struct sourceSymbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[ringBufferIndex & 0xff];
    // See if the packet is already in the buffer
    struct tlvSource__convo_t *tlv_ss = (struct tlvSource__convo_t *)&sourceSymbol->tlv;
    if (tlv_ss->encodingSymbolID == encodingSymbolID) {
        if (DEBUG) bpf_printk("Receiver: source symbol already in the buffer\n");
        return -1;
    }
    // Otherwise we just reset the location
    memset(sourceSymbol, 0, sizeof(struct sourceSymbol_t)); // Optimization ?

    /* Store source symbol */
    err = storePacket(skb, sourceSymbol);
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: error from storePacket confirmed\n");
        return -1;
    } else if (err > 0) {
        if (DEBUG) bpf_printk("Receiver: confirmed packet too big for protection\n");
        return -1;
    }

    /* Copy the TLV for later use */
    memcpy(&sourceSymbol->tlv, &tlv, sizeof(struct tlvSource__convo_t));

    bpf_printk("Receiver: stored source symbol: %d %d!\n", sourceSymbol->packet_length, encodingSymbolID);

    /* Indicate to all window information structures in the neighboorhood of the 
     * source symbol that it has been processed. As the repair symbol encodingSymbolID is the value
     * of the last source symbol => update windows after this source symbol */
    for (__u8 i = 0; i < RLC_WINDOW_SIZE; ++i) {
        __u8 windowRingBufferIndex = (encodingSymbolID + i) % RLC_RECEIVER_BUFFER_SIZE;
        window_info_t *window_info = &fecConvolution->windowInfoBuffer[windowRingBufferIndex & 0xff];
        ++(window_info->received_ss);
    }

    /* Try to recover from lost packet */
    // TODO;

    return 0;
}

static __always_inline int receiveRepairSymbol__convolution(struct __sk_buff *skb, struct ip6_srh_t *srh, int tlv_offset) {
    int err;
    int k = 0;

    struct tlvRepair__convo_t tlv;
    err = bpf_skb_load_bytes(skb, tlv_offset, &tlv, sizeof(struct tlvRepair__block_t));
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load the repair TLV\n");
        return 0;
    }

    /* Get information about the source symbol */
    __u32 encodingSymbolID = tlv.encodingSymbolID;
    if (encodingSymbolID < 0) return -1; // Lol

    /* Get pointer to global stucture */
    fecConvolution_t *fecConvolution = bpf_map_lookup_elem(&fecConvolutionInfoMap, &k);
    if (!fecConvolution) {
        if (DEBUG) bpf_printk("Receiver: impossible to get pointer to the structure\n");
        return BPF_ERROR;
    }

    /* Get index in the ring buffer based on the encodingSymbolID value */
    __u8 windowRingBufferIndex = encodingSymbolID % RLC_RECEIVER_BUFFER_SIZE;
    if (windowRingBufferIndex < 0 || windowRingBufferIndex >= RLC_RECEIVER_BUFFER_SIZE) {
        if (DEBUG) bpf_printk("Receiver: impossible index\n");
        return -1;
    }

    /* Get pointer to information of the window */
    window_info_t *window_info = &fecConvolution->windowInfoBuffer[windowRingBufferIndex & 0xff];
    // TODO: check if already received repair symbol ?
    struct repairSymbol_t *repairSymbol = &window_info->repairSymbol;
    memset(repairSymbol, 0, sizeof(struct repairSymbol_t)); // Optimization ?

    /* Store repair symbol 'as a source symbol' */
    err = storePacket(skb, (struct sourceSymbol_t *)repairSymbol);
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: error from storePacket confirmed\n");
        return -1;
    } else if (err > 0) {
        if (DEBUG) bpf_printk("Receiver: confirmed packet too big for protection\n");
        return -1;
    }

    /* (Re)set values of window info: assumes that only one repair symbol is used here */
    window_info->received_ss = 0;
    window_info->received_rs = 1;
    window_info->encodingSymbolID = encodingSymbolID;

    /* Copy the TLV for later use */
    memcpy(&repairSymbol->tlv, &tlv, sizeof(struct tlvRepair__convo_t));

    bpf_printk("Receiver: stored repair symbol: %d %d\n", repairSymbol->packet_length, encodingSymbolID);

    /* Iterate over sourceRingBuffer to get information about possible reparation */
    for (__u8 i = 0; i < RLC_WINDOW_SIZE; ++i) {
        __u8 ringBufferIndex = (encodingSymbolID - i) % RLC_RECEIVER_BUFFER_SIZE;
        struct tlvSource__convo_t *tlv_ss = (struct tlvSource__convo_t *)&fecConvolution->sourceRingBuffer[ringBufferIndex & 0xff].tlv;
        if (tlv_ss->encodingSymbolID - i == encodingSymbolID) {
            ++window_info->received_ss;
        }
    }

    /* Try to recover from lost packet */
    // TODO

    return 0;
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
    long cursor = seg6_find_tlv2(skb, srh, &tlv_type, sizeof(struct tlvSource__block_t), sizeof(struct tlvRepair__block_t));
    if (cursor < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to get the TLV\n");
        return BPF_ERROR;
    }
    if (tlv_type != TLV_CODING_SOURCE && tlv_type != TLV_CODING_REPAIR) { // Should not enter in this condition
        if (DEBUG) bpf_printk("Receiver: does not contain a source/repair TLV\n");
        return BPF_ERROR;
    }

    xorStruct_t *xorStruct = 0;

    /* Call FEC framework depending on the type of packet */
    if (tlv_type == TLV_CODING_SOURCE) {
        //xorStruct = fecFrameworkSource(skb, cursor, srh);
        err = receiveSourceSymbol__convolution(skb, srh, cursor);
    } else {
        //xorStruct = fecFrameworkRepair(skb, cursor, srh);
        err = receiveRepairSymbol__convolution(skb, srh, cursor);
    }
    /*if (!xorStruct) {
        if (DEBUG) bpf_printk("Receiver: fec framework fail confirmed\n");
        return BPF_ERROR;
    }*/

    /* If we can recover from a loss, send the decoded information 
     * to user space to send new packet */
    if (0 && canDecode(xorStruct)) {
        // TODO: make it convertible for multiple coding functions
        //struct repairSymbol_t *repairSymbol = &(xorStruct->repairSymbols);
        //bpf_printk("%d\n", repairSymbol->packet_length);

        /* Submit repair symbol(s) to User Space using perf events */
        //bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, repairSymbol, sizeof(struct repairSymbol_t));
        if (DEBUG) bpf_printk("Receiver: sent bpf event to user space");
    }

    /* The repair symbol(s) must be dropped because not useful for the rest of the network */
    if (tlv_type == TLV_CODING_REPAIR) {
        return BPF_DROP;
    }

    if (DEBUG) bpf_printk("Receiver: done FEC\n");
    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";