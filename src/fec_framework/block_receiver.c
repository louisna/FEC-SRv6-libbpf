#ifndef VMLINUX_H_
#define VMLINUX_H_
#include <linux/bpf.h>
#endif

#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_
#include <bpf/bpf_helpers.h>
#endif

#include "../libseg6.c"
#include "../decoder.h"
#include "store_packet_receiver.c"
#include "../fec_scheme/bpf/block_xor_receiver.c"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCK);
    __type(key, __u32);
    __type(value, xorStruct_t);
} xorBuffer SEC(".maps");

static __always_inline int can_decode(struct sourceBlock_t *sourceBlock) {
    return can_decode_xor(sourceBlock);
}

static __always_inline int receiveSourceSymbol__block(struct __sk_buff *skb, struct ip6_srh_t *srh, int tlv_offset, void *map) {
    int err;
    int k = 0;

    /* Load the TLV in the structure */
    struct tlvSource__block_t tlv;
    err = bpf_skb_load_bytes(skb, tlv_offset, &tlv, sizeof(struct tlvSource__block_t));
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load the source TLV\n");
        return -1;
    }

    /* Remove the TLV from the packet as we have a local copy */
    err = seg6_delete_tlv2(skb, srh, tlv_offset);
    if (err != 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to remove the source TLV from the packet\n");
        return -1;
    }

    /* Get information about the source symbol */
    __u16 sourceBlockNb = tlv.sourceBlockNb;
    __u16 sourceSymbolNb = tlv.sourceSymbolNb;

    /* Get index of the repair symbol based on the block */
    __u32 k_block = sourceBlockNb % MAX_BLOCK;
    if (k_block < 0 || k_block >= MAX_BLOCK) { // TODO: remove this block because should be useless
        if (DEBUG) bpf_printk("Receiver: wrong block index from source framework\n");
        return -1;
    }

    xorStruct_t *xorStruct = bpf_map_lookup_elem(&xorBuffer, &k_block);
    if (!xorStruct) {
        if (DEBUG) bpf_printk("Receiver: impossible to get pointer to globla structure\n");
        return -1;
    }

    /* Get a pointer to the source symbol structure from map */
    struct sourceSymbol_t *sourceSymbol = &(xorStruct->sourceSymbol);
    memset(sourceSymbol, 0, sizeof(struct sourceSymbol_t)); // Clean the source symbol from previous packet

    /* Store source symbol */
    err = storePacket_decode(skb, sourceSymbol);
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: error from storePacket confirmed\n");
        return -1;
    } else if (err > 0) {
        if (DEBUG) bpf_printk("Receiver: confirmed packet too big for protection\n");
        return -1;
    }

    /* Copy the TLV for later use */
    memcpy(&sourceSymbol->tlv, &tlv, sizeof(struct tlvSource__block_t));

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

    //bpf_printk("Receiver: received ss=%d\n", sourceBlock->receivedSource);
    
    /* Call decoding function. This function:
     * 1) If this is the first source for this block, re-init the corresponding repair block
     * 2) Decodes */
    err = decoding_xor_on_the_line(skb, xorStruct, sourceBlock);
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: error confirmed from decodingXOR\n");
        return -1;
    }

    /* Detect if we can recover a lost symbol */
    err = can_decode(sourceBlock);

    /* A source symbol is recovered, transmit it to user space */
    if (err == 1) {
        struct repairSymbol_t *repairSymbol = &xorStruct->repairSymbols;
        bpf_perf_event_output(skb, map, BPF_F_CURRENT_CPU, repairSymbol, sizeof(struct repairSymbol_t));
    }

    return 0;
}

static __always_inline int receiveRepairSymbol__block(struct __sk_buff *skb, struct ip6_srh_t *srh, int tlv_offset, void *map) {
    int err;
    int k0 = 0;

    if (DEBUG) bpf_printk("Receiver: TRIGGERED FROM REPAIR SYMBOL\n");

    /* Here must first load the repair TLV to know the source block, to load the good repair pointer */
    struct tlvRepair__block_t tlv;
    err = bpf_skb_load_bytes(skb, tlv_offset, &tlv, sizeof(struct tlvRepair__block_t));
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load the repair TLV\n");
        return -1;
    }

    /* Retrieve the block number and the corresponding index */
    __u16 blockID = tlv.sourceBlockNb;
    int k_block = blockID % MAX_BLOCK;

    /* Get pointer to global structure */
    xorStruct_t *xorStruct = bpf_map_lookup_elem(&xorBuffer, &k_block);
    if (!xorStruct) {
        if (DEBUG) bpf_printk("Receiver: impossible to get pointer to globla structure\n");
        return -1;
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
        sourceBlock->receivedRepair = 0;
    }
    sourceBlock->receivedRepair += 1;
    sourceBlock->nss = tlv.nss;
    sourceBlock->nrs = tlv.nrs;

    /* Load the repair symbol structure */
    struct repairSymbol_t *repairSymbol = &xorStruct->repairSymbols;
    
    /* Also load pointer to the source symbol structure */
    struct sourceSymbol_t *sourceSymbol = &xorStruct->sourceSymbol;

    /* if != 0 => already received some source symbols that a deoced in the repairSymbol structure
     * => we copy the content of the repairSymbol in sourceSymbol */
    if (sourceBlock->receivedSource != 0) {
        memset(sourceSymbol, 0, sizeof(struct sourceSymbol_t));
        memcpy(sourceSymbol->packet, repairSymbol->packet, MAX_PACKET_SIZE); // Copy decoded packet
        sourceSymbol->packet_length = repairSymbol->packet_length; // Copy decoded packet length
    }
    memset(repairSymbol, 0, sizeof(struct repairSymbol_t));

    /* Store repair symbol */
    err = storeRepairSymbol(skb, repairSymbol, srh);
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: error from storeRepairSymbol confirmed\n");
        return -1;
    } else if (err > 0) {
        if (DEBUG) bpf_printk("Receiver: confirmed packet too big for protection\n");
        return -1;
    }

    err = decoding_xor_on_the_line_repair(skb, xorStruct, sourceBlock);
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: error confirmed from decodingXOR\n");
        return -1;
    }

    /* Detect if we can recover a lost symbol */
    err = can_decode(sourceBlock);

    /* A source symbol is recovered, transmit it to user space */
    if (err == 1) {
        bpf_perf_event_output(skb, map, BPF_F_CURRENT_CPU, repairSymbol, sizeof(struct repairSymbol_t));
    }

    return 0;
}