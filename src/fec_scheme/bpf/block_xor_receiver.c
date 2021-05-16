#ifndef VMLINUX_H_
#define VMLINUX_H_
#include <linux/bpf.h>
#endif

#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_
#include <bpf/bpf_helpers.h>
#endif

#include "../../libseg6.c"
#include "../../decoder.h"

static __always_inline int can_decode_xor(struct sourceBlock_t *sourceBlock) {

    /* Still not received the repair symbol */
    if (!sourceBlock->receivedRepair) {
        if (DEBUG) bpf_printk("Receiver: waiting for the repair symbol\n");
        return 0;
    }

    /* Count the number of lost packets
     * If no loss, no need for recovery;
     * If more than one loss in this repair block, cannot recover
     * TODO: if we disable the tracing, we can make only one 'if' condition */
    int total_loss = sourceBlock->nss - sourceBlock->receivedSource;
    //bpf_printk("Receiver: receivedSource: %d and nss: %d\n", sourceBlock->receivedSource, sourceBlock->nss);
    if (total_loss == 0) {
        if (DEBUG) bpf_printk("Receiver: no loss, no need for recovery\n");
        return 0;
    } else if (total_loss > 1) {
        if (DEBUG) bpf_printk("Receiver: too much loss for recovery\n");
        return 0;
    }

    /* At this point, we know we can send a recovered packet */
    //bpf_printk("Receiver: can recover from a lost packet\n");
    return 1;

}

static __always_inline int decoding_xor_on_the_line(struct __sk_buff *skb, xorStruct_t *xorStruct, struct sourceBlock_t *sourceBlock) {
    /* Get a pointer to the source symbol structure from map */
    struct sourceSymbol_t *sourceSymbol = &(xorStruct->sourceSymbol);

    /* Get pointer to the repair symbol for decoding */
    struct repairSymbol_t *repairSymbol = &(xorStruct->repairSymbols);

    /* If this is the first received source symbol and we did not received yet
     * the repair symbol for this block, we reset the memory of the repair symbol
     * of this block to 0 */
    if (sourceBlock->receivedSource == 1 && sourceBlock->receivedRepair == 0) {
        memset(repairSymbol, 0, sizeof(struct repairSymbol_t));
    }

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

static __always_inline int decoding_xor_on_the_line_repair(struct __sk_buff *skb, xorStruct_t *xorStruct, struct sourceBlock_t *sourceBlock) {
    int err;

    /* Get a pointer to the source symbol structure from map */
    struct sourceSymbol_t *sourceSymbol = &(xorStruct->sourceSymbol);

    /* Get pointer to the repair symbol for decoding */
    struct repairSymbol_t *repairSymbol = &(xorStruct->repairSymbols);

    /* Still no source received => we do not need to XOR with null information */
    if (sourceBlock->receivedSource == 0) {
        if (DEBUG) bpf_printk("Receiver: nothing to de-XOR\n");
        return 0;
    }

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