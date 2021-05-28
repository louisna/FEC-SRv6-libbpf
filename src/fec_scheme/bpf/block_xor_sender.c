#ifndef VMLINUX_H_
#define VMLINUX_H_
#include <linux/bpf.h>
#endif

#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_
#include <bpf/bpf_helpers.h>
#endif

#include "../../libseg6.c"
#include "../../encoder.h"

#define MAX(a, b) a > b ? a : b

static __always_inline int xor_on_the_line(struct __sk_buff *skb, struct repairSymbol_t *repairSymbol, struct sourceSymbol_t *sourceSymbol) {
    if (DEBUG) bpf_printk("Sender: XOR on the line\n");

    /* XOR is done by batch of 8 bytes */
    __u64 *source_8 = (__u64 *)sourceSymbol->packet;  
    __u64 *repair_8 = (__u64 *)repairSymbol->packet;

    /* XOR computation */
    #pragma clang loop unroll(full)
    for (int j = 0; j < MAX_PACKET_SIZE / sizeof(__u64); ++j) {
        repair_8[j] ^= source_8[j];
    }

    /* Also compute the XOR of the length of the packets that will be stored in the repair TLV */
    struct tlvRepair__block_t *repair_tlv = (struct tlvRepair__block_t *)&repairSymbol->tlv;
    repair_tlv->payload_len ^= sourceSymbol->packet_length;

    /* Get the maximum length of the source symbols as the length of the repair symbol */
    //bpf_printk("Maximum packet length before: %u\n", repairSymbol->packet_length);
    repairSymbol->packet_length = MAX(repairSymbol->packet_length, sourceSymbol->packet_length); 
    //bpf_printk("Maximum packet length=%u from %u\n", repairSymbol->packet_length, sourceSymbol->packet_length);

    return 0;
}

static __always_inline int fecScheme__blockXOR(struct __sk_buff *skb, fecBlock_t *mapStruct, __u16 sourceSymbolCount, __u16 sourceBlock)  {
    int err;
    int k0 = 0;

    /* Load the unique repair symbol pointer from map */
    struct repairSymbol_t *repairSymbol = &mapStruct->repairSymbol;

    /* Load the source symbol structure to store the packet */
    struct sourceSymbol_t *sourceSymbol = &mapStruct->sourceSymbol;

    /* Reset the repair symbol from previous block if this is new block */
    if (sourceSymbolCount == 0) {
        memset(repairSymbol, 0, sizeof(struct repairSymbol_t));
    }

    /* Perform XOR on the line */
    err = xor_on_the_line(skb, repairSymbol, sourceSymbol);
    if (err < 0) {
        if (DEBUG) bpf_printk("Sender: error in coding on the line\n");
        return -1;
    }

    /* Creates the repair symbol TLV if the repair symbol must be sent */
    if (sourceSymbolCount == mapStruct->currentBlockSize - 1) { // -1 to convert from number to index
        // Get the TLV from the repairSymbol pointer
        struct tlvRepair__block_t *repairTLV = (struct tlvRepair__block_t *)&(repairSymbol->tlv);
        repairTLV->tlv_type = TLV_CODING_REPAIR;
        repairTLV->len = sizeof(struct tlvRepair__block_t) - 2; // Does not include tlv_type and len
        repairTLV->sourceBlockNb = sourceBlock;
        repairTLV->repairSymbolNb = 0; // There is only one repair symbol
        repairTLV->nrs = 1;
        repairTLV->nss = mapStruct->currentBlockSize;

        return 1;
    }

    return 0;
}