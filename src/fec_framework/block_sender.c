#ifndef VMLINUX_H_
#define VMLINUX_H_
#include <linux/bpf.h>
#endif

#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_
#include <bpf/bpf_helpers.h>
#endif

#include "../libseg6.c"
#include "../encoder.h"
#include "../fec_scheme/bpf/block_xor_sender.c"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, mapStruct_t);
} fecBuffer SEC(".maps");

static __always_inline int fecFramework__block(struct __sk_buff *skb, struct tlvSource__block_t *csh, mapStruct_t *mapStruct, void *map) {
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
    err = fecScheme__blockXOR(skb, mapStruct);
    if (err < 0) { // Error
        if (DEBUG) bpf_printk("Sender fewFramework: error confirmed\n");
        return -1;
    } else if (err == 2) {
        if (DEBUG) bpf_printk("Sender: too big packet confirmed 2\n");
        return -1;
    }

    /* A repair symbol is generated and will be forwarded to user space to be forwarded */
    if (err == 1) {
        bpf_perf_event_output(skb, map, BPF_F_CURRENT_CPU, &mapStruct->repairSymbol, sizeof(struct repairSymbol_t));
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