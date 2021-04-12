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
#include "store_packet_sender.c"

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