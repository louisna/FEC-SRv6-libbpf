#ifndef VMLINUX_H_
#define VMLINUX_H_
#include <linux/bpf.h>
#endif

#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_
#include <bpf/bpf_helpers.h>
#endif

#include "../../libseg6.c"
#include "../../encoder.bpf.h"

static __always_inline int fecScheme__convoRLC(struct __sk_buff *skb, fecConvolution_t *fecConvolution, __u8 newRingBuffSize, __u32 encodingSymbolID) {
    int err;
    __u16 repairKey = fecConvolution->repairKey;
    __u8 windowSize = fecConvolution->currentWindowSize;
    __u8 windowSlide = fecConvolution->currentWindowSlide;

    /* Compute the repair symbol if needed */
    if (newRingBuffSize == windowSize) {
        for (int i = 0; i < RLC_RS_NUMBER; ++i) {
            ++repairKey;
            /* Start to complete the TLV for the repair symbol. The remaining will be done in US */
            struct tlvRepair__convo_t *repairTlv = (struct tlvRepair__convo_t *)&fecConvolution->repairTlv[i];
            // memset(repairTlv, 0, sizeof(tlvRepair__convo_t));
            repairTlv->tlv_type = TLV_CODING_REPAIR; // TODO: change also ?
            repairTlv->len = sizeof(struct tlvRepair__convo_t) - 2;
            repairTlv->unused = 0;
            repairTlv->encodingSymbolID = encodingSymbolID; // Set to the value of the last source symbol of the window
            repairTlv->repairFecInfo = (windowSlide << 16) + repairKey;
            repairTlv->nss = windowSize;
            repairTlv->nrs = RLC_RS_NUMBER;
        }
        /* Reset parameters for the next window */
        fecConvolution->ringBuffSize = newRingBuffSize - windowSlide; // For next window, already some symbols
        fecConvolution->repairKey = repairKey; // Increment the repair key seed

        /* Indicate to the FEC Framework that a repair symbol has been generated */
        return 1;
    }

    /* Indicate to the FEC Framework that no repair symbol has been generated */
    return 0;
}