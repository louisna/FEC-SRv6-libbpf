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
#include "store_packet_sender.c"
#include "../fec_scheme/bpf/convo_rlc_sender.c"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, fecConvolution_t);
} fecConvolutionInfoMap SEC(".maps");

static __always_inline int fecFramework__convolution(struct __sk_buff *skb, void *tlv_void, void *fecConvolution_void, void *map) {
    struct tlvSource__convo_t *tlv = (struct tlvSource__convo_t *)tlv_void;
    fecConvolution_t *fecConvolution = (fecConvolution_t *)fecConvolution_void;
    
    int ret;
    __u32 encodingSymbolID = fecConvolution->encodingSymbolID;
    __u8 repairKey = fecConvolution->repairKey;
    __u8 ringBuffSize = fecConvolution->ringBuffSize;
    __u8 DT = 15; // TODO find good value

    /* Complete the source symbol TLV */
    memset(tlv, 0, sizeof(struct tlvSource__convo_t));
    tlv->tlv_type = TLV_CODING_SOURCE; // TODO: other value to distinguish ??
    tlv->len = sizeof(struct tlvSource__convo_t) - 2;
    tlv->encodingSymbolID = encodingSymbolID;

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
    ret = storePacket(skb, sourceSymbol);
    if (ret < 0) { // Error
        if (DEBUG) bpf_printk("Sender: error from storePacket confirmed\n");
        return -1;
    } else if (ret > 0) {
        if (DEBUG) bpf_printk("Sender: confirmed packet too big for protection\n");
        return -1;
    }

    /* The ring buffer contains a new source symbol */
    ++ringBuffSize;

    /* Call coding function */
    ret = fecScheme__convoRLC(skb, fecConvolution, ringBuffSize);
    if (ret < 0) {
        return -1;
    }

    /* A repair symbol must be generated
     * Forward all data to user space for computation for now as we cannot perform that is the kernel
     * due to the current limitations */
    if (ret) {
        //bpf_printk("Send data to user space for repair symbol generation\n");
        bpf_perf_event_output(skb, map, BPF_F_CURRENT_CPU, fecConvolution, sizeof(fecConvolution_t));
    } else {
        fecConvolution->ringBuffSize = ringBuffSize; // The value is updated by the FEC Scheme if we generate repair symbols
    }

    /* Update encodingSymbolID: wraps to zero after 2^32 - 1 */
    fecConvolution->encodingSymbolID = encodingSymbolID + 1;

    return ret;
}