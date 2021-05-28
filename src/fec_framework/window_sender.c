#ifndef VMLINUX_H_
#define VMLINUX_H_
#include <linux/bpf.h>
#endif

#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_
#include <bpf/bpf_helpers.h>
#endif

#include "../libseg6.c"
#include "../encoder.bpf.h"
#include "store_packet_sender.c"
#include "../fec_scheme/bpf/convo_rlc_sender.c"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, fecConvolution_t);
} fecConvolutionInfoMap SEC(".maps");

typedef struct {
    __u32 encodingSymbolID;
    __u16 repairKey;
    __u8 ringBuffSize; // Number of packets for next coding in the ring buffer
    struct sourceSymbol_t sourceRingBuffer[RLC_BUFFER_SIZE];
    struct tlvRepair__convo_t repairTlv[RLC_RS_NUMBER];
    __u8 currentWindowSize;
    __u8 currentWindowSlide;
} for_user_space_t;

static __always_inline int fecFramework__convolution(struct __sk_buff *skb, void *tlv_void, fecConvolution_t *fecConvolution, void *map) {
    struct tlvSource__convo_t *tlv = (struct tlvSource__convo_t *)tlv_void;
    
    int ret;

    // Ensures that we do not try to protect a too big packet
    if (skb->len > MAX_PACKET_SIZE) {
        return -1;
    }

    // Get parameters of the Framework *safely*
    bpf_spin_lock(&fecConvolution->lock);
    __u32 encodingSymbolID = fecConvolution->encodingSymbolID;
    __u16 repairKey = fecConvolution->repairKey;
    __u8 ringBuffSize = fecConvolution->ringBuffSize;
    __u8 windowSize = fecConvolution->currentWindowSize;
    fecConvolution->encodingSymbolID = encodingSymbolID + 1; // Already update the encodingSymbolID for next
    // TODO: maybe do the check to update the ring buff size directly here
    bpf_spin_unlock(&fecConvolution->lock);

    // Complete the source symbol TLV
    tlv->tlv_type = TLV_CODING_SOURCE;
    tlv->len = sizeof(struct tlvSource__convo_t) - 2;
    tlv->encodingSymbolID = encodingSymbolID;
    tlv->controller_update = fecConvolution->controller_period;

    // Get pointer in the ring buffer to store the source symbol
    __u32 ringBufferIndex = encodingSymbolID % windowSize;
    if (ringBufferIndex < 0 || ringBufferIndex >= windowSize) { // Check for the eBPF verifier
        if (DEBUG) bpf_printk("Sender: RLC index to ring buffer\n");
        return -1;
    }
    struct sourceSymbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[ringBufferIndex & (RLC_BUFFER_SIZE - 1)];
    // Custom memset
    //__u64 *ss64 = (__u64 *)sourceSymbol->packet;
    //for (int i = 0; i < MAX_PACKET_SIZE / 8; ++i) {
    //    ss64[i] = 0;
    //}

    // Store source symbol
    ret = storePacket(skb, sourceSymbol);
    if (ret < 0) { // Error
        if (DEBUG) bpf_printk("Sender: error from storePacket confirmed\n");
        return -1;
    } else if (ret > 0) {
        if (DEBUG) bpf_printk("Sender: confirmed packet too big for protection\n");
        return -1;
    }

    // The ring buffer contains a new source symbol
    ++ringBuffSize;

    // Call coding function
    ret = fecScheme__convoRLC(skb, fecConvolution, ringBuffSize, encodingSymbolID);
    if (ret < 0) {
        return -1;
    }

    // A repair symbol must be generated
    // Forward all data to user space for computation for now as we cannot perform that is the kernel
    // due to the current limitations
    if (ret && (fecConvolution->controller_repair & 0x1)) {
        fecConvolution_user_t *to_user_space = (fecConvolution_user_t *)fecConvolution;
        bpf_perf_event_output(skb, map, BPF_F_CURRENT_CPU, fecConvolution, sizeof(fecConvolution_user_t));
    } else if (!ret) {
        fecConvolution->ringBuffSize = ringBuffSize; // The value is updated by the FEC Scheme if we generate repair symbols
    }

    return 0;
}