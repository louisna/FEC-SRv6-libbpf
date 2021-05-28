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
#include "../fec_scheme/bpf/convo_rlc_receiver.c"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, fecConvolution_t);
} fecConvolutionInfoMap SEC(".maps");

static __always_inline int receiveSourceSymbol__convolution(struct __sk_buff *skb, struct ip6_srh_t *srh, int tlv_offset, void *map) {
    int err;
    int k = 0;

    // Load the TLV in the structure
    struct tlvSource__convo_t tlv;
    err = bpf_skb_load_bytes(skb, tlv_offset, &tlv, sizeof(struct tlvSource__convo_t));
    if (err < 0) {
        //bpf_printk("Receiver: impossible to load the source TLV\n");
        return 0;
    }

    // Remove the TLV from the packet as we have a local copy
    err = seg6_delete_tlv2(skb, srh, tlv_offset);
    if (err != 0) {
        //bpf_printk("Receiver: impossible to remove the source TLV from the packet\n");
        return 0;
    }

    // Get information about the source symbol
    __u32 encodingSymbolID = tlv.encodingSymbolID;
    if (encodingSymbolID < 0) {
        //bpf_printk("LOL ?\n");
        return -1;
    }

    // Get pointer to global stucture
    fecConvolution_t *fecConvolution = bpf_map_lookup_elem(&fecConvolutionInfoMap, &k);
    if (!fecConvolution) {
        //bpf_printk("Receiver: impossible to get pointer to the structure\n");
        return BPF_ERROR;
    }

    // Get index in the ring buffer based on the encodingSymbolID value 
    __u8 ringBufferIndex = encodingSymbolID % RLC_RECEIVER_BUFFER_SIZE;
    if (ringBufferIndex < 0 || ringBufferIndex >= RLC_RECEIVER_BUFFER_SIZE) {
        // bpf_printk("Receiver: impossible index\n");
        return -1;
    }

    struct sourceSymbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[ringBufferIndex & (RLC_RECEIVER_BUFFER_SIZE - 1)];
    // See if the packet is already in the buffer
    struct tlvSource__convo_t *tlv_ss = (struct tlvSource__convo_t *)&sourceSymbol->tlv;
    // Second condition to ensure that this is not the initialization
    if (tlv_ss->encodingSymbolID == encodingSymbolID && tlv_ss->tlv_type != 0) {
        // bpf_printk("Receiver: source symbol already in the buffer: %d %d\n", tlv_ss->encodingSymbolID, encodingSymbolID);
        return -1;
    }

    // Store source symbol
    err = storePacket_decode(skb, sourceSymbol);
    if (err < 0) {
        // bpf_printk("Receiver: error from storePacket confirmed\n");
        return -1;
    } else if (err > 0) {
        // bpf_printk("Receiver: confirmed packet too big for protection\n");
        return -1;
    }

    // Copy the TLV for later use
    memcpy(&sourceSymbol->tlv, &tlv, sizeof(struct tlvSource__convo_t));

    // Update the controller update period
    fecConvolution->controller_update = tlv.controller_update;

    // Call the controller program every 32 received source symbols 
    // First condition: the controller is enabled
    // Second condition: received 32 source symbols after last update 
    //      recall: the number of received source symbols since last update is
    //      stored in the highest order byte of controller_repair
    if (fecConvolution->controller_update > 0) {
        // First increment the counter
        ++fecConvolution->received_counter;

        // The following lines update the encodingSymbolID only if it is more recent than what we have
        // => take into account reordering that could jeopardize the good statistics
        if ((fecConvolution->most_recent_encodingSymbolID < encodingSymbolID && 
                encodingSymbolID - fecConvolution->most_recent_encodingSymbolID < RLC_RECEIVER_BUFFER_SIZE) ||
                (fecConvolution->most_recent_encodingSymbolID > encodingSymbolID && 
                encodingSymbolID - fecConvolution->most_recent_encodingSymbolID > RLC_RECEIVER_BUFFER_SIZE)) {
            fecConvolution->most_recent_encodingSymbolID = encodingSymbolID;
        }

        // Compute theoretical counter
        __u16 theoretical_counter = fecConvolution->most_recent_encodingSymbolID - fecConvolution->last_encodingSymbolID;
        if (theoretical_counter >= fecConvolution->controller_update) {
            controller_t controller_info = {0};
            
            // 4 => this is a controller message, 2 => controller enabled
            controller_info.controller_repair = 6;

            // Set counters
            controller_info.received_counter = fecConvolution->received_counter;
            controller_info.theoretical_counter = theoretical_counter;

            // Get lightweight structure for the perf output
            bpf_perf_event_output(skb, map, BPF_F_CURRENT_CPU, &controller_info, sizeof(controller_t));
            
            // Reset the counter and last update
            fecConvolution->last_encodingSymbolID = fecConvolution->most_recent_encodingSymbolID;
            fecConvolution->received_counter = 0;
        }
    }

    return 0;
}

static __always_inline int receiveRepairSymbol__convolution(struct __sk_buff *skb, struct ip6_srh_t *srh, int tlv_offset, void *map) {
    int err;
    int k = 0;

    struct tlvRepair__convo_t tlv;
    err = bpf_skb_load_bytes(skb, tlv_offset, &tlv, sizeof(struct tlvRepair__block_t));
    if (err < 0) {
        // bpf_printk("Receiver: impossible to load the repair TLV\n");
        return 0;
    }

    // Get information about the source symbol
    __u32 encodingSymbolID = tlv.encodingSymbolID;
    if (encodingSymbolID < 0) {
        // bpf_printk("Double lol ?\n");
        return -1;
    }
    __u8 windowSize = tlv.nss;

    // Get pointer to global stucture
    fecConvolution_t *fecConvolution = bpf_map_lookup_elem(&fecConvolutionInfoMap, &k);
    if (!fecConvolution) {
        // bpf_printk("Receiver: impossible to get pointer to the structure\n");
        return BPF_ERROR;
    }

    // Get index in the ring buffer based on the encodingSymbolID value
    __u8 windowRingBufferIndex = encodingSymbolID % RLC_RECEIVER_BUFFER_SIZE;
    if (windowRingBufferIndex < 0 || windowRingBufferIndex >= RLC_RECEIVER_BUFFER_SIZE) {
        // bpf_printk("Receiver: impossible index\n");
        return -1;
    }

    /* Get pointer to information of the window */
    window_info_t *window_info = &fecConvolution->windowInfoBuffer[windowRingBufferIndex & (RLC_RECEIVER_BUFFER_SIZE - 1)];
    // TODO: check if already received repair symbol ?
    struct repairSymbol_t *repairSymbol = &window_info->repairSymbol;

    // Store repair symbol
    err = storeRepairSymbol(skb, repairSymbol, srh);
    if (err < 0) {
         bpf_printk("Receiver: error from storeRepairSymbol confirmed\n");
        return -1;
    } else if (err > 0) {
         bpf_printk("Receiver: confirmed packet too big for protection\n");
        return -1;
    }

    // (Re)set values of window info: assumes that only one repair symbol is used here
    window_info->received_ss = 0;
    window_info->received_rs = 1;
    window_info->encodingSymbolID = encodingSymbolID;

    // Copy the TLV for later use
    memcpy(&repairSymbol->tlv, &tlv, sizeof(struct tlvRepair__convo_t));

    // Iterate over sourceRingBuffer to get information about possible reparation
    for (__u8 i = 0; i < windowSize && i < MAX_RLC_WINDOW_SIZE; ++i) {
        __u8 ringBufferIndex = (encodingSymbolID - i) % RLC_RECEIVER_BUFFER_SIZE;
        struct tlvSource__convo_t *tlv_ss = (struct tlvSource__convo_t *)&fecConvolution->sourceRingBuffer[ringBufferIndex & (RLC_RECEIVER_BUFFER_SIZE - 1)].tlv;
        if (tlv_ss->encodingSymbolID - i == encodingSymbolID) {
            ++window_info->received_ss;
        }
    }

    fecConvolution->encodingSymbolID = encodingSymbolID;

    // For now we give all data to user space to decode and recover from lost symbols
    // TODO: decode in eBPF kernel program and only send the recovered packets here
    // but currently not possible due to the verifier limitations */
    if (try_to_recover_from_repair__convoRLC(skb, fecConvolution, window_info, &tlv)) {
        bpf_perf_event_output(skb, map, BPF_F_CURRENT_CPU, fecConvolution, sizeof(fecConvolution_t));
    }

    return 0;
}