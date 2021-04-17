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
#include "libseg6.c"
#include "decoder.h"
#include "fec_framework/window_receiver.c"
#include "fec_framework/block_receiver.c"

/* Perf even buffer */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("lwt_seg6local")
int decode(struct __sk_buff *skb) {
    //if (DEBUG) bpf_printk("Receiver: BPF triggered from packet with SRv6!\n");
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

    //xorStruct_t *xorStruct = 0;

    /* Call FEC framework depending on the type of packet */
    if (tlv_type == TLV_CODING_SOURCE) {
        //err = receiveSourceSymbol__block(skb, srh, cursor, &events);
        err = receiveSourceSymbol__convolution(skb, srh, cursor, &events);
    } else {
        //err = receiveRepairSymbol__block(skb, srh, cursor, &events);
        err = receiveRepairSymbol__convolution(skb, srh, cursor, &events);
    }

    if (err < 0) {
        bpf_printk("Receiver: error confirmed\n");
        return BPF_ERROR;
    }

    /* The repair symbol(s) must be dropped because not useful for the rest of the network */
    if (tlv_type == TLV_CODING_REPAIR) {
        return BPF_DROP;
    }

    if (DEBUG) bpf_printk("Receiver: done FEC\n");
    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";