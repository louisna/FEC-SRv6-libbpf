#ifndef VMLINUX_H_
#define VMLINUX_H_
#include <linux/bpf.h>
#endif
#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_
#include <bpf/bpf_helpers.h>
#endif
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "libseg6.c"
#include "encoder.bpf.h"
#include "fec_framework/window_sender.c"
#include "fec_framework/block_sender.c"

/* Perf even buffer to communicate with the user space */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline void handle_controller(struct __sk_buff *skb, struct ip6_srh_t *srh, fecConvolution_t *fecConvolution) {
    tlv_controller_t tlv;
    long cursor = seg6_find_tlv(skb, srh, TLV_CODING_SOURCE, sizeof(tlv));
    if (cursor < 0) return;

    if (bpf_skb_load_bytes(skb, cursor, &tlv, sizeof(tlv)) < 0) return;

    /* Update internal value controlling the sending of repair symbol
     * with the value of the tlv.
     * We only update the last bit as the penultimate controls if we want to use the controller */
    fecConvolution->controller_repair = tlv.controller_repair + 2;
    //bpf_printk("Sender: update the controller with value: %d\n", tlv.controller_repair);
}

SEC("lwt_seg6local_convo")
int srv6_fec_encode_convo(struct __sk_buff *skb)
{
    /* First check if the packet can be protected in term of size 
     * The packet is not dropped, just not protected */
    if (skb->len > MAX_PACKET_SIZE) {
        if (DEBUG) bpf_printk("Packet too big, cannot protect\n");
        return BPF_OK;
    }

    if (DEBUG) bpf_printk("BPF triggered from packet with SRv6 !\n");

    int err;
    int k = 0;  // Key for hashmap

    /* Get Segment Routing Header */
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (!srh) {
        if (DEBUG) bpf_printk("Sender: impossible to get the SRH\n");
        return BPF_ERROR;
    }

    fecConvolution_t *fecConvolution = bpf_map_lookup_elem(&fecConvolutionInfoMap, &k);
    if (!fecConvolution) return BPF_ERROR;

    if (fecConvolution->controller_repair >> 1) {
        // Small trick here: we assume that if we still have at least
        // two segments left, it corresponds to the FEC plugin because
        // we need:
        // - the decoder plugin
        // - (intermediate segments)
        // - the final destination 
        // If we only have 1 segment left, we assume that it corresponds
        // to an "information" packet and treat it like that without more check.
        // This trick allows us to avoid using seg6_find_tlv for each source symbol*/
        if (srh->segments_left < 1) {
            //bpf_printk("Sender: passage\n");
            handle_controller(skb, srh, fecConvolution);
            return BPF_DROP;
        }
    }

    if (fecConvolution->encodingSymbolID % 100000 == 0) bpf_printk("Sender: check %lu\n", fecConvolution->encodingSymbolID);

    struct tlvSource__convo_t tlv;
    tlv.padding = 0;
    err = fecFramework__convolution(skb, &tlv, fecConvolution, &events);
    if (err < 0) {
        bpf_printk("Sender: Error in FEC Framework\n");
        return BPF_ERROR;
    }

    /* Add the TLV to the current source symbol and forward */
    __u16 tlv_length = sizeof(struct tlvSource__convo_t);
    err = seg6_add_tlv(skb, srh, (srh->hdrlen + 1) << 3, (struct sr6_tlv_t *)&tlv, tlv_length);
    //bpf_printk("Sender: return value of TLV add: %d\n", err);
    //if (err < 0) { 
    //    bpf_printk("Sender: error. Length=%u, encodingSymbolID:%u\n", tlv_length, fecConvolution->encodingSymbolID);
    //}
    return BPF_OK;
}

SEC("lwt_seg6local_block")
int srv6_fec_encode_block(struct __sk_buff *skb)
{
    /* First check if the packet can be protected in term of size 
     * The packet is not dropped, just not protected */
    if (skb->len > MAX_PACKET_SIZE) {
        if (DEBUG) bpf_printk("Packet too big, cannot protect\n");
        return BPF_OK;
    }
    
    if (DEBUG) bpf_printk("BPF triggered from packet with SRv6 !\n");

    int err;
    int k = 0;  // Key for hashmap

    /* Get Segment Routing Header */
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (!srh) {
        if (DEBUG) bpf_printk("Sender: impossible to get the SRH\n");
        return BPF_ERROR;
    }

    /* Get pointer to structure of the plugin */
    fecBlock_t *mapStruct = bpf_map_lookup_elem(&fecBuffer, &k);
    if (!mapStruct) { if (DEBUG) bpf_printk("Sender: impossible to get global pointer\n"); return BPF_ERROR;}

    struct tlvSource__block_t tlv;
    tlv.padding = 0;
    err = fecFramework__block(skb, &tlv, mapStruct, &events);
    if (err < 0) {
        bpf_printk("Sender: Error in FEC Framework\n");
        return BPF_ERROR;
    }

    /* Add the TLV to the current source symbol and forward */
    __u16 tlv_length = sizeof(struct tlvSource__block_t);
    err = seg6_add_tlv(skb, srh, (srh->hdrlen + 1) << 3, (struct sr6_tlv_t *)&tlv, tlv_length);
    //bpf_printk("Sender: return value of TLV add: %d\n", err);
    //if (err < 0) bpf_printk("Sender: error\n");
    return (err) ? BPF_ERROR : BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";
