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

// Perf even buffer to communicate with the user space 
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("lwt_seg6local_convo")
int srv6_fec_encode_convo(struct __sk_buff *skb)
{
    // First check if the packet can be protected in term of size 
    // The packet is not dropped, just not protected 
    if (skb->len > MAX_PACKET_SIZE) {
        //if (DEBUG) bpf_printk("Packet too big, cannot protect\n");
        return BPF_OK;
    }

    //if (DEBUG) bpf_printk("BPF triggered from packet with SRv6 !\n");

    int err;
    int k = 0; // Key for hashmap

    // Get Segment Routing Header 
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (!srh) {
        //if (DEBUG) bpf_printk("Sender: impossible to get the SRH\n");
        return BPF_ERROR;
    }

    fecConvolution_t *fecConvolution = bpf_map_lookup_elem(&fecConvolutionInfoMap, &k);
    if (!fecConvolution) return BPF_ERROR;

    struct tlvSource__convo_t tlv;
    err = fecFramework__convolution(skb, &tlv, fecConvolution, &events);
    if (err < 0) {
        //bpf_printk("Sender: Error in FEC Framework\n");
        return BPF_ERROR;
    }

    // Add the TLV to the current source symbol and forward 
    __u16 tlv_length = sizeof(struct tlvSource__convo_t);
    err = seg6_add_tlv(skb, srh, (srh->hdrlen + 1) << 3, (struct sr6_tlv_t *)&tlv, tlv_length);

    return BPF_OK;
}

SEC("lwt_seg6local_block")
int srv6_fec_encode_block(struct __sk_buff *skb)
{
    // First check if the packet can be protected in term of size 
    // The packet is not dropped, just not protected 
    if (skb->len > MAX_PACKET_SIZE) {
        //if (DEBUG) bpf_printk("Packet too big, cannot protect\n");
        return BPF_OK;
    }
    
    //if (DEBUG) bpf_printk("BPF triggered from packet with SRv6 !\n");

    int err;
    int k = 0;  // Key for hashmap

    // Get Segment Routing Header 
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (!srh) {
        //if (DEBUG) bpf_printk("Sender: impossible to get the SRH\n");
        return BPF_ERROR;
    }

    // Get pointer to structure of the plugin 
    fecBlock_t *mapStruct = bpf_map_lookup_elem(&fecBuffer, &k);
    if (!mapStruct) { 
        //if (DEBUG) bpf_printk("Sender: impossible to get global pointer\n"); 
        return BPF_ERROR;
    }

    struct tlvSource__block_t tlv;
    tlv.padding = 0;
    err = fecFramework__block(skb, &tlv, mapStruct, &events);
    if (err < 0) {
        //bpf_printk("Sender: Error in FEC Framework\n");
        return BPF_ERROR;
    }

    // Add the TLV to the current source symbol and forward 
    __u16 tlv_length = sizeof(struct tlvSource__block_t);
    err = seg6_add_tlv(skb, srh, (srh->hdrlen + 1) << 3, (struct sr6_tlv_t *)&tlv, tlv_length);
    return (err) ? BPF_ERROR : BPF_OK;
}

SEC("lwt_seg6local_controller")
static int handle_controller(struct __sk_buff *skb) {
    int k = 0;

    // Get Segment Routing Header 
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (!srh) {
        //if (DEBUG) bpf_printk("Sender: impossible to get the SRH\n");
        return BPF_DROP;
    }

    fecConvolution_t *fecConvolution = bpf_map_lookup_elem(&fecConvolutionInfoMap, &k);
    if (!fecConvolution) return BPF_ERROR;

    tlv_controller_t tlv;
    long cursor = seg6_find_tlv(skb, srh, TLV_CODING_SOURCE, sizeof(tlv));
    if (cursor < 0) {
        //bpf_printk("ICI erreur\n");
        return BPF_DROP;
    }

    if (bpf_skb_load_bytes(skb, cursor, &tlv, sizeof(tlv)) < 0) return BPF_DROP;

    bpf_spin_lock(&fecConvolution->lock);

    fecConvolution->controller_repair = 2;

    // Update internal value controlling the sending of repair symbol
    // with the value of the tlv.
    // We only update the last bit as the penultimate controls if we want to use the controller 
    if ((tlv.received_counter * 100) / tlv.theoretical_counter <= 98) {
        fecConvolution->controller_repair += 1;
    }

    bpf_spin_unlock(&fecConvolution->lock);

    return BPF_DROP;
}

char LICENSE[] SEC("license") = "GPL";
