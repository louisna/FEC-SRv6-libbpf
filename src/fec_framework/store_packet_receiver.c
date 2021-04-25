#ifndef STORE_PACKET_RECEIVER_H_
#define STORE_PACKET_RECEIVER_H_

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

static __always_inline int storePacket_decode(struct __sk_buff *skb, struct sourceSymbol_t *sourceSymbol) {
    int err;

    /* Get the packet length from the IPv6 header to the end of the payload */
    __u32 packet_len = skb->len;

    /* Ensures that we do not try to protect a too big packet */
    if (packet_len > MAX_PACKET_SIZE) {
        if (DEBUG) bpf_printk("Receiver: too big packet, does not protect\n");
        return 1;
    }

    /* Get pointer to the IPv6 header of the packet, i.e. the beginning of the source symbol */
    struct ip6_t *ip6 = seg6_get_ipv6(skb);
    if (!ip6) {
        if (DEBUG) bpf_printk("Receiver: impossible to get the IPv6 header\n");
        return -1;
    }

    __u32 ipv6_offset = (__u64)ip6 - (__u64)skb->data;
    if (ipv6_offset < 0 || ipv6_offset > MAX_PACKET_SIZE) return -1;

    /* Load the payload of the packet and store it in sourceSymbol */
    err = bpf_skb_load_bytes(skb, ipv6_offset, (void *)sourceSymbol->packet, ((skb->len - ipv6_offset - 1) & 0x1ff) + 1);
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load bytes from packet\n");
        return -1;
    }

    //bpf_printk("Receiver: Done storing of packet with big size ! %d\n", packet_len);

    /* Store the length of the packet that will also be coded */
    sourceSymbol->packet_length = packet_len;

    /* Get the IPv6 header from the sourceSymbol pointer.
     * We must put the fields that may vary in the network to 0 because coding to ensure that the
     * decoded values on the decoder will be the same.
     * Destination address
     * Hot Limit */
    struct ip6_t *source_ipv6 = (struct ip6_t *)sourceSymbol->packet;
    source_ipv6->dst_hi    = 0;
    source_ipv6->dst_lo    = 0;
    source_ipv6->hop_limit = 0;

    /* Also get the Segment Routing header. We must set the value of segment_left to 0
     * as it will also be modified for the decoder */
    if (40 + sizeof(struct ip6_srh_t) > sizeof(sourceSymbol->packet)) {
        if (DEBUG) bpf_printk("Receiver: cannot get the SRH from the sourceSymbol\n");
        return -1;
    }
    struct ip6_srh_t *srh = (struct ip6_srh_t *)(sourceSymbol->packet + 40);
    srh->segments_left = 0;
    /* Unfortunately, the seg6_delete_tlv function does not update the length of the SRH when we
     * remove the TLV. We need to locally update this value in the sourceSymbol version of the packet.
     * We cannot use seg6_get_srh because we work with local structure and not with __sk_buff */
    srh->hdrlen -= 1; // TODO: more clean ?

    if (DEBUG) bpf_printk("Receiver: storePacket done\n");
    return 0;
}

static __always_inline int storeRepairSymbol(struct __sk_buff *skb, struct repairSymbol_t *repairSymbol, struct ip6_srh_t *srh) {
    int err;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Get pointer to the payload of the packet */
    void *payload_pointer = seg6_find_payload(skb, srh);
    if (!payload_pointer) {
        if (DEBUG) bpf_printk("Receiver: impossible to get a pointer to the repair symbol payload\n");
        return -1;
    }

    /* The payload contains the repair symbol, but also the transport header which must be skipped
     * By construction, this transport header is a simple UDP transport header */
    if (payload_pointer + 8 > data_end) {
        if (DEBUG) bpf_printk("Receiver: cannot get passed the transport header\n");
        return -1;
    }
    payload_pointer += 8;

    /* Get the packet payload length */
    __u32 payload_len = skb->len;

    /* Store the payload in repairSymbol->packet */
    __u32 payload_offset = (long)payload_pointer - (long)data;
    const __u16 size = payload_len - 1;

    err = bpf_skb_load_bytes(skb, payload_offset, (void *)repairSymbol->packet, ((skb->len - payload_offset - 1) & 0x1ff) + 1);
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load bytes\n");
        return -1;
    }

    repairSymbol->packet_length = payload_len - payload_offset;

    //if (DEBUG) bpf_printk("Receiver: stored the repair symbol!\n");

    return 0;
}

#endif