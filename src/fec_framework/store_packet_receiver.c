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

    void *data = (void *)(long)(skb->data);
    void *data_end = (void *)(long)(skb->data_end);

    /* Get pointer to the IPv6 header of the packet, i.e. the beginning of the source symbol */
    struct ip6_t *ip6 = seg6_get_ipv6(skb);
    if (!ip6) {
        if (DEBUG) bpf_printk("Receiver: impossible to get the IPv6 header\n");
        return -1;
    }

    /* Get the packet length from the IPv6 header to the end of the payload */
    __u32 packet_len = ((long)data_end) - ((long)(void *)ip6);
    if ((void *)ip6 + packet_len > data_end) {
        if (DEBUG) bpf_printk("Receiver: inconsistent payload length\n");
        return -1;
    }

    /* Ensures that we do not try to protect a too big packet */
    if (packet_len > MAX_PACKET_SIZE) {
        if (DEBUG) bpf_printk("Receiver: too big packet, does not protect\n");
        return 1;
    }

    __u32 ipv6_offset = (long)ip6 - (long)data;
    if (ipv6_offset < 0) return -1;

    /* Load the payload of the packet and store it in sourceSymbol */
    const __u16 size = packet_len - 1; // Small trick here because the verifier thinks the value can be negative
    if (size < sizeof(sourceSymbol->packet) && ipv6_offset + size <= (long)data_end) {
        // TODO: 0xffff should be set as global => ensures that the size is the max classic size of IPv6 packt
        err = bpf_skb_load_bytes(skb, ipv6_offset, (void *)sourceSymbol->packet, (size & 0xffff) + 1);
    } else {
        if (DEBUG) bpf_printk("Receiver: Wrong ipv6_offset\n");
        return -1;
    }
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load bytes from packet\n");
        return -1;
    }

    bpf_printk("Receiver: Done storing of packet with big size ! %d\n", packet_len);

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
    payload_pointer += 8 * sizeof(char);

    /* Get the packet payload length */
    __u32 payload_len = ((long)data_end) - ((long)payload_pointer);
    if (payload_pointer + payload_len > data_end) {
        if (DEBUG) bpf_printk("Receiver: inconsistent payload\n");
        return -1;
    }

    /* Store the payload in repairSymbol->packet */
    __u32 payload_offset = (long)payload_pointer - (long)data;
    const __u16 size = payload_len - 1;
    if (size < sizeof(repairSymbol->packet) && payload_offset + size <= (long)data_end) {
        err = bpf_skb_load_bytes(skb, payload_offset, (void *)repairSymbol->packet, (size & 0xffff) + 1);
    } else {
        if (DEBUG) bpf_printk("Receiver: Wrong offset: %u %u %u\n", (size & 0xffff) + 1, sizeof(repairSymbol->packet), payload_offset);
        return -1;
    }
    if (err < 0) {
        if (DEBUG) bpf_printk("Receiver: impossible to load bytes\n");
        return -1;
    }

    repairSymbol->packet_length = payload_len;

    if (DEBUG) bpf_printk("Receiver: stored the repair symbol!\n");

    return 0;
}

#endif