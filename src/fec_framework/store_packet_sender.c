#ifndef STORE_PACKET_SENDER_H_
#define STORE_PACKET_SENDER_H_

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

static __always_inline int storePacket(struct __sk_buff *skb, struct sourceSymbol_t *sourceSymbol) {
    int err;
    int k = 0;

    // Get the packet length from the IPv6 header to the end of the payload
    __u32 packet_len = skb->len;

    // Ensures that we do not try to protect a too big packet
    if (packet_len > MAX_PACKET_SIZE) {
        return 1;
    }

    // Get pointer to the IPv6 header of the packet, i.e. the beginning of the source symbol
    struct ip6_t *ip6 = seg6_get_ipv6(skb);
    if (!ip6) {
        return -1;
    }

    __u64 ipv6_offset = (__u64)ip6 - (__u64)skb->data;
    if (ipv6_offset < 0 || ipv6_offset > MAX_PACKET_SIZE) return -1;

    // TODO: 0xffff should be set as global => ensures that the size is the max classic size of IPv6 packt
    err = bpf_skb_load_bytes(skb, ipv6_offset, sourceSymbol->packet, ((skb->len - ipv6_offset - 1) & (MAX_PACKET_SIZE - 1)) + 1);
    if (err < 0) {
        //bpf_printk("Sender: impossible to load bytes from packet\n");
        return -1;
    }

    sourceSymbol->packet_length = packet_len;

    // Get the IPv6 header from the sourceSymbol pointer.
    // We must put the fields that may vary in the network to 0 because coding to ensure that the
    // decoded values on the decoder will be the same.
    // Destination address
    // Hot Limit
    struct ip6_t *source_ipv6 = (struct ip6_t *)sourceSymbol->packet;
    source_ipv6->dst_hi    = 0;
    source_ipv6->dst_lo    = 0;
    source_ipv6->hop_limit = 0;

    // Also get the Segment Routing header. We must set the value of segment_left to 0
    // as it will also be modified for the decoder */
    if (40 + sizeof(struct ip6_srh_t) > sizeof(sourceSymbol->packet)) {
        return -1;
    }
    struct ip6_srh_t *srh = (struct ip6_srh_t *)(sourceSymbol->packet + 40);
    srh->segments_left = 0;

    return 0;
}

#endif