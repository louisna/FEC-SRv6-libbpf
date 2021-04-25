#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/seg6.h>

#include "encoder.h"

/* From https://github.com/gih900/IPv6--DNS-Frag-Test-Rig/blob/master/dns-server-frag.c */
uint16_t udp_checksum(const void *buff, size_t len, struct in6_addr *src_addr, struct in6_addr *dest_addr) {
    const uint16_t *buf = buff;
    uint16_t *ip_src = (void *)src_addr, *ip_dst = (void *)dest_addr;
    uint32_t sum;
    size_t length = len;
    int i;

    /* Calculate the sum */
    sum = 0;
    while (len > 1) {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }
    if ( len & 1 )
    /* Add the padding if the packet length is odd */
    sum += *((uint8_t *)buf);

    /* Add the pseudo-header */
    for (i = 0 ; i <= 7 ; ++i) 
        sum += *(ip_src++);

    for (i = 0 ; i <= 7 ; ++i) 
        sum += *(ip_dst++);

    sum += htons(IPPROTO_UDP);
    sum += htons(length);

    /* Add the carries */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    /* Return the one's complement of sum */
    return((uint16_t)(~sum));
}

int send_raw_socket(int sfd, const struct repairSymbol_t *repairSymbol, struct sockaddr_in6 src, struct sockaddr_in6 dst) {
    uint8_t packet[4200];
    size_t packet_length;
    struct ip6_hdr *iphdr;
    struct ipv6_sr_hdr *srh;
    struct udphdr *uhdr;
    size_t ip6_length = 40;
    size_t srh_length = 0;
    size_t tlv_length = 0;
    size_t udp_length = 8;
    size_t pay_length = repairSymbol->packet_length;
    int bytes; // Number of sent bytes

    if (sfd < 0) {
        fprintf(stderr, "The socket is not initialized\n");
        return -1;
    }

    /* IPv6 header */
    iphdr = (struct ip6_hdr *)&packet[0];
    iphdr->ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
    iphdr->ip6_nxt  = 43; // Nxt hdr = Routing header
    iphdr->ip6_hops = 44;
    iphdr->ip6_plen = 0; // Changed later

    /* IPv6 Source address */
    bcopy(&src.sin6_addr, &(iphdr->ip6_src), 16);

    /* IPv6 droper address */
    struct sockaddr_in6 drp;
    memset(&drp, 0, sizeof(src));
    src.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, "fc00::d", drp.sin6_addr.s6_addr) != 1) {
        perror("inet ntop src");
        return -1;
    }

	/* IPv6 Destination address */
	bcopy(&drp.sin6_addr, &(iphdr->ip6_dst), 16);

    /* Segment Routing header */
    srh = (struct ipv6_sr_hdr *)&packet[ip6_length];
    srh_length = sizeof(struct ipv6_sr_hdr) + 16 + 16 + 16;
    srh->nexthdr = 17; // UDP
    srh->hdrlen = 4 + 2 + 2;
    srh->type = 4;
    srh->segments_left = 2;
    srh->first_segment = 2;
    srh->flags = 0;
    srh->tag = 0;

    bcopy(&src.sin6_addr, &(srh->segments[0]), 16);
    bcopy(&dst.sin6_addr, &(srh->segments[1]), 16);
    bcopy(&drp.sin6_addr, &(srh->segments[2]), 16);

    /* TLV */
    tlv_length = sizeof(struct tlvRepair__block_t);
    uint8_t *tlv_pointer = &packet[ip6_length + srh_length];
    bcopy(&repairSymbol->tlv, tlv_pointer, tlv_length);

    /* UDP header */
	uhdr = (struct udphdr *)&packet[ip6_length + srh_length + tlv_length];
	uhdr->uh_sport = htons(50);
	uhdr->uh_dport = htons(50);
	uhdr->uh_ulen  = htons(pay_length);
	uhdr->uh_sum   = 0; // Checksum computed later

    /* Payload */
	bcopy(repairSymbol->packet, &packet[ip6_length + srh_length + tlv_length + udp_length], pay_length);

    /* Compute packet length */
    packet_length = ip6_length + srh_length + tlv_length + udp_length + pay_length;
    iphdr->ip6_plen = htons(srh_length + tlv_length + udp_length + pay_length);

    /* Compute the UDP checksum */
    uhdr->uh_sum = udp_checksum(uhdr, udp_length + pay_length, &src.sin6_addr, &dst.sin6_addr);

    /* Send packet */
    bytes = sendto(sfd, packet, packet_length, 0, (struct sockaddr *)&drp, sizeof(drp));
    //++total;
    if (bytes != packet_length) {
        return -1;
    }

    return 0;
}