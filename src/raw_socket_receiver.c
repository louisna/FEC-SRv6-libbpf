#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/seg6.h>

#include "decoder.h"

int send_raw_socket(int sfd, const struct repairSymbol_t *repairSymbol, struct sockaddr_in6 local_addr) {
    // struct sockaddr_in6 src;
    struct sockaddr_in6 dst;
    uint8_t packet[4200];
    size_t packet_length;
    struct ip6_hdr *iphdr;
    struct ipv6_sr_hdr *srh;
    // struct udphdr *uhdr;
    size_t ip6_length = 40;
    // size_t srh_length = 0;
    // size_t udp_length = 8;
    // size_t pay_length = repairSymbol->packet_length;
    int next_segment_idx;
    int bytes; // Number of sent bytes
    int i;

    if (sfd < 0) {
        fprintf(stderr, "The socket is not initialized\n");
        return -1;
    }

    /* Copy the content of the repairSymbol_t packet inside the local packet variable.
     * => we are given a const variable, but we will need to change some fields
     */
    memcpy(packet, repairSymbol->packet, repairSymbol->packet_length);
    packet_length = repairSymbol->packet_length;

    
    /* Get pointer to the IPv6 header and Segment Routing header */
    iphdr = (struct ip6_hdr *)&packet[0];
    srh = (struct ipv6_sr_hdr *)&packet[ip6_length];
    // srh_length = srh->hdrlen;

    /* Put new value of Hop Limit */
    iphdr->ip6_hops = 51;

    /* Retrieve the next segment after the current node to put as destination address.
     * Also need to update the Segment Routing header segment left entry
     */
    bool found_current_segment;
    for (i = srh->first_segment; i >= 0; --i) {
        found_current_segment = 1;
        struct in6_addr current_seg = srh->segments[i];
        for (int j = 0; j < 16; ++j) {
            if (current_seg.s6_addr[j] != local_addr.sin6_addr.s6_addr[j]) {
                found_current_segment = 0;
                break;
            }
            //printf("%d :::: %d\n", current_seg.s6_addr[j], local_addr.sin6_addr.s6_addr[j]);
        }
        //printf("------\n");
        if (found_current_segment) break;
    }
    if (!found_current_segment) { // Should not happen !
        fprintf(stderr, "Cannot retrieve the current segment from the packet !\n");
        return -1; // TODO: maybe just use the last segment instead ?
    }
    next_segment_idx = i - 1;
    //printf("Value of next_segment_idx: %d\n", next_segment_idx);

    /* Copy the address of the next segment in the Destination Address entry of the IPv6 header */
    memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    bcopy(&(srh->segments[next_segment_idx]), &(dst.sin6_addr), 16);
    bcopy(&dst.sin6_addr, &(iphdr->ip6_dst), 16);

    /* Update the value of next segment in the Segment Routing header */
    srh->segments_left = next_segment_idx;

    /* Send packet */
    bytes = sendto(sfd, packet, packet_length, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (bytes != packet_length) {
        perror("Impossible to send packet");
        return -1;
    }

    return 0;
}

int send_raw_socket_recovered(int sfd, const recoveredSource_t *repairSymbol, struct sockaddr_in6 local_addr) {
    // struct sockaddr_in6 src;
    struct sockaddr_in6 dst;
    uint8_t packet[4200];
    size_t packet_length;
    struct ip6_hdr *iphdr;
    struct ipv6_sr_hdr *srh;
    // struct udphdr *uhdr;
    size_t ip6_length = 40;
    // size_t srh_length = 0;
    // size_t udp_length = 8;
    // size_t pay_length = repairSymbol->packet_length;
    int next_segment_idx;
    int bytes; // Number of sent bytes
    int i;

    if (sfd < 0) {
        fprintf(stderr, "The socket is not initialized\n");
        return -1;
    }

    /* Copy the content of the repairSymbol_t packet inside the local packet variable.
     * => we are given a const variable, but we will need to change some fields */
    memcpy(packet, repairSymbol->packet, repairSymbol->packet_length);
    packet_length = repairSymbol->packet_length;
    printf("Packet recovered of length: %ld\n", packet_length);
    
    /* Get pointer to the IPv6 header and Segment Routing header */
    iphdr = (struct ip6_hdr *)&packet[0];
    srh = (struct ipv6_sr_hdr *)&packet[ip6_length];
    // srh_length = srh->hdrlen;

    /* Put new value of Hop Limit */
    iphdr->ip6_hops = 51;

    /* Retrieve the next segment after the current node to put as destination address.
     * Also need to update the Segment Routing header segment left entry */
    bool found_current_segment;
    for (i = srh->first_segment; i >= 0; --i) {
        found_current_segment = 1;
        struct in6_addr current_seg = srh->segments[i];
        for (int j = 0; j < 16; ++j) {
            if (current_seg.s6_addr[j] != local_addr.sin6_addr.s6_addr[j]) {
                found_current_segment = 0;
                break;
            }
            //printf("%d :::: %d\n", current_seg.s6_addr[j], local_addr.sin6_addr.s6_addr[j]);
        }
        //printf("------\n");
        if (found_current_segment) break;
    }
    if (!found_current_segment) { // Should not happen !
        fprintf(stderr, "Cannot retrieve the current segment from the packet !\n");
        return -1; // TODO: maybe just use the last segment instead ?
    }
    next_segment_idx = i - 1;
    printf("Value of next_segment_idx: %d\n", next_segment_idx);

    /* Copy the address of the next segment in the Destination Address entry of the IPv6 header */
    memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    bcopy(&(srh->segments[next_segment_idx]), &(dst.sin6_addr), 16);
    bcopy(&dst.sin6_addr, &(iphdr->ip6_dst), 16);

    /* Update the value of next segment in the Segment Routing header */
    srh->segments_left = next_segment_idx;

    /* Send packet */
    bytes = sendto(sfd, packet, packet_length, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (bytes != packet_length) {
        perror("Impossible to send packet");
        return -1;
    }

    return 0;
}