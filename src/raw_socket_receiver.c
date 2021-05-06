#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/seg6.h>

#include "decoder.h"

void compute_tcp_checksum(struct ip6_hdr *pIph, uint16_t *ipPayload, uint16_t tcpLen) {
    register unsigned long sum = 0;
    int i;
    struct tcphdr *tcphdrp = (struct tcphdr *)(ipPayload);
    //printf("Longueur tcp est=%u et sport=%x\n", tcpLen, tcphdrp->th_sport);
    //add the pseudo header 
    //the source ip
    struct in6_addr *src_addr = &pIph->ip6_src;
    struct in6_addr *dst_addr = &pIph->ip6_dst;
    uint16_t *ip_src = (void *)src_addr, *ip_dst = (void *)dst_addr;
    //the dest ip
    for (i = 0 ; i <= 7 ; ++i) 
        sum += *(ip_src++);

    for (i = 0 ; i <= 7 ; ++i) 
        sum += *(ip_dst++);
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);

    //printf("Passage 1\n");
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //printf("Passage 2\n");
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      //printf("Passage 3\n");
      sum = ~sum;
    //set computation result
    tcphdrp->check = (uint16_t)sum;
}

void compute_udp_checksum(struct ip6_hdr *pIph, uint16_t *buf, uint16_t len) {
    struct in6_addr *src_addr = &pIph->ip6_src;
    struct in6_addr *dst_addr = &pIph->ip6_dst;
    uint16_t *ip_src = (void *)src_addr, *ip_dst = (void *)dst_addr;
    struct udphdr *udphdr = (struct udphdr *)(buf);
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
    for (i = 0 ; i <= 7 ; ++i) {
        sum += *(ip_src++);
    }

    for (i = 0 ; i <= 7 ; ++i) {
        sum += *(ip_dst++);
    }

    sum += htons(IPPROTO_UDP);
    sum += htons(length);

    /* Add the carries */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    /* Return the one's complement of sum */
    //return((uint16_t)(~sum));
    udphdr->uh_sum = ((uint16_t)(~sum));
}

int send_raw_socket(int sfd, const struct repairSymbol_t *repairSymbol, struct sockaddr_in6 local_addr) {
    // struct sockaddr_in6 src;
    struct sockaddr_in6 dst;
    uint8_t packet[4200];
    //fprintf(stderr, "Entering send raw socket\n");
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

    if (repairSymbol->packet_length > sizeof(packet)) {
        fprintf(stderr, "I think the packet is wrongly decoded...\n");
        return -1;
    }

    /* Copy the content of the repairSymbol_t packet inside the local packet variable.
     * => we are given a const variable, but we will need to change some fields */
    memcpy(packet, repairSymbol->packet, repairSymbol->packet_length);
    packet_length = repairSymbol->packet_length;
    //printf("Packet recovered of length: %ld\n", packet_length);
    
    /* Get pointer to the IPv6 header and Segment Routing header */
    iphdr = (struct ip6_hdr *)&packet[0];
    srh = (struct ipv6_sr_hdr *)&packet[ip6_length];
    // srh_length = srh->hdrlen;

    /* Put new value of Hop Limit */
    iphdr->ip6_hops = 51;

    /* Retrieve the next segment after the current node to put as destination address.
     * Also need to update the Segment Routing header segment left entry */
    bool found_current_segment;
    if (srh->first_segment * 16 > sizeof(packet)) {
        fprintf(stderr, "I think the packet is wrongly decoded 1...\n");
        return -1;
    }
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
        printf("Value of first segment: %u and repair symbol length %u and HLIM=%u\n", srh->first_segment, repairSymbol->packet_length, iphdr->ip6_hlim);
        return -1; // TODO: maybe just use the last segment instead ?
    }

    printf("Value of first segment: %u and repair symbol length222 %u\n", srh->first_segment, repairSymbol->packet_length);
    next_segment_idx = i - 1;
    //printf("Value of next_segment_idx: %d\n", next_segment_idx);

    /* Copy the address of the next segment in the Destination Address entry of the IPv6 header */
    memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    bcopy(&(srh->segments[next_segment_idx]), &(dst.sin6_addr), 16);
    bcopy(&dst.sin6_addr, &(iphdr->ip6_dst), 16);

    /* Update the value of next segment in the Segment Routing header */
    srh->segments_left = next_segment_idx;

    /* Compute the Checksum for IP for now */
    size_t srh_len = 8 + (srh->hdrlen << 3);
    if (srh_len > sizeof(packet)) {
        fprintf(stderr, "I think the packet is wrongly decoded 2...\n");
        return -1;
    }
    if (srh->nexthdr == 6) { // TCP
        //printf("SRH LEN=%u\n", srh_len);
        //printf("Avant\n");
        struct tcphdr *tcp = (struct tcphdr *)&packet[ip6_length + srh_len];
        //for (int i = 0; i < 32; ++i) {
        //    printf("%x ", packet[ip6_length + srh_len + i]);
        //}
        //printf("\n");
        //printf("Apres, avant calcul, le checksum vaut: %x\n", tcp->check);
        if (repairSymbol->packet_length < ip6_length + srh_len) {
            fprintf(stderr, "Erorr during the decoding, surely due to the 'multi threading' of the plugin\n");
            return -1;
        }
        uint16_t tcp_len = repairSymbol->packet_length - ip6_length - srh_len;
        //printf("Valeur de tcp len:%u\n", tcp_len);
        compute_tcp_checksum(iphdr, (unsigned short *)tcp, tcp_len);
        //printf("Apres, apres calcul, le checksum vaut: %x\n", tcp->check);
    }

    /* Send packet */
    bytes = sendto(sfd, packet, packet_length, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (bytes != packet_length) {
        perror("Impossible to send packet");
        return 1;
    }

    return 0;
}

int send_raw_socket_recovered(int sfd, const recoveredSource_t *repairSymbol, struct sockaddr_in6 local_addr) {
    // struct sockaddr_in6 src;
    struct sockaddr_in6 dst;
    uint8_t packet[4200];
    //fprintf(stderr, "Entering send raw socket\n");
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

    if (repairSymbol->packet_length > sizeof(packet)) {
        fprintf(stderr, "I think the packet is wrongly decoded...\n");
        return -1;
    }

    /* Copy the content of the repairSymbol_t packet inside the local packet variable.
     * => we are given a const variable, but we will need to change some fields */
    memcpy(packet, repairSymbol->packet, repairSymbol->packet_length);
    packet_length = repairSymbol->packet_length;
    //printf("Packet recovered of length: %ld\n", packet_length);
    
    /* Get pointer to the IPv6 header and Segment Routing header */
    iphdr = (struct ip6_hdr *)&packet[0];
    srh = (struct ipv6_sr_hdr *)&packet[ip6_length];
    // srh_length = srh->hdrlen;

    /* Put new value of Hop Limit */
    iphdr->ip6_hops = 51;

    /* Retrieve the next segment after the current node to put as destination address.
     * Also need to update the Segment Routing header segment left entry */
    bool found_current_segment;
    if (srh->first_segment * 16 > sizeof(packet)) {
        fprintf(stderr, "I think the packet is wrongly decoded 1...\n");
        return -1;
    }
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

    /* Compute the Checksum for IP for now */
    size_t srh_len = 8 + (srh->hdrlen << 3);
    if (srh_len > sizeof(packet)) {
        fprintf(stderr, "I think the packet is wrongly decoded 2...\n");
        return -1;
    }
    if (srh->nexthdr == 6) { // TCP
        //printf("SRH LEN=%u\n", srh_len);
        //printf("Avant\n");
        struct tcphdr *tcp = (struct tcphdr *)&packet[ip6_length + srh_len];
        //for (int i = 0; i < 32; ++i) {
        //    printf("%x ", packet[ip6_length + srh_len + i]);
        //}
        //printf("\n");
        //printf("Apres, avant calcul, le checksum vaut: %x\n", tcp->check);
        if (repairSymbol->packet_length < ip6_length + srh_len) {
            fprintf(stderr, "Erorr during the decoding, surely due to the 'multi threading' of the plugin\n");
            return -1;
        }
        uint16_t tcp_len = repairSymbol->packet_length - ip6_length - srh_len;
        //printf("Valeur de tcp len:%u\n", tcp_len);
        compute_tcp_checksum(iphdr, (uint16_t *)tcp, tcp_len);
        //printf("Apres, apres calcul, le checksum vaut: %x\n", tcp->check);
    } else if (srh->nexthdr == 17) { // UDP
        struct udphdr *udp = (struct udphdr *)&packet[ip6_length + srh_len];
        if (repairSymbol->packet_length < ip6_length + srh_len) {
            fprintf(stderr, "Error during decoding UDP, multi threading in cause ?\n");
            return -1;
        }
        // Reinit the previous checksum
        udp->uh_sum = 0;
        uint16_t udp_len = repairSymbol->packet_length - ip6_length - srh_len;
        //printf("UDP length is: %u\n", udp_len);
        compute_udp_checksum(iphdr, (uint16_t *)udp, udp_len);
        printf("UDP checksum: %x\n", udp->uh_sum);
    }

    /* Send packet */
    bytes = sendto(sfd, packet, packet_length, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (bytes != packet_length) {
        perror("Impossible to send packet");
        return 1;
    }

    return 0;
}