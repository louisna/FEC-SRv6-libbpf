#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/seg6.h>
#include <signal.h>

/**
 * This function sets an SRH in the sfd containing the table of segments.
 * The destination segment is inserted by the function and therefore is not
 * needed in the parameter.
 * The number of segments is given by segment_number.
 * The first segment in segment table will be in the first segment used.
 */
int set_srv6_segments(int sfd, char *segments[], size_t segment_number)
{
	struct ipv6_sr_hdr *srh;
	size_t srh_len = sizeof(*srh) + (segment_number + 1) * sizeof(struct in6_addr);
	srh = malloc(srh_len);
	if (!srh) {
		fprintf(stderr, "Out of memory\n");
		return -1;
	}

	srh->nexthdr = 0;
	srh->hdrlen = 2*(segment_number + 1);
	srh->type = 4;
	srh->segments_left = segment_number;
	srh->first_segment = srh->segments_left;
	srh->flags = 0;
	srh->tag = 0;
	memset(&srh->segments[0], 0, sizeof(struct in6_addr)); // Final destination segment

	for (size_t i = 0; i < segment_number; i++) {
		if (inet_pton(AF_INET6, segments[i], &srh->segments[segment_number-i]) != 1) {
			fprintf(stderr, "Cannot parse %s as an IPv6 address\n", segments[i]);
			free(srh);
			return -1;
		}
	}

	if (setsockopt(sfd, IPPROTO_IPV6, IPV6_RTHDR, srh, srh_len) < 0) {
		perror("sr_socket - setsockopt");
		free(srh);
		return -1;
	}

	free(srh);
	return 0;
}

/**
 * touch test.log
   chmod o=rw test.log
   sudo tshark -i wlan0 -w test.log
 */

static int exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

int main()
{
	int sfd;
	char *payload = "Hello from Raw socket ! zefhekfhejfhejlfhe zjfhzel fehaflkjz ehfjklezh fljehf eljazhfaj ezlkfhejfz ";
	int payload_length = strlen(payload);
	if ((sfd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("socket()");
		return -1;
	}

	int optval;

	int ret = setsockopt(sfd, IPPROTO_IPV6, IP_HDRINCL, &optval, sizeof(int));
    if(ret != 0) {
        printf("Error setting options %d\n", ret);
        return -1;
    }
    printf("Socket options done\n");

	char *srcaddr = "2042:11::2";
	char *dstaddr = "fc00::a";
	char *itdaddr = "2042:22::2";
	struct sockaddr_in6 src;
	struct sockaddr_in6 itd;
    struct sockaddr_in6 dst;
    uint8_t packet[4200];
    size_t packet_length;
    struct ip6_hdr *iphdr;
    struct ipv6_sr_hdr *srh;
    struct udphdr *uhdr;
    size_t ip6_length = 40;
    size_t srh_length = 0;
    size_t tlv_length = 0;
    size_t udp_length = 8;
    size_t pay_length = payload_length;
    size_t bytes; // Number of sent bytes

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
    memset(&src, 0, sizeof(src));
    src.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, srcaddr, src.sin6_addr.s6_addr) != 1) {
        perror("inet ntop src");
        return -1;
    }
    bcopy(&src.sin6_addr, &(iphdr->ip6_src), 16);

	/* IPv6 Destination address */
	dst.sin6_family = AF_INET6;
	if (inet_pton(AF_INET6, dstaddr, dst.sin6_addr.s6_addr) != 1) {
		perror("inet_ntop dst");
		return -1;
	}
	bcopy(&dst.sin6_addr, &(iphdr->ip6_dst), 16);

	/* IPv6 Intermediate address */
	itd.sin6_family = AF_INET6;
	if (inet_pton(AF_INET6, itdaddr, itd.sin6_addr.s6_addr) != 1) {
		perror("inet_ntop dst");
		return -1;
	}

    /* Segment Routing header */
    srh = (struct ipv6_sr_hdr *)&packet[ip6_length];
    srh_length = sizeof(struct ipv6_sr_hdr) + 16 + 16;
    srh->nexthdr = 17; // UDP
    srh->hdrlen = 4 + 2;
    srh->type = 4;
    srh->segments_left = 1;
    srh->first_segment = 1;
    srh->flags = 0;
    srh->tag = 0;

    bcopy(&itd.sin6_addr, &(srh->segments[0]), 16);
    bcopy(&dst.sin6_addr, &(srh->segments[1]), 16);

    /* TLV */
	uint8_t *tlv = &packet[40 + srh_length];
	tlv_length = 16;
	tlv[0] = 157;
	tlv[1] = 14;
	tlv[2] = 0;
	tlv[3] = 1;
	tlv[4] = 0;
	tlv[5] = 0;
	tlv[6] = 0;
	tlv[7] = 0;
	tlv[8] = 0;
	tlv[9] = 0;
	tlv[10] = 0;
	tlv[11] = 0;
	tlv[12] = 5;
	tlv[13] = 1;
	tlv[14] = 0;
	tlv[15] = 0;

    /* UDP header */
	uhdr = (struct udphdr *)&packet[ip6_length + srh_length + tlv_length];
	uhdr->uh_sport = htons(50);
	uhdr->uh_dport = htons(50);
	uhdr->uh_ulen  = htons(pay_length);
	uhdr->uh_sum   = 0; // TODO: compute checksum

    /* Payload */
	bcopy(payload, &packet[ip6_length + srh_length + tlv_length + udp_length], pay_length);

    /* Compute packet length */
    packet_length = ip6_length + srh_length + tlv_length + udp_length + pay_length;
    iphdr->ip6_plen = htons(srh_length + tlv_length + udp_length + pay_length);

    /* Compute the UDP checksum */
    //uhdr->uh_sum = udp_checksum(uhdr, udp_length + pay_length, &src.sin6_addr, &dst.sin6_addr);
	
	/* Clean handling of Ctrl+C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

	while (!exiting) {
		/* Send packet */
		bytes = sendto(sfd, packet, packet_length, 0, (struct sockaddr *)&dst, sizeof(dst));
		if (bytes != packet_length) {
			perror("Impossible to send packet");
			return -1;
		}
	}

	close(sfd);
	return 0;
}

