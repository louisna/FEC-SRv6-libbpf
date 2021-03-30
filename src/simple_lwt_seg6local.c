// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/resource.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "simple_lwt_seg6local.skel.h"
#include <bpf/bpf.h>
#include "fec_srv6.h"

#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/seg6.h>
//#include "socket_handler.h"

/* Structures */
struct sourceSymbol_t {
    unsigned char packet[MAX_PACKET_SIZE];
    uint16_t packet_length;
} BPF_PACKET_HEADER;

struct repairSymbol_t {
    unsigned char packet[MAX_PACKET_SIZE];
    int packet_length;
    unsigned char tlv[sizeof(struct coding_repair2_t)];
};

typedef struct mapStruct {
    unsigned short soubleBlock;
    unsigned short sourceSymbolCount;
    struct sourceSymbol_t sourceSymbol;
    struct repairSymbol_t repairSymbol;
} mapStruct_t;

static volatile int sfd = -1;
static volatile int first_sfd = 1;
static uint64_t total = 0;

static struct sockaddr_in6 src;
static struct sockaddr_in6 dst;

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

int send_raw_socket(const struct repairSymbol_t *repairSymbol) {
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

	/* IPv6 Destination address */
	bcopy(&dst.sin6_addr, &(iphdr->ip6_dst), 16);

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

    bcopy(&src.sin6_addr, &(srh->segments[0]), 16);
    bcopy(&dst.sin6_addr, &(srh->segments[1]), 16);

    /* TLV */
    tlv_length = sizeof(struct coding_repair2_t);
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
    bytes = sendto(sfd, packet, packet_length, 0, (struct sockaddr *)&dst, sizeof(dst));
    //++total;
    if (bytes != packet_length) {
        perror("Impossible to send packet");
        return -1;
    }

    return 0;
}

/* Used to detect the end of the program */
static volatile bool exiting = 0;

static void sig_handler(int sig) {
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void) {
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static void send_repairSymbol_XOR(void *ctx, int cpu, void *data, __u32 data_sz) {
    /* Get the repairSymbol
     * ->packet: the repair symbol
     * ->packet_length: the length of the repair symbol
     * ->tlv: the TLV to be added in the SRH header 
     */
    const struct repairSymbol_t *repairSymbol = (struct repairSymbol_t *)data;
    //printf("CALL TRIGGERED!\n");

    ++total;
    //send_raw_socket(repairSymbol);
}

static void handle_events(int map_fd_events) {
    /* Define structure for the perf event */
    struct perf_buffer_opts pb_opts = {
        .sample_cb = send_repairSymbol_XOR,
    };
    struct perf_buffer *pb = NULL;
    int err;

    pb = perf_buffer__new(map_fd_events, 128, &pb_opts);
    err = libbpf_get_error(pb);
    if (err) {
        pb = NULL;
        fprintf(stderr, "Impossible to open perf event\n");
        goto cleanup;
    }


    /* Enter in loop until a signal is retrieved
     * Poll the notification from the BPF program means that we can
     * retrieve information from a repairSymbol_t and send it to the decoder router
     */
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && errno != EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            goto cleanup;
        }
    }

    printf("Total number of calls: %lu\n", total);

cleanup:
    perf_buffer__free(pb);
}

int main(int argc, char *argv[]) {
    struct simple_lwt_seg6local_bpf *skel;
    int err;

    if (argc != 3) {
        fprintf(stderr, "Usage: ./simple_lwt_seg6local <encoder_addr> <decoder_addr>");
        return -1;
    }

    /* IPv6 Source address */
    memset(&src, 0, sizeof(src));
    src.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, argv[1], src.sin6_addr.s6_addr) != 1) {
        perror("inet ntop src");
        return -1;
    }

    /* IPv6 Destination address */
    memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	if (inet_pton(AF_INET6, argv[2], dst.sin6_addr.s6_addr) != 1) {
		perror("inet_ntop dst");
		return -1;
	}

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything :3 */
    bump_memlock_rlimit();

    /* Clean handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open BPF application */
    skel = simple_lwt_seg6local_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton :(\n");
        return 1;
    }

    /* Load and verify BPF program */
    err = simple_lwt_seg6local_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to verify and load BPF skeleton :(\n");
        goto cleanup;
    }

    bpf_object__pin(skel->obj, "/sys/fs/bpf/simple_me");

    char *cmd = "sudo ip -6 route add fc00::a encap seg6local action End.BPF endpoint fd /sys/fs/bpf/simple_me/lwt_seg6local section notify_ok dev enp0s3";
    printf("Command is %s\n", cmd);
    //system(cmd);

    int k0 = 0;

    /* Get file descriptor of maps and init the value of the structures */
    struct bpf_map *map_fecBuffer = skel->maps.fecBuffer;
    int map_fd_fecBuffer = bpf_map__fd(map_fecBuffer);
    mapStruct_t struct_zero = {};
    bpf_map_update_elem(map_fd_fecBuffer, &k0, &struct_zero, BPF_ANY);

    struct bpf_map *map_events = skel->maps.events;
    int map_fd_events = bpf_map__fd(map_events);

    /* Open raw socket */
    sfd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (sfd == -1) {
		perror("Cannot create socket");
		goto cleanup;
	}

    /*int optval;

	int ret = setsockopt(sfd, IPPROTO_IPV6, IP_HDRINCL, &optval, sizeof(int));
    if(ret != 0) {
        printf("Error setting options %d\n", ret);
        return -1;
    }*/

    /* Enter perf event handling for packet recovering */
    handle_events(map_fd_events);

    /* Close socket */
    if (close(sfd) == -1) {
		perror("Cannot close socket");
		goto cleanup;
	}


    // We reach this point when we Ctrl+C with signal handling
    /* Unpin the program and the maps to clean at exit */
    bpf_object__unpin_programs(skel->obj,  "/sys/fs/bpf/simple_me");
    bpf_map__unpin(map_fecBuffer, "/sys/fs/bpf/simple_me/fecBuffer");
    // Do not know if I have to unpin the perf event too
    bpf_map__unpin(map_events, "/sys/fs/bpf/simple_me/events");
    simple_lwt_seg6local_bpf__destroy(skel);
cleanup:
    return 0;
}
