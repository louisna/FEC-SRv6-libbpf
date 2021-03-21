// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "decoder.skel.h"
#include <bpf/bpf.h>
#include "fec_srv6.h"

#define MAX_BLOCK 5  // Number of blocks we can simultaneously store

/* Structures */
struct sourceSymbol_t {
    struct coding_source_t tlv;
    unsigned char packet[MAX_PACKET_SIZE];
    unsigned short packet_length;
} BPF_PACKET_HEADER;

struct repairSymbol_t {
    unsigned char packet[MAX_PACKET_SIZE];
    int packet_length; // TODO: change to u16 ?
    struct coding_repair2_t tlv;
};

struct sourceBlock_t {
    unsigned short blockID;
    unsigned char rceivedSource;
    unsigned char receivedRepair;
    unsigned char nss;
    unsigned char nrs;
};

/* Used to detect the end of the program */
static volatile int exiting = 0;

static volatile int sfd = -1;

int send_raw_socket(const struct repairSymbol_t *repairSymbol, char *srcaddr, char *dstaddr) {
    struct sockaddr_in6 src;
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
    memset(&src, 0, sizeof(src));
    src.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, srcaddr, src.sin6_addr.s6_addr) != 1) {
        perror("inet ntop src");
        return -1;
    }
    bcopy(&src.sin6_addr, &(iphdr->ip6_src), 16);

	/* IPv6 Destination address */
    memset(&src, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	if (inet_pton(AF_INET6, dstaddr, dst.sin6_addr.s6_addr) != 1) {
		perror("inet_ntop dst");
		return -1;
	}
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
    if (bytes != packet_length) {
        perror("Impossible to send packet");
        return -1;
    }

    return 0;
}

static void sig_handler(int sig)
{
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    struct decoder_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything :3 */
    bump_memlock_rlimit();

    /* Clean handling of Ctrl+C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open BPF application */
    skel = decoder_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton :(\n");
        return 1;
    }

    /* Load and verify BPF program */
    err = decoder_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to verify and load BPF skeleton :(\n");
        goto cleanup;
    }

    /* Pin program object to attach it with iproute2 */
    bpf_object__pin(skel->obj, "/sys/fs/bpf/decoder");

    char *cmd = "sudo ip -6 route add fc00::9 encap seg6local action End.BPF endpoint fd /sys/fs/bpf/decoder/lwt_seg6local section decode dev enp0s3";
    printf("Command is %s\n", cmd);

    int k0 = 0;

    /* Get file descriptor of maps and init the value of the structures */
    struct bpf_map *map_sourceSymbolBuffer = skel->maps.sourceSymbolBuffer;
    int map_fd_sourceSymbolBuffer = bpf_map__fd(map_sourceSymbolBuffer);
    struct sourceSymbol_t source_zero = {};
    bpf_map_update_elem(map_fd_sourceSymbolBuffer, &k0, &source_zero, BPF_ANY);

    struct bpf_map *map_repairSymbolBuffer = skel->maps.repairSymbolBuffer;
    int map_fd_repairSymbolBuffer = bpf_map__fd(map_repairSymbolBuffer);
    for (int i = 0; i < MAX_BLOCK; ++i) { // Init each entry of the buffer
        struct repairSymbol_t repair_zero = {};
        bpf_map_update_elem(map_fd_repairSymbolBuffer, &i, &repair_zero, BPF_ANY);
    }

    struct bpf_map *map_blockBuffer = skel->maps.blockBuffer;
    int map_fd_blockBuffer = bpf_map__fd(map_blockBuffer);
    for (int i = 0; i < MAX_BLOCK; ++i) { // Init each entry of the buffer
        struct sourceBlock_t block_zero = {};
        bpf_map_update_elem(map_fd_blockBuffer, &i, &block_zero, BPF_ANY);
    }

    while (!exiting) {
        //printf("Waiting for some information...\n");
        sleep(3);
    }

    // We reach this point when we Ctrl+C with signal handling
    /* Unpin the program and the maps to clean at exit */
    bpf_object__unpin_programs(skel->obj,  "/sys/fs/bpf/decoder");
    bpf_map__unpin(map_sourceSymbolBuffer, "/sys/fs/bpf/decoder/sourceSymbolBuffer");
    bpf_map__unpin(map_repairSymbolBuffer, "/sys/fs/bpf/decoder/repairSymbolBuffer");
    bpf_map__unpin(map_blockBuffer,        "/sys/fs/bpf/decoder/blockBuffer");
    decoder_bpf__destroy(skel);
cleanup:
    return 0;
}