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
#include "decoder.skel.h"
#include <bpf/bpf.h>
#include "fec_srv6.h"

#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/seg6.h>

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

int send_raw_socket(const struct repairSymbol_t *repairSymbol) {
    struct sockaddr_in6 src;
    struct sockaddr_in6 dst;
    uint8_t packet[4200];
    size_t packet_length;
    struct ip6_hdr *iphdr;
    struct ipv6_sr_hdr *srh;
    struct udphdr *uhdr;
    size_t ip6_length = 40;
    size_t srh_length = 0;
    size_t udp_length = 8;
    size_t pay_length = repairSymbol->packet_length;
    int next_segment_idx;
    int bytes; // Number of sent bytes

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
    srh_length = srh->hdrlen;

    /* Put new value of Hop Limit */
    iphdr->ip6_hops = 51;

    /* Retrieve the next segment after the current node to put as destination address.
     * Also need to update the Segment Routing header segment left entry
     */
    // TODO: for now it is hardcoded
    next_segment_idx = 0;

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

static void send_recovered_symbol_XOR(void *ctx, int cpu, void *data, __u32 data_sz) {
    /* Get the repairSymbol
     * ->packet: the decoded and recovered packet
     * ->packet_length: the length of the recovered packet
     */
    const struct repairSymbol_t *repairSymbol = (struct repairSymbol_t *)data;
    printf("CALL TRIGGERED!\n");

    send_raw_socket(repairSymbol);
}

static void handle_events(int map_fd_events) {
    /* Define structure for the perf event */
    struct perf_buffer_opts pb_opts = {
        .sample_cb = send_recovered_symbol_XOR,
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
     * Poll the recovered packet from the BPF program
     */
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && errno != EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            goto cleanup;
        }
    }

cleanup:
    perf_buffer__free(pb);
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

    struct bpf_map *map_events = skel->maps.events;
    int map_fd_events = bpf_map__fd(map_events);

    /* Open raw socket */
    sfd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (sfd == -1) {
        perror("Cannot create socket");
        goto cleanup;
    }

    /* Enter perf event handling for packet recovering */
    handle_events(map_fd_events);

    /* Close socket */
    if (close(sfd) == -1) {
        perror("Cannot close socket");
        goto cleanup;
    }

    // We reach this point when we Ctrl+C with signal handling
    /* Unpin the program and the maps to clean at exit */
    bpf_object__unpin_programs(skel->obj,  "/sys/fs/bpf/decoder");
    bpf_map__unpin(map_sourceSymbolBuffer, "/sys/fs/bpf/decoder/sourceSymbolBuffer");
    bpf_map__unpin(map_repairSymbolBuffer, "/sys/fs/bpf/decoder/repairSymbolBuffer");
    bpf_map__unpin(map_blockBuffer,        "/sys/fs/bpf/decoder/blockBuffer");
    // Do not know if I have to unpin the perf event too
    bpf_map__unpin(map_events, "/sys/fs/bpf/decoder/events");
    decoder_bpf__destroy(skel);
cleanup:
    return 0;
}