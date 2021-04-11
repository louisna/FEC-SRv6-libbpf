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
#include "decoder.h"
// #include "fec/fec.c"
#include "fec_scheme/rlc_gf256_decode.c"

#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/seg6.h>

typedef struct xorStruct {
    struct sourceSymbol_t sourceSymbol;
    struct repairSymbol_t repairSymbols;
    struct sourceBlock_t sourceBlocks;
} xorStruct_t;

/* Used to detect the end of the program */
static volatile int exiting = 0;

static volatile int sfd = -1;

static struct sockaddr_in6 local_addr;

decode_rlc_t *rlc = NULL;

int send_raw_socket(const struct repairSymbol_t *repairSymbol) {
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

int send_raw_socket_recovered(const recoveredSource_t *repairSymbol) {
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
    memcpy(packet, repairSymbol->packet, MAX_PACKET_SIZE);
    packet_length = MAX_PACKET_SIZE;

    
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

static void debug_print(fecConvolution_t *fecConvolution) {
    for (int i = 0; i < RLC_RECEIVER_BUFFER_SIZE; ++i) {
        printf("Valeur du source symbol is: %d\n", ((struct tlvSource__convo_t *)(&fecConvolution->sourceRingBuffer[i].tlv))->encodingSymbolID);
    }
}

static void fecScheme(void *ctx, int cpu, void *data, __u32 data_sz) {
    fecConvolution_t *fecConvolution = (fecConvolution_t *)data;
    printf("Call triggered: %d\n", fecConvolution->encodingSymbolID);

    debug_print(fecConvolution);

    /* Generate the repair symbol */
    int err = rlc__fec_recover(fecConvolution, rlc);
    if (err < 0) {
        printf("ERROR. TODO: handle\n");
    } else {
        printf("Correctly finished\n");
    }
}

static void handle_events(int map_fd_events) {
    /* Define structure for the perf event */
    struct perf_buffer_opts pb_opts = {
        .sample_cb = fecScheme,
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

    printf("Sort ici\n");

cleanup:
    perf_buffer__free(pb);
}

int main(int argc, char **argv)
{
    struct decoder_bpf *skel;
    int err;

    if (argc != 2) {
        fprintf(stderr, "Usage: ./decoder <decoder_addr>");
        return -1;
    }

    /* Init the address structure for current node */
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin6_family = AF_INET6;
    // TODO: now it is hardcoded
    if (inet_pton(AF_INET6, argv[1], local_addr.sin6_addr.s6_addr) != 1) {
        perror("inet ntop src");
        return -1;
    }

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

    /* Get file descriptor of maps and init the value of the structures */
    struct bpf_map *map_xorBuffer = skel->maps.xorBuffer;
    int map_fd_xorBuffer = bpf_map__fd(map_xorBuffer);
    for (int i = 0; i < MAX_BLOCK; ++i) {
        xorStruct_t struct_zero = {};
        bpf_map_update_elem(map_fd_xorBuffer, &i, &struct_zero, BPF_ANY);
    }

    int k0 = 0;
    struct bpf_map *map_fecConvolutionBuffer = skel->maps.fecConvolutionInfoMap;
    int map_fd_fecConvolutionBuffer = bpf_map__fd(map_fecConvolutionBuffer);
    fecConvolution_t convo_struct_zero = {};
    bpf_map_update_elem(map_fd_fecConvolutionBuffer, &k0, &convo_struct_zero, BPF_ANY);

    struct bpf_map *map_events = skel->maps.events;
    int map_fd_events = bpf_map__fd(map_events);

    /* Open raw socket */
    sfd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (sfd == -1) {
        perror("Cannot create socket");
        goto cleanup;
    }

    /* Initialize structure for RLC */
    rlc = initialize_rlc_decode();
    if (!rlc) {
        perror("Cannot create RLC structure");
        goto cleanup;
    }

    /* Enter perf event handling for packet recovering */
    handle_events(map_fd_events);

    printf("Arrive ici\n");

    /* Close socket */
    if (close(sfd) == -1) {
        perror("Cannot close socket");
        goto cleanup;
    }

cleanup:
    // We reach this point when we Ctrl+C with signal handling
    /* Unpin the program and the maps to clean at exit */
    bpf_object__unpin_programs(skel->obj,  "/sys/fs/bpf/decoder");
    bpf_map__unpin(map_xorBuffer, "/sys/fs/bpf/decoder/xorBuffer");
    bpf_map__unpin(map_fecConvolutionBuffer, "/sys/fs/bpf/decoder/fecConvolutionInfoMap");
    // Do not know if I have to unpin the perf event too
    bpf_map__unpin(map_events, "/sys/fs/bpf/decoder/events");
    decoder_bpf__destroy(skel);
    /* Free memory of the RLC structure */
    free_rlc_decode(rlc);
    return 0;
}