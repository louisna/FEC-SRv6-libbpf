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
#include "raw_socket_receiver.c"
#include "fec_scheme/window_rlc_gf256/rlc_gf256_decode.c"

#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/seg6.h>

/* Used to detect the end of the program */
static volatile int exiting = 0;

static volatile int sfd = -1;

static struct sockaddr_in6 local_addr;

decode_rlc_t *rlc = NULL;

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
    //printf("CALL TRIGGERED!\n");

    send_raw_socket(sfd, repairSymbol, local_addr);
}

static void debug_print(fecConvolution_t *fecConvolution) {
    for (int i = 0; i < RLC_RECEIVER_BUFFER_SIZE; ++i) {
        printf("Valeur du source symbol is: %d\n", ((struct tlvSource__convo_t *)(&fecConvolution->sourceRingBuffer[i].tlv))->encodingSymbolID);
    }
}

int globalCount = 0;

static void fecScheme(void *ctx, int cpu, void *data, __u32 data_sz) {
    fecConvolution_t *fecConvolution = (fecConvolution_t *)data;
    //printf("Call triggered: %d\n", fecConvolution->encodingSymbolID);

    //debug_print(fecConvolution);

    ++globalCount;

    /* Generate the repair symbol */
    int err = rlc__fec_recover(fecConvolution, rlc, sfd, local_addr);
    if (err < 0) {
        printf("ERROR. TODO: handle\n");
    } else {
        //printf("Correctly finished\n");
    }
}

static void handle_events(int map_fd_events) {
    /* Define structure for the perf event */
    struct perf_buffer_opts pb_opts = {
        //.sample_cb = fecScheme,
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

    printf("GLOBAL COUNT: %d\n", globalCount);

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