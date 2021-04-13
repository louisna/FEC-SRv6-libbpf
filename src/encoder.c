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
#include "encoder.skel.h"
#include <bpf/bpf.h>
#include "encoder.h"
#include "fec_scheme/window_rlc_gf256/rlc_gf256.c"
#include "raw_socket_sender.c"

static volatile int sfd = -1;
static volatile int first_sfd = 1;
static uint64_t total = 0;

static struct sockaddr_in6 src;
static struct sockaddr_in6 dst;

encode_rlc_t *rlc = NULL;

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
    if (total % 10000 == 0) printf("CALL TRIGGERED!\n");
    printf("Information sur mon repair symbol: %u %u\n", repairSymbol->packet_length, repairSymbol->tlv[0]);

    ++total;
    send_raw_socket(sfd, repairSymbol, src, dst);
}

static void fecScheme(void *ctx, int cpu, void *data, __u32 data_sz) {
    fecConvolution_t *fecConvolution = (fecConvolution_t *)data;
    // printf("Call triggered: %d\n", fecConvolution->encodingSymbolID);

    /* Reset the content of the repair symbol from previous call */
    memset(rlc->repairSymbol, 0, sizeof(struct repairSymbol_t));

    /* Generate the repair symbol */
    int err = rlc__generateRepairSymbols(fecConvolution, rlc);
    if (err < 0) {
        printf("ERROR. TODO: handle\n");
        return;
    }

    /* Send the repair symbol */
    err = send_raw_socket(sfd, rlc->repairSymbol, src, dst);
    if (err < 0) {
        perror("Impossible to send packet");
    }
    return;
}

static void handle_events(int map_fd_events) {
    /* Define structure for the perf event */
    struct perf_buffer_opts pb_opts = {
        .sample_cb = fecScheme,
        //.sample_cb = send_repairSymbol_XOR,
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

int main(int argc, char *argv[]) {
    struct encoder_bpf *skel;
    int err;

    if (argc != 3) {
        fprintf(stderr, "Usage: ./encoder <encoder_addr> <decoder_addr>");
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
    skel = encoder_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton :(\n");
        return 1;
    }

    /* Load and verify BPF program */
    err = encoder_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to verify and load BPF skeleton :(\n");
        goto cleanup;
    }

    bpf_object__pin(skel->obj, "/sys/fs/bpf/encoder");

    char *cmd = "sudo ip -6 route add fc00::a encap seg6local action End.BPF endpoint fd /sys/fs/bpf/encoder/lwt_seg6local section notify_ok dev enp0s3";
    printf("Command is %s\n", cmd);
    //system(cmd);

    int k0 = 0;

    /* Get file descriptor of maps and init the value of the structures */
    struct bpf_map *map_fecBuffer = skel->maps.fecBuffer;
    int map_fd_fecBuffer = bpf_map__fd(map_fecBuffer);
    mapStruct_t struct_zero = {};
    bpf_map_update_elem(map_fd_fecBuffer, &k0, &struct_zero, BPF_ANY);

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
    rlc = initialize_rlc();
    if (!rlc) {
        perror("Cannot create structure");
        goto cleanup;
    }

    /* Enter perf event handling for packet recovering */
    handle_events(map_fd_events);

    /* Close socket */
    if (close(sfd) == -1) {
		perror("Cannot close socket");
		goto cleanup;
	}

cleanup:
    // We reach this point when we Ctrl+C with signal handling
    /* Unpin the program and the maps to clean at exit */
    bpf_object__unpin_programs(skel->obj, "/sys/fs/bpf/encoder");
    bpf_map__unpin(map_fecBuffer, "/sys/fs/bpf/encoder/fecBuffer");
    bpf_map__unpin(map_fecConvolutionBuffer, "/sys/fs/bpf/encoder/fecConvolutionInfoMap");
    // Do not know if I have to unpin the perf event too
    bpf_map__unpin(map_events, "/sys/fs/bpf/encoder/events");
    encoder_bpf__destroy(skel);
    /* Free memory of the RLC structure */
    free_rlc(rlc);
    return 0;
}
