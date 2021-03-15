// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "simple_lwt_seg6local.skel.h"
#include <bpf/bpf.h>
#include "fec_srv6.h"

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

    // TODO: create the packet with as payload: repairSymbol->packet[:repairSymbol->packet_length]
    /* IPv6 header */
    // TODO

    /* Segment Routing v6 header */
    // TODO

    /* Useless UDP header */
    // TODO

    /* Payload */
    // TODO

    // TODO: send the packet
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

cleanup:
    perf_buffer__free(pb);
}

int main(int argc, char **argv) {
    struct simple_lwt_seg6local_bpf *skel;
    int err;

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
    struct bpf_map *map_indexTable = skel->maps.indexTable;
    int map_fd_indexTable = bpf_map__fd(map_indexTable);

    struct bpf_map *map_sourceSymbolBuffer = skel->maps.sourceSymbolBuffer;
    int map_fd_sourceSymbolBuffer = bpf_map__fd(map_sourceSymbolBuffer);
    struct sourceSymbol_t source_zero = {};
    bpf_map_update_elem(map_fd_sourceSymbolBuffer, &k0, &source_zero, BPF_ANY);

    struct bpf_map *map_repairSymbolBuffer = skel->maps.repairSymbolBuffer;
    int map_fd_repairSymbolBuffer = bpf_map__fd(map_repairSymbolBuffer);
    struct repairSymbol_t repair_zero = {};
    bpf_map_update_elem(map_fd_repairSymbolBuffer, &k0, &repair_zero, BPF_ANY);

    struct bpf_map *map_events = skel->maps.events;
    int map_fd_events = bpf_map__fd(map_events);

    /* Enter perf event handling for packet recovering */
    handle_events(map_fd_events);


    // We reach this point when we Ctrl+C with signal handling
    /* Unpin the program and the maps to clean at exit */
    bpf_object__unpin_programs(skel->obj,  "/sys/fs/bpf/simple_me");
    bpf_map__unpin(map_indexTable,         "/sys/fs/bpf/simple_me/indexTable");
    bpf_map__unpin(map_sourceSymbolBuffer, "/sys/fs/bpf/simple_me/sourceSymbolBuffer");
    bpf_map__unpin(map_repairSymbolBuffer, "/sys/fs/bpf/simple_me/repairSymbolBuffer");
    // Do not know if I have to unpin the perf event too
    bpf_map__unpin(map_events, "/sys/fs/bpf/simple_me/events");
    simple_lwt_seg6local_bpf__destroy(skel);
cleanup:
    return 0;
}