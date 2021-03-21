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
static volatile bool exiting = 0;

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