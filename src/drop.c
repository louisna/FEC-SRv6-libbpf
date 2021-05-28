#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/resource.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "drop.skel.h"
#include <bpf/bpf.h>

typedef struct {
    __u8 k;
    __u8 d;
    __u8 current_state;
    __u64 seed;
    __u32 intercepted;
} drop_markov_t;

/* Used to detect the end of the program */
static volatile int exiting = 0;

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

static void notify_droped(void *ctx, int cpu, void *data, __u32 data_sz) {
    /* Get the repairSymbol
     * ->packet: the decoded and recovered packet
     * ->packet_length: the length of the recovered packet
     */
    int *id_droped = (int *)data;
    printf("Packet droped: %d!\n", *id_droped);
}

static void handle_events(int map_fd_events) {
    /* Define structure for the perf event */
    struct perf_buffer_opts pb_opts = {
        .sample_cb = notify_droped,
        //.sample_cb = send_recovered_symbol_XOR,
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

void update_markov_auto(int map_fd) {
    int key = 0;
    drop_markov_t markov;
    int d, k;
    char useless[10];

    while (!exiting) {
        printf("Wait for next");
        scanf("%s", useless);
        printf("\n");
        bpf_map_lookup_elem(map_fd, &key, &markov);
        printf("Useless 0:%c\n", useless[0]);
        if (useless[0] == 'r') {
            markov.seed = 4; // Reinit
            markov.intercepted = 0;
            printf("Reinit the seed\n");
        } else {
            k = markov.k;
            d = markov.d;
            if (d >= 50) {
                d = 2;
                --k;
            } else {
                d += 2;
            }
            markov.k = k;
            markov.d = d;
            printf("Updated markov with values k=%d d=%d\n", k, d);
        }
        bpf_map_update_elem(map_fd, &key, &markov, BPF_ANY);
    }
}

void update_markov(int map_fd) {
    int key = 0;
    drop_markov_t markov;
    int d, k;

    while (!exiting) {
        printf("Next value (k d): ");
        scanf("%d %d", &k, &d);
        printf("\n");
        bpf_map_lookup_elem(map_fd, &key, &markov);
        if (k == -1) {
            markov.seed = 4; // Reinit
            markov.intercepted = 0;
            printf("Reinit the seed\n");
        } else {
            markov.k = k;
            markov.d = d;
            printf("Updated markov with values k=%d d=%d\n", k, d);
        }
        bpf_map_update_elem(map_fd, &key, &markov, BPF_ANY);
    }
}

int main() {
    struct drop_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything :3 */
    bump_memlock_rlimit();

    /* Clean handling of Ctrl+C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open BPF application */
    skel = drop_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton :(\n");
        return 1;
    }

    /* Load and verify BPF program */
    err = drop_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to verify and load BPF skeleton :(\n");
        goto cleanup;
    }

    /* Pin program object to attach it with iproute2 */
    bpf_object__pin(skel->obj, "/sys/fs/bpf/drop");

    /* Load map */
    struct bpf_map *map_events = skel->maps.events;
    int map_fd_events = bpf_map__fd(map_events);
    struct bpf_map *map_bss = skel->maps.interceptionMap;
    int map_fd_bss = bpf_map__fd(map_bss);
    int k = 0;
    drop_markov_t init_markov = {
        .k = 98,
        .d = 2,
        .current_state = 0,
        .seed = 4,
        .intercepted = 0,
    };
    bpf_map_update_elem(map_fd_bss, &k, &init_markov, BPF_ANY);

    /* Test */
    update_markov_auto(map_fd_bss);
    //while (!exiting) {}

cleanup:
    // We reach this point when we Ctrl+C with signal handling
    /* Unpin the program and the maps to clean at exit */
    bpf_object__unpin_programs(skel->obj,  "/sys/fs/bpf/drop");
    // Do not know if I have to unpin the perf event too
    bpf_map__unpin(map_events, "/sys/fs/bpf/drop/events");
    bpf_map__unpin(map_bss, "/sys/fs/bpf/drop/interceptionMap");
    drop_bpf__destroy(skel);
    return 0;
}