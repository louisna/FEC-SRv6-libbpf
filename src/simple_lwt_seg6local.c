// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "simple_lwt_seg6local.skel.h"
#include <bpf/bpf.h>

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

    /* Attach tracepoint handler */
    /*err = simple_lwt_seg6local_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton :(\n");
        goto cleanup; 
    }*/

    int fd = bpf_program__nth_fd(skel->progs.notify_ok, 0);
    printf("Value of the file descriptor of the program: %d\n", fd);
    printf("Name is: %s\n", bpf_program__name(skel->progs.notify_ok));


    bpf_object__pin(skel->obj, "/sys/fs/bpf/simple_me");

    char *cmd = "sudo ip -6 route add fc00::a encap seg6local action End.BPF endpoint fd /sys/fs/bpf/simple_me/lwt_seg6local section notify_ok dev enp0s3";
    printf("Command is %sn", cmd);
    //system(cmd);

    struct bpf_map *my_map = skel->maps.my_map;
    int map_fd = bpf_map__fd(my_map);

    while (!exiting) {
        const int k = 0;
        int val = -1;
        bpf_map_lookup_elem(map_fd, &k, &val);
        printf("Value de val:%d\n", val);
        sleep(1);
    }
    bpf_object__unpin_programs(skel->obj, "/sys/fs/bpf/simple_me");
    bpf_map__unpin(my_map, "/sys/fs/bpf/simple_me/my_map");
    simple_lwt_seg6local_bpf__destroy(skel);
cleanup:
    bpf_object__unpin_programs(skel->obj, "/sys/fs/bpf/simple_me");
    return 0;
}