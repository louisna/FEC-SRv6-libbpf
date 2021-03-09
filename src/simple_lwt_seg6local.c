// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "simple_lwt_seg6local.skel.h"

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

    char cmd[150];
    strcat(cmd, "python3 attach_bpf.py add ");

    int fd = bpf_program__nth_fd(skel->progs.notify_ok, 0);
    printf("Value of the file descriptor of the program: %d\n", fd);
    printf("Name is: %s\n", bpf_program__name(skel->progs.notify_ok));

    char buffer[3];
    sprintf(buffer, "%d", fd);
    strcat(cmd, buffer);
    printf("Successfully started the BPF program\n");
    printf("Command to be executed: %s\n", cmd);
    int out = system(cmd);
    printf("Output of the system call: %d\n", out);

    while (!exiting) {
        sleep(1);
    }

cleanup:
    simple_lwt_seg6local_bpf__destroy(skel);
    return 0;
}