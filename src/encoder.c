// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/resource.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include "encoder.skel.h"
#include <bpf/bpf.h>
#include "encoder.bpf.h"
#include "raw_socket/raw_socket_sender.h"
#include "fec_scheme/window_rlc_gf256/rlc_gf256.c"

#define MAX_CONTROLLER_UPDATE_LATENCY 10000

enum fec_framework {
    CONVO = 0,
    BLOCK = 1,
};

typedef struct {
    char encoder_ip[48];
    char decoder_ip[48];
    enum fec_framework framework;
    uint8_t block_size;
    uint8_t window_size;
    uint8_t window_slide;
    bool attach;
    char interface[15];
    char controller_ip[48];
    uint8_t controller;
    uint16_t controller_update_every;
    uint8_t controller_threshold; // Percentage
} args_t;


static volatile int sfd = -1;
static volatile int first_sfd = 1;

static struct sockaddr_in6 src;
static struct sockaddr_in6 dst;

encode_rlc_t *rlc = NULL;

// Used to detect the end of the program
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
    // Get the repairSymbol
    // ->packet: the repair symbol
    // ->packet_length: the length of the repair symbol
    // ->tlv: the TLV to be added in the SRH header 
     
    const struct repairSymbol_t *repairSymbol = (struct repairSymbol_t *)data;
    send_raw_socket(sfd, repairSymbol, src, dst);
}

static void fecScheme(void *ctx, int cpu, void *data, __u32 data_sz) {
    fecConvolution_user_t *fecConvolution = (fecConvolution_user_t *)data;
    // Generate the repair symbol 
    int err = rlc__generate_repair_symbols(fecConvolution, rlc, sfd, &src, &dst);
    if (err < 0) {
        printf("ERROR. TODO: handle\n");
        return;
    }

    return;
}

static void handle_events(int map_fd_events, enum fec_framework framework) {
    // Define structure for the perf event 
    struct perf_buffer_opts pb_opts = {0};
    if (framework == BLOCK) {
        pb_opts.sample_cb = send_repairSymbol_XOR;
    } else {
        pb_opts.sample_cb = fecScheme;
    }

    struct perf_buffer *pb = NULL;
    int err;

    pb = perf_buffer__new(map_fd_events, 128, &pb_opts);
    err = libbpf_get_error(pb);
    if (err) {
        pb = NULL;
        fprintf(stderr, "Impossible to open perf event\n");
        goto cleanup;
    }

    // Enter in loop until a signal is retrieved
    // Poll the recovered packet from the BPF program
     
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

void usage(char *prog_name) {
    fprintf(stderr, "USAGE:\n");
    fprintf(stderr, "    %s [-f framework] [-e encoder ipv6] [-d decoder ipv6]\n", prog_name);
    fprintf(stderr, "    -f framework (default: convo): FEC Framework to use [convo, block]\n");
    fprintf(stderr, "    -e encoder_ip (default: fc00::a): IPv6 of the encoder router\n");
    fprintf(stderr, "    -d decoder_ip (default: fc00::9): IPv6 of the decoder router\n");
    fprintf(stderr, "    -b block_size (default: 3): size of a FEC Block (used if framework is block)\n");
    fprintf(stderr, "    -w window_size (default: 4): size of the FEC Window (used if framework is convo)\n");
    fprintf(stderr, "    -s window_slide (default: 2) slide of the window after each repair symbol (used if framework is convo)\n");
    fprintf(stderr, "    -a attach: if set, attempts to attach the program to *encoder_ip*\n");
    fprintf(stderr, "    -i interface: the interface to which attach the program (if *attach* is set)\n");
    fprintf(stderr, "    -c controller_ip (default: fc00::b): activate the controller mechanism\n");
    fprintf(stderr, "    -l update_latency: the number of packets between two controller update (default: 1000)\n");
    fprintf(stderr, "    -t threshold: controller threshold below which repair symbols are forwarded (default: 98)\n");
}

int parse_args(args_t *args, int argc, char *argv[]) {
    memset(args, 0, sizeof(args_t));
    // Default values
    strcpy(args->encoder_ip, "fc00::a");
    strcpy(args->decoder_ip, "fc00::9");
    args->framework = CONVO;
    args->block_size = 3;
    args->window_size = 4;
    args->window_slide = 2;
    args->attach = false;
    strcpy(args->controller_ip, "fc00::b");
    args->controller = 1;
    args->controller_threshold = 98;
    args->controller_update_every = 1024;

    bool interface_if_attach = false;

    int opt;
    while ((opt = getopt(argc, argv, "f:e:d:b:w:s:ai:c:t:l:")) != -1) {
        switch (opt) {
            case 'f':
                if (strncmp(optarg, "block", 6) == 0) {
                    args->framework = BLOCK;
                } else if (strncmp(optarg, "convo", 6) == 0) {
                    args->framework = CONVO;
                } else {
                    fprintf(stderr, "Wrong FEC Framework: %s\n", optarg);
                    return -1;
                }
                break;
            case 'e':
                if (strlen(optarg) > 48) {
                    fprintf(stderr, "Wrong encoder IPv6 address: %s\n", optarg);
                    return -1;
                }
                strncpy(args->encoder_ip, optarg, 48);
                break;
            case 'd':
                if (strlen(optarg) > 48) {
                    fprintf(stderr, "Wrong decoder IPv6 address: %s\n", optarg);
                    return -1;
                }
                strncpy(args->decoder_ip, optarg, 48);
                break;
            case 'b':
                args->block_size = atoi(optarg);
                if (args->block_size <= 0 || args->block_size >= MAX_BLOCK_SIZE) {
                    fprintf(stderr, "Wrong block size, needs to be in [1, %u] but given %u\n", MAX_BLOCK_SIZE - 1, args->block_size);
                    return -1;
                }
                break;
            case 'w':
                args->window_size = atoi(optarg);
                if (args->window_size <= 0 || args->window_size >= MAX_RLC_WINDOW_SIZE) {
                    fprintf(stderr, "Wrong block size, needs to be in [1, %u] but given %u\n", MAX_RLC_WINDOW_SIZE - 1, args->window_size);
                    return -1;
                }
                break;
            case 's':
                args->window_slide = atoi(optarg);
                if (args->window_slide <= 0 || args->window_slide >= MAX_RLC_WINDOW_SLIDE) {
                    fprintf(stderr, "Wrong block size, needs to be in [1, %u] but given %u\n", MAX_RLC_WINDOW_SLIDE - 1, args->window_slide);
                    return -1;
                }
                break;
            case 'a':
                args->attach = true;
                break;
            case 'i':
                if (args->attach) {
                    interface_if_attach = true;
                    strncpy(args->interface, optarg, 15);
                }
                break;
            case 'c':
                args->controller = 3;
                if (strlen(optarg) > 48) {
                    fprintf(stderr, "Wrong controller SID: %s\n", optarg);
                    return -1;
                }
                strncpy(args->controller_ip, optarg, 48);
                break;
            case 'l':
                args->controller_update_every = atoi(optarg);
                if (args->controller_update_every <= 0 || args->controller_update_every > MAX_CONTROLLER_UPDATE_LATENCY) {
                    fprintf(stderr, "Give a valid latency for the controller [0, %u]\n", MAX_CONTROLLER_UPDATE_LATENCY);
                    return -1;
                }
                break;
            case 't':
                args->controller_threshold = atoi(optarg);
                if (args->controller_threshold < 0 || args->controller_threshold > 100) {
                    fprintf(stderr, "Give a valid threshold for the controller [0, 100]\n");
                    return -1;
                }
                break;
            case '?':
                usage(argv[0]);
                return 1;
            default:
                usage(argv[0]);
                return 1;
        }
    }
    if (args->attach && !interface_if_attach) {
            fprintf(stderr, "You need to specify an interface to plug the program\n");
            return -1;
        }

        return 0;
}

int main(int argc, char *argv[]) {
    int err;
    struct encoder_bpf *skel;

    args_t plugin_arguments;
    err = parse_args(&plugin_arguments, argc, argv);
    if (err != 0) {
        exit(EXIT_FAILURE);
    }

    // IPv6 Source address 
    memset(&src, 0, sizeof(src));
    src.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, plugin_arguments.encoder_ip, src.sin6_addr.s6_addr) != 1) {
        perror("inet ntop src");
        return -1;
    }

    // IPv6 Destination address 
    memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	if (inet_pton(AF_INET6, plugin_arguments.decoder_ip, dst.sin6_addr.s6_addr) != 1) {
		perror("inet_ntop dst");
		return -1;
	}

    // Set up libbpf errors and debug info callback 
    libbpf_set_print(libbpf_print_fn);

    // Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything :3 
    bump_memlock_rlimit();

    // Clean handling of Ctrl-C 
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open BPF application 
    skel = encoder_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton :(\n");
        return 1;
    }

    // Load and verify BPF program 
    err = encoder_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to verify and load BPF skeleton :(\n");
        goto cleanup;
    }

    bpf_object__pin(skel->obj, "/sys/fs/bpf/encoder");

    if (plugin_arguments.attach) {
        char attach_cmd[200];
        memset(attach_cmd, 0, 200 * sizeof(char));
        char *framework_str = plugin_arguments.framework == CONVO ? "convo" : "block";
        sprintf(attach_cmd, "ip -6 route add %s encap seg6local action End.BPF endpoint fd /sys/fs/bpf/encoder/lwt_seg6local_%s section srv6_fec dev %s", 
            plugin_arguments.encoder_ip, framework_str, plugin_arguments.interface);
        fprintf(stderr, "Command used to attach: %s\n", attach_cmd);
        system(attach_cmd);

        // Now the same for the controller
        if (plugin_arguments.controller == 3) { // TODO !
            memset(attach_cmd, 0, sizeof(char) * 200);
            sprintf(attach_cmd, "ip -6 route add %s encap seg6local action End.BPF endpoint fd /sys/fs/bpf/encoder/lwt_seg6local_controller section srv6_fec dev %s",
            plugin_arguments.controller_ip, plugin_arguments.interface);
            fprintf(stderr, "Command used to attach the controller: %s\n", attach_cmd);
            system(attach_cmd);
        }
    }


    int k0 = 0;

    // Get file descriptor of maps and init the value of the structures 
    struct bpf_map *map_fecBuffer = skel->maps.fecBuffer;
    int map_fd_fecBuffer = bpf_map__fd(map_fecBuffer);
    fecBlock_t block_init = {0};
    block_init.currentBlockSize = plugin_arguments.block_size;
    bpf_map_update_elem(map_fd_fecBuffer, &k0, &block_init, BPF_ANY);

    struct bpf_map *map_fecConvolutionBuffer = skel->maps.fecConvolutionInfoMap;
    int map_fd_fecConvolutionBuffer = bpf_map__fd(map_fecConvolutionBuffer);
    fecConvolution_t convo_init = {
        .currentWindowSize = plugin_arguments.window_size,
        .currentWindowSlide = plugin_arguments.window_slide,
        .controller_repair = plugin_arguments.controller,
        .controller_threshold = plugin_arguments.controller_threshold,
        .controller_period = plugin_arguments.controller_update_every,
    };
    bpf_map_update_elem(map_fd_fecConvolutionBuffer, &k0, &convo_init, BPF_ANY);

    struct bpf_map *map_events = skel->maps.events;
    int map_fd_events = bpf_map__fd(map_events);

    // Open raw socket 
    sfd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (sfd == -1) {
		perror("Cannot create socket");
		goto cleanup;
	}

    // Initialize structure for RLC 
    rlc = initialize_rlc();
    if (!rlc) {
        perror("Cannot create structure");
        goto cleanup;
    }

    // Enter perf event handling for packet recovering 
    handle_events(map_fd_events, plugin_arguments.framework);

    // Close socket 
    if (close(sfd) == -1) {
		perror("Cannot close socket");
		goto cleanup;
	}

cleanup:
    // We reach this point when we Ctrl+C with signal handling
    // Unpin the program and the maps to clean at exit 
    bpf_object__unpin_programs(skel->obj, "/sys/fs/bpf/encoder");
    bpf_map__unpin(map_fecBuffer, "/sys/fs/bpf/encoder/fecBuffer");
    bpf_map__unpin(map_fecConvolutionBuffer, "/sys/fs/bpf/encoder/fecConvolutionInfoMap");
    // Do not know if I have to unpin the perf event too
    bpf_map__unpin(map_events, "/sys/fs/bpf/encoder/events");
    encoder_bpf__destroy(skel);
    // Free memory of the RLC structure 
    free_rlc(rlc);

    // Detach the program if we attached it
    if (plugin_arguments.attach) {
        char detach_cmd[200];
        sprintf(detach_cmd, "ip -6 route del %s", plugin_arguments.encoder_ip);
        fprintf(stderr, "Command used to detach: %s\n", detach_cmd);
        system(detach_cmd);

        if (plugin_arguments.controller == 3) { // TODO
        sprintf(detach_cmd, "ip -6 route del fc00::b");
        fprintf(stderr, "Command used to detach controller: %s\n", detach_cmd);
        system(detach_cmd);
        }
    }
    return 0;
}
