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
#include "decoder.skel.h"
#include <bpf/bpf.h>
#include "decoder.h"
#include "raw_socket/raw_socket_receiver.h"
#include "fec_scheme/window_rlc_gf256/rlc_gf256_decode.c"
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/seg6.h>

#define MAX_CONTROLLER_UPDATE_LATENCY 100000

enum fec_framework {
    CONVO = 0,
    BLOCK = 1,
};

typedef struct {
    char encoder_ip[48];
    char decoder_ip[48];
    enum fec_framework framework;
    bool attach;
    char interface[15];
    uint8_t controller;
    uint16_t controller_update_every;
    uint8_t controller_threshold; // Percentage
} args_t;

args_t plugin_arguments;

/* Used to detect the end of the program */
static volatile int exiting = 0;

static volatile int sfd = -1;

static volatile int map_fd_fecConvolutionBuffer;

static struct sockaddr_in6 local_addr;
static struct sockaddr_in6 encoder;

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

int globalCount = 0;

static void send_recovered_symbol_XOR(void *ctx, int cpu, void *data, __u32 data_sz) {
    /* Get the repairSymbol
     * ->packet: the decoded and recovered packet
     * ->packet_length: the length of the recovered packet
     */
    const struct repairSymbol_t *repairSymbol = (struct repairSymbol_t *)data;

    ++globalCount;
    if (globalCount % 1000 == 0) printf("CALL TRIGGERED!\n");

    send_raw_socket_recovered(sfd, repairSymbol, local_addr);
}

/*static void debug_print(fecConvolution_t *fecConvolution) {
    for (int i = 0; i < RLC_RECEIVER_BUFFER_SIZE; ++i) {
        printf("Valeur du source symbol is: %d\n", ((struct tlvSource__convo_t *)(&fecConvolution->sourceRingBuffer[i].tlv))->encodingSymbolID);
    }
}*/

// Values used for the controller
uint16_t controller_theoric_counter = 0;
uint16_t controller_received_counter = 0;


static void controller(void *data) {
    int k = 0;
    int err;
    controller_t *controller_info = (controller_t *)data;

    // Get the number of source symbols currently in the buffer
    uint8_t total_source_symbols_in_buffer = 0;
    uint8_t idx;
    for (k = 0; k < RLC_RECEIVER_BUFFER_SIZE; ++k) {
        idx = (controller_info->encodingSymbolID - k) % RLC_RECEIVER_BUFFER_SIZE;
        uint32_t source_symbol_id = controller_info->receivedEncodingSymbolId[idx];
        if (source_symbol_id == (controller_info->encodingSymbolID - k)) {
            ++total_source_symbols_in_buffer;
        }
    }

    // Update the counters
    controller_received_counter += total_source_symbols_in_buffer;
    controller_theoric_counter += RLC_RECEIVER_BUFFER_SIZE;

    // Time to send an update message to the encoder
    if (controller_theoric_counter >= plugin_arguments.controller_update_every) {
        // Message to send to the encoder
        uint8_t msg = 0; // Stop sending repair symbols

        // Decision function
        if ((controller_received_counter * 100) / controller_theoric_counter <= plugin_arguments.controller_threshold) {
            msg = 1;
        }

        //printf("Send a update with %u of %u: %u\n", controller_received_counter, controller_theoric_counter, msg);

        // Reset the counter for next update
        controller_received_counter = 0;
        controller_theoric_counter = 0;

        err = send_raw_socket_controller(sfd, local_addr, encoder, msg);
        if (err < 0) {
            fprintf(stderr, "Error while sending the control message\n");
        }
    }
}

static void fecScheme(void *ctx, int cpu, void *data, __u32 data_sz) {
    uint8_t *controller_message = (uint8_t *)data;
    if ((*controller_message) & 0x4) {
        // This is a controller message
        controller(data);
        return;
    }
    // This is a recovering information
    fecConvolution_t *fecConvolution = (fecConvolution_t *)data;
    //printf("Call triggered: %d\n", fecConvolution->encodingSymbolID);

    //debug_print(fecConvolution);

    ++globalCount;

    if (globalCount % 1000 == 0) printf("Coucou\n");

    /* Generate the repair symbol */
    int err = rlc__fec_recover(fecConvolution, rlc, sfd, local_addr);
    if (err < 0) {
        printf("ERROR. TODO: handle\n");
    } else {
        //printf("Correctly finished\n");
    }
}

static void handle_events(int map_fd_events, enum fec_framework framework) {
    /* Define structure for the perf event */
    struct perf_buffer_opts pb_opts = {0};
    if (framework == BLOCK) {
        pb_opts.sample_cb = send_recovered_symbol_XOR;
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

void usage(char *prog_name) {
    fprintf(stderr, "USAGE:\n");
    fprintf(stderr, "    %s [-f framework] [-d decoder ipv6]\n", prog_name);
    fprintf(stderr, "    -f framework (default: convo): FEC Framework to use [convo, block]\n");
    fprintf(stderr, "    -e encoder_ip (default: fc00::a): IPv6 of the encoder router\n");
    fprintf(stderr, "    -d decoder_ip (default: fc00::9): IPv6 of the decoder router\n");
    fprintf(stderr, "    -a attach: if set, attempts to attach the program to *encoder_ip*\n");
    fprintf(stderr, "    -i interface: the interface to which attach the program (if *attach* is set)\n");
    fprintf(stderr, "    -c controller: activate the controller mechanism\n");
    fprintf(stderr, "    -l update latency: the number of packets between two controller update (default: 1000)\n");
    fprintf(stderr, "    -t threshold: controller threshold below which repair symbols are forwarded (default: 98)\n");
}

int parse_args(args_t *args, int argc, char *argv[]) {
    memset(args, 0, sizeof(args_t));
    // Default values
    strcpy(args->decoder_ip, "fc00::9");
    strcpy(args->encoder_ip, "fc00::a");
    args->framework = CONVO;
    args->attach = false;
    args->controller = 0;
    args->controller_threshold = 98;
    args->controller_update_every = 1000;

    bool interface_if_attach = false;

    int opt;
    while ((opt = getopt(argc, argv, "f:d:e:ai:cl:t:")) != -1) {
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
            case 'd':
                if (strlen(optarg) > 48) {
                    fprintf(stderr, "Wrong decoder IPv6 address: %s\n", optarg);
                    return -1;
                }
                strncpy(args->decoder_ip, optarg, 48);
                break;
            case 'e':
                if (strlen(optarg) > 48) {
                    fprintf(stderr, "Wrong decoder IPv6 address: %s\n", optarg);
                    return -1;
                }
                strncpy(args->encoder_ip, optarg, 48);
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
                args->controller = 2;
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

int main(int argc, char **argv)
{
    struct decoder_bpf *skel;
    int err;

    err = parse_args(&plugin_arguments, argc, argv);
    if (err != 0) {
        exit(EXIT_FAILURE);
    }

    /* Init the address structure for current node */
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, plugin_arguments.decoder_ip, local_addr.sin6_addr.s6_addr) != 1) {
        perror("inet ntop src");
        return -1;
    }

    /* Init the address structure for encoder */
    memset(&encoder, 0, sizeof(encoder));
    encoder.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, plugin_arguments.encoder_ip, encoder.sin6_addr.s6_addr) != 1) {
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

    if (plugin_arguments.attach) {
        char attach_cmd[200];
        memset(attach_cmd, 0, 200 * sizeof(char));
        char *framework_str = plugin_arguments.framework == CONVO ? "convo" : "block";
        sprintf(attach_cmd, "ip -6 route add %s encap seg6local action End.BPF endpoint fd /sys/fs/bpf/decoder/lwt_seg6local_%s section srv6_fec dev %s", 
            plugin_arguments.decoder_ip, framework_str, plugin_arguments.interface);
        fprintf(stderr, "Command used to attach: %s\n", attach_cmd);
        system(attach_cmd);
    }

    /* Get file descriptor of maps and init the value of the structures */
    struct bpf_map *map_xorBuffer = skel->maps.xorBuffer;
    int map_fd_xorBuffer = bpf_map__fd(map_xorBuffer);
    for (int i = 0; i < MAX_BLOCK; ++i) {
        xorStruct_t struct_zero = {};
        bpf_map_update_elem(map_fd_xorBuffer, &i, &struct_zero, BPF_ANY);
    }

    int k0 = 0;
    struct bpf_map *map_fecConvolutionBuffer = skel->maps.fecConvolutionInfoMap;
    map_fd_fecConvolutionBuffer = bpf_map__fd(map_fecConvolutionBuffer);
    fecConvolution_t convo_struct_zero = {
        .controller_repair = plugin_arguments.controller,
    };
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
    handle_events(map_fd_events, plugin_arguments.framework);

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

    // Detach the program if we attached it
    if (plugin_arguments.attach) {
        char detach_cmd[200];
        sprintf(detach_cmd, "ip -6 route del %s", plugin_arguments.decoder_ip);
        fprintf(stderr, "Command used to detach: %s\n", detach_cmd);
        system(detach_cmd);
    }
    return 0;
}