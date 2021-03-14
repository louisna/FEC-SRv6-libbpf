#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "fec_srv6.h"
#include "libseg6.c"

#define DEBUG 1
#define BPF_ERROR BPF_DROP  // Choose action when an error occurs in the process

#define MAX_BLOCK 5  // Number of blocks we can simultaneously store
#define MAX_SOURCE_SYMBOLS 25  // Number of source symbols per block
#define DEBUG 1

/* Structures */
struct sourceSymbol_t {
    struct coding_source_t tlv;
    unsigned char packet[MAX_PACKET_SIZE];
    u16 packet_length;
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

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct sourceSymbol_t);
} sourceSymbolBuffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCK);
    __type(key, u32);
    __type(value, struct repairSymbol_t);
} repairSymbolBuffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCK);
    __type(key, u32);
    __type(value, struct sourceBlock_t);
} blockBuffer SEC(".maps");

SEC("lwt_seg6local")
int decode(struct __sk_buff *skb)
{
    bpf_printk("Receiver: BPF triggered from packet with SRv6!\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";