#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "fec_srv6.h"

#define DEBUG 1

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

/* Maps */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, u16);
} indexTable SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct sourceSymbol_t);
} sourceSymbolBuffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct repairSymbol_t);
} repairSymbolBuffer SEC(".maps");

SEC("lwt_seg6local")
int notify_ok(struct __sk_buff *skb) {
    bpf_printk("BPF triggered from packet with SRv6 !\n");
    __u32 k = 0;
    __u16 *val = bpf_map_lookup_elem(&indexTable, &k);
    bpf_printk("J'ai recup la valeur...\n");
    __u16 vval;
    if (!val) {
        vval = 0;
    } else {
        vval = *val;
    }
    bpf_printk("Value is: %d\n", vval);
    vval++;
    bpf_map_update_elem(&indexTable, &k, &vval, BPF_ANY);

    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";