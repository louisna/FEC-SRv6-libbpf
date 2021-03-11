#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 5);
	__type(key, u32);
	__type(value, u32);
} my_map SEC(".maps");

SEC("lwt_seg6local")
int notify_ok(struct __sk_buff *skb) {
    bpf_printk("BPF triggered from packet with SRv6 !\n");
    __u32 k = 0;
    __u32 *val = bpf_map_lookup_elem(&my_map, &k);
    bpf_printk("J'ai recup la valeur...\n");
    __u32 vval;
    if (!val) {
        vval = 0;
    } else {
        vval = *val;
    }
    bpf_printk("Value is: %d\n", vval);
    vval++;
    bpf_map_update_elem(&my_map, &k, &vval, BPF_ANY);

    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";