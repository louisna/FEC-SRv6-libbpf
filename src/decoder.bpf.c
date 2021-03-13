#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "fec_srv6.h"
#include "libseg6.c"

#define DEBUG 1
#define BPF_ERROR BPF_DROP  // Choose action when an error occurs in the process

SEC("lwt_seg6local")
int decode(struct __sk_buff *skb)
{
    bpf_printk("Receiver: BPF triggered from packet with SRv6!\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";