#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENCE[] SEC("license") = "Dual BSD/GPL";

SEC("lwt_seg6local")
int notify_ok(struct __sk_buff *skb) {
    bpf_printk("BPF triggered from packet with SRv6 !\n");
    
    return BPF_OK;
}