#ifndef VMLINUX_H_
#define VMLINUX_H_
#include <linux/bpf.h>
#endif

#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_
#include <bpf/bpf_helpers.h>
#endif

#include "../../libseg6.c"
#include "../../decoder.h"

static __always_inline int try_to_recover_from_repair__convoRLC(struct __sk_buff *skb, fecConvolution_t *fecConvolution, window_info_t *window_info, struct tlvRepair__convo_t *tlv) {
    // Analyze if we can recover from a lost packet
    // If we can, send the window alongside with the repair symbol(s) to user space
    if (1 || window_info->received_ss < tlv->nss && window_info->received_rs > 0) {
        // TODO: improve by not sending the entire structure !
        return 1;
    }
    return 0;
}