#ifndef BPF_H_
#define BPF_H_
#include <linux/bpf.h>
#endif
#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_
#include <bpf/bpf_helpers.h>
#endif

#include <bpf/bpf_tracing.h>

/* Perf even buffer */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

typedef struct {
    __u8 k;
    __u8 d;
    __u8 current_state;
    __u64 seed;
    __u32 intercepted;
} drop_markov_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, drop_markov_t);
} interceptionMap SEC(".maps");

// From https://stackoverflow.com/questions/506118/how-to-manually-generate-random-numbers
static __always_inline __u64 my_random_generator(__u64 seed) {
    __u64 next = seed * 1103515245 + 12345;
    return ((unsigned) (next / 65536) % 32768);
}

static __always_inline int drop_predefined(int id_to_drop[10]) {
    int k = 0;

    drop_markov_t *intercepted = bpf_map_lookup_elem(&interceptionMap, &k);
    if (!intercepted) return BPF_OK;

    int is_to_drop = 0;
    for (int i = 0; i < 4; ++i) {
        if (intercepted->intercepted == id_to_drop[i]) {
            is_to_drop = 1;
            break;
        }
    }

    //bpf_printk("Drop: I drop ? %d with value %d\n", is_to_drop, intercepted->intercepted);
    
    if (is_to_drop) {
        //bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, intercepted, sizeof(int));
        intercepted->intercepted += 1;
        bpf_printk("Drop packet %u\n", intercepted->intercepted-1);
        return BPF_DROP;
    } else {
        intercepted->intercepted += 1;
        return BPF_OK;
    }
}

static __always_inline void update_markov_model(drop_markov_t *markov) {
    // RLC: 3999 and 4000
    // XOR: always 4000
    //__u8 intercepted_first = markov->k == 98 && markov->d == 2 && markov->intercepted >= 4000;
    //__u8 intercepted_after = (markov->k != 98 || markov->d != 2) && markov->intercepted >= 4000;
    __u8 intercepted_first = 0;
    __u8 intercepted_after = markov->intercepted >= 1000;
    if (intercepted_first || intercepted_after) {
        bpf_printk("Intercepted=%u\n", markov->intercepted);
        markov->intercepted = 0;
        if (markov->d >= 50) {
            markov->d = 2;
            --markov->k;
        } else {
            ++markov->d;
        }

        if (markov->k < 90) {
            markov->k = 90;
            bpf_printk("Droper: /!\\ already in this state\n");
            }
        bpf_printk("Droper: updated the params to k=%d, d=%d\n", markov->k, markov->d);
    }
}

static __always_inline int drop_markov_model() {
    int k = 0;
    drop_markov_t *markov = bpf_map_lookup_elem(&interceptionMap, &k);
    if (!markov) return BPF_OK;

    update_markov_model(markov);

    int is_to_drop = 0;
    __u64 next = my_random_generator(markov->seed);

    /* Update the intercepted value */
    ++markov->intercepted;

    /* The current value will serve as the seed for next call */
    markov->seed = next;

    /* Update the finite state machine */
    if (markov->current_state == 0) { // BPF_OK state
        if (next % 100 <= markov->k) { // Keep the symbol
            markov->current_state = 0;
            return BPF_OK;
        } else {
            markov->current_state = 1;
            //bpf_printk("Drop intercepted #%d\n", markov->intercepted - 1);
            return BPF_DROP;
        }
    } else {
        if (next % 100 >= markov->d) { // Keep the symbol
            markov->current_state = 0;
            return BPF_OK;
        } else {
            markov->current_state = 1;
            //bpf_printk("Drop intercepted #%d\n", markov->intercepted - 1);
            return BPF_DROP;
        }
    }
}

SEC("lwt_seg6local")
int drop(struct __sk_buff *skb) {
    //int id_to_drop[] = {0, 3, 6, 7, -1, -1}; // Test for (4, 2)
    //int id_to_drop[] = {2, 3, 5, -1, -1, -1, -1, -1, -1, -1}; // Test for (4, 2) with 3 loss
    int id_to_drop[] = {8, 3, 4, -1, -1, -1, -1, -1, -1, -1}; // Test for (4, 2) with 3 loss
    //int id_to_drop[] = {2, 14, 19, -1, -1, -1, -1, -1, -1, -1}; // Test for (4, 2) with 3 loss
    return drop_predefined(id_to_drop);
    //return drop_markov_model();
}

char LICENSE[] SEC("license") = "GPL";