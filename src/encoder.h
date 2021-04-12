#ifndef ENCODER_STRUCT_H
#define ENCODER_STRUCT_H

#include "fec_srv6.h"

#define BPF_ERROR BPF_DROP
#define DEBUG 1

#define RLC_BUFFER_SIZE 4
#define RLC_WINDOW_SIZE 4
#define RLC_WINDOW_SLIDE 2

/* Structures */
struct sourceSymbol_t {
    __u8 packet[MAX_PACKET_SIZE];
    __u16 packet_length;
};

struct repairSymbol_t {
    __u8 tlv[sizeof(struct tlvRepair__block_t)];
    __u8 packet[MAX_PACKET_SIZE];
    __u16 packet_length;
};

typedef struct mapStruct {
    __u16 soubleBlock;
    __u16 sourceSymbolCount;
    struct sourceSymbol_t sourceSymbol;
    struct repairSymbol_t repairSymbol;
} mapStruct_t;

/* CONVOLUTION */
typedef struct fecConvolution {
    __u32 encodingSymbolID;
    __u16 repairKey;
    __u8 ringBuffSize; // Number of packets for next coding in the ring buffer
    struct sourceSymbol_t sourceRingBuffer[RLC_BUFFER_SIZE];
    struct tlvRepair__convo_t repairTlv;
} fecConvolution_t;

typedef struct {
    __u8 *muls;
    struct repairSymbol_t *repairSymbol;
} encode_rlc_t;

#endif