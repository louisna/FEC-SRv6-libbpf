#ifndef ENCODER_BPF_H
#define ENCODER_BPF_H

#include "encoder.h"

typedef struct {
    __u32 encodingSymbolID;
    __u16 repairKey;
    __u8 ringBuffSize; // Number of packets for next coding in the ring buffer
    struct sourceSymbol_t sourceRingBuffer[RLC_BUFFER_SIZE];
    struct tlvRepair__convo_t repairTlv[RLC_RS_NUMBER];
    __u8 currentWindowSize;
    __u8 currentWindowSlide;
    __u8 controller_repair;
    struct bpf_spin_lock lock;
} fecConvolution_t;

typedef struct {
    __u16 soubleBlock;
    __u16 sourceSymbolCount;
    struct sourceSymbol_t sourceSymbol;
    struct repairSymbol_t repairSymbol;
    __u8 currentBlockSize;
    struct bpf_spin_lock lock;
} fecBlock_t;

#endif