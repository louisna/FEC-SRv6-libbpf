#ifndef ENCODER_STRUCT_H
#define ENCODER_STRUCT_H

#include "fec_srv6.h"

#define BPF_ERROR BPF_OK
#define DEBUG 0

#define RLC_BUFFER_SIZE MAX_RLC_WINDOW_SIZE
#define RLC_RS_NUMBER 1

typedef struct sourceSymbol_t {
    __u8 packet[MAX_PACKET_SIZE];
    __u16 packet_length;
} source_symbol_t;

typedef struct repairSymbol_t {
    __u8 tlv[sizeof(struct tlvRepair__block_t)];
    __u8 packet[MAX_PACKET_SIZE];
    __u16 packet_length;
} repair_symbol_t;

typedef struct {
    __u16 soubleBlock;
    __u16 sourceSymbolCount;
    struct sourceSymbol_t sourceSymbol;
    struct repairSymbol_t repairSymbol;
    __u8 currentBlockSize;
} fecBlock_user_t;

// CONVOLUTION
typedef struct {
    __u32 encodingSymbolID;
    __u16 repairKey;
    __u8 ringBuffSize; // Number of packets for next coding in the ring buffer
    struct sourceSymbol_t sourceRingBuffer[RLC_BUFFER_SIZE];
    struct tlvRepair__convo_t repairTlv[RLC_RS_NUMBER];
    __u8 currentWindowSize;
    __u8 currentWindowSlide;
    // Controller parameters
    __u8 controller_repair; // Enabling or not the controller
    __u8 controller_threshold; // Threshold for the decision function
    __u16 controller_period; // Period between two statistics messages
} fecConvolution_user_t;

typedef struct {
    __u8 *muls;
    struct repairSymbol_t *repairSymbol;
} encode_rlc_t;

#endif