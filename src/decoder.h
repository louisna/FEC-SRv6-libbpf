#ifndef DECODER_STRUCT_H
#define DECODER_STRUCT_H

#include "fec_srv6.h"

#define BPF_ERROR BPF_OK  // Choose action when an error occurs in the process
#define DEBUG 0

#define RLC_RECEIVER_BUFFER_SIZE 32

#define MAX_BLOCK 5

/* Structures */
struct sourceSymbol_t {
    __u8 packet[MAX_PACKET_SIZE];
    __u16 packet_length;
    struct tlvSource__block_t tlv;
} BPF_PACKET_HEADER;

struct repairSymbol_t {
    __u8 packet[MAX_PACKET_SIZE];
    __u16 packet_length; // TODO: change to unsigned short ?
    struct tlvRepair__block_t tlv;
};

struct sourceBlock_t {
    __u16 blockID;
    __u8 receivedSource;
    __u8 receivedRepair;
    __u8 nss;
    __u8 nrs;
};

typedef struct xorStruct {
    struct sourceSymbol_t sourceSymbol;
    struct repairSymbol_t repairSymbols;
    struct sourceBlock_t sourceBlocks;
} xorStruct_t;

typedef struct {
    struct repairSymbol_t repairSymbol;
    __u8 received_ss;
    __u8 received_rs;
    __u32 encodingSymbolID;
} window_info_t;

typedef struct {
    __u16 controller_repair;
    __u32 encodingSymbolID; // Of the current repair symbol
    __u32 receivedEncodingSymbolID[RLC_RECEIVER_BUFFER_SIZE]; // encodingSymbolID received (redundant but faster !)
    __u16 repairKey;
    __u8 ringBuffSize; // Number of packets for next coding in the ring buffer
    struct sourceSymbol_t sourceRingBuffer[RLC_RECEIVER_BUFFER_SIZE];
    window_info_t windowInfoBuffer[RLC_RECEIVER_BUFFER_SIZE];
} fecConvolution_t;

typedef struct {
    __u8 packet[MAX_PACKET_SIZE];
    __u16 packet_length;
    __u32 encodingSymbolID;
} recoveredSource_t;

typedef struct {
    __u8 *muls;
    __u8 *table_inv;
    recoveredSource_t *recoveredSources[RLC_RECEIVER_BUFFER_SIZE];
} decode_rlc_t;

typedef struct {
    __u16 controller_repair;
    __u32 encodingSymbolID;
    __u32 receivedEncodingSymbolId[RLC_RECEIVER_BUFFER_SIZE];
} controller_t;

#endif