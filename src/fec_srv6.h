#ifndef FEC_SRH_H_
#define FEC_SRH_H_

#define TLV_CODING_SOURCE 28
#define TLV_CODING_REPAIR 29
#define MAX_PACKET_SIZE 512

#define my_memset(ptr, size) ({\
    __u64 *____ptr_64 = (__u64 *)ptr;\
    for (__u16 ____i = 0; ____i < size / 8; ++____i) {\
        ____ptr_64[____i] = 0;\
    }\
})

#define my_memcpy(ptr1, ptr2, size) ({\
    __u64 *____ptr1_64 = (__u64 *)ptr1;\
    __u64 *____ptr2_64 = (__u64 *)ptr2;\
    for (__u16 ____i = 0; ____i < size / 8; ++____i) {\
        ____ptr1_64[____i] = ____ptr2_64[____i];\
    }\
})

#define BPF_PACKET_HEADER __attribute__((packed))

/* Block FEC Framework */
#define MAX_BLOCK_SIZE 10

struct tlvSource__block_t {
    __u8 tlv_type;
    __u8 len;
    __u16 padding;
    __u16 sourceBlockNb;
    __u16 sourceSymbolNb;
} BPF_PACKET_HEADER;

struct tlvRepair__block_t {
    __u8 tlv_type;
    __u8 len;
    __u16 unused;
    __u16 sourceBlockNb;
    __u16 repairSymbolNb; // Will not be used for now
    __u32 repairFecInfo; // Repair FEC Information (32 bits)
    __u16 payload_len; // Payload length in bytes
    __u8 nss; // Number of Source Symbols
    __u8 nrs; // Number of Repair Symbols
} BPF_PACKET_HEADER;

/* Convolutional FEC FRamework */
#define MAX_RLC_WINDOW_SIZE 16
#define MAX_RLC_WINDOW_SLIDE 5
#define MAX_RLC_REPAIR_GEN 8

struct tlvSource__convo_t {
    __u8 tlv_type;
    __u8 len;
    __u16 padding;
    __u32 encodingSymbolID;
} BPF_PACKET_HEADER;

struct tlvRepair__convo_t {
    __u8 tlv_type;
    __u8 len;
    __u16 unused;
    __u32 encodingSymbolID;
    __u32 repairFecInfo;
    __u16 coded_payload_len;
    __u8 nss;
    __u8 nrs;
} BPF_PACKET_HEADER;

/* Controller */
typedef struct {
    __u8 tlv_type;
    __u8 len;
    __u8 controller_repair;
    __u8 padding1;
    __u32 padding4;
} tlv_controller_t;

#endif