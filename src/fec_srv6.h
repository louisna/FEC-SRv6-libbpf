#ifndef FEC_SRH_H_
#define FEC_SRH_H_

#define TLV_CODING_SOURCE 156
#define TLV_CODING_REPAIR 157
#define MAX_PACKET_SIZE 512
#define NB_SOURCE_SYMBOLS 5

#define BPF_PACKET_HEADER __attribute__((packed))

struct tlvSource__block_t {
    __u8 tlv_type;
    __u8 len;
    __u16 sourceBlockNb;
    __u16 sourceSymbolNb;
} BPF_PACKET_HEADER;

struct tlvRepair__block_t {
    __u8 tlv_type;
    __u8 len;
    __u16 sourceBlockNb;
    __u16 repairSymbolNb; // Will not be used for now
    __u32 repairFecInfo; // Repair FEC Information (32 bits)
    __u16 payload_len; // Payload length in bytes
    __u8 nss; // Number of Source Symbols
    __u8 nrs; // Number of Repair Symbols
    __u16 padding;
} BPF_PACKET_HEADER;

struct tlvSource__convo_t {
    __u8 tlv_type;
    __u8 len;
    __u32 encodingSymbolID;
} BPF_PACKET_HEADER;

struct tlvRepair__convo_t {
    __u8 tlv_type;
    __u8 len;
    __u32 encodingSymbolID;
    __u32 repairFecInfo; // TODO: split ?
    __u16 payload_len;
    __u8 nss;
    __u8 nrs;
    __u16 padding;
} BPF_PACKET_HEADER;

#endif