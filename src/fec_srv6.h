#define TLV_CODING_SOURCE 156
#define TLV_CODING_REPAIR 157
#define MAX_PACKET_SIZE 512
#define NB_SOURCE_SYMBOLS 5

#define BPF_PACKET_HEADER __attribute__((packed))

struct coding_source_t {
    unsigned char tlv_type;
    unsigned char len;
    unsigned short sourceBlockNb;
    unsigned short sourceSymbolNb;
} BPF_PACKET_HEADER;

struct coding_repair2_t {
    unsigned char tlv_type;
    unsigned char len;
    unsigned short sourceBlockNb;
    unsigned short repairSymbolNb; // Will not be used for now
    unsigned int repairFecInfo; // Repair FEC Information (32 bits)
    unsigned short payload_len; // Payload length in bytes
    unsigned char nss; // Number of Source Symbols
    unsigned char nrs; // Number of Repair Symbols
    unsigned short padding;
} BPF_PACKET_HEADER;