#include <stdint.h>
#include "../prng/tinymt32.c"
#include "../gf256/swif_symbol.c"
#include "../encoder.h"
#define MIN(a, b) ((a < b) ? a : b)

static void rlc__get_coefs(tinymt32_t *prng, uint32_t seed, int n, uint8_t coefs[n]) {
    tinymt32_init(prng, seed);
    int i;
    for (i = 0 ; i < n ; i++) {
        coefs[i] = (uint8_t) tinymt32_generate_uint32(prng);
        if (coefs[i] == 0)
            coefs[i] = 1;
    }
}

static int rlc__generate_a_repair_symbol(fecConvolution_t *fecConvolution, encode_rlc_t *rlc, int idx) {
    uint16_t max_length = 0;
    uint32_t encodingSymbolID = fecConvolution->encodingSymbolID - 1;
    struct repairSymbol_t *repairSymbol = rlc->repairSymbol;
    memset(repairSymbol, 0, sizeof(struct repairSymbol_t));
    uint8_t windowSize = fecConvolution->currentWindowSize;
    printf("Passage 1\n");
    struct tlvRepair__convo_t *tlv = (struct tlvRepair__convo_t *)&fecConvolution->repairTlv[idx];
    uint16_t repairKey = tlv->repairFecInfo & 0xff;
    //uint8_t windowSlide = fecConvolution->currentWindowSlide;
    //printf("size=%d, slide=%d\n", windowSize, windowSlide);

    tinymt32_t prng;
    prng.mat1 = 0x8f7011ee;
    prng.mat2 = 0xfc78ff1f;
    prng.tmat = 0x3793fdff;

    uint8_t *coefs = malloc(sizeof(uint8_t) * windowSize);
    if (!coefs) return -1;

    rlc__get_coefs(&prng, repairKey, windowSize, coefs);
    //printf("repairKey is %d\n", fecConvolution->repairKey);
    //for (int jj = 0; jj < windowSize; ++jj) {
    //    printf("Valeur du coef: %d\n", coefs[jj]);
    //}
    printf("Passage 1\n");

    for (uint8_t i = 0; i < windowSize; ++i) {
        /* Get the source symbol in order in the window */
        uint8_t sourceBufferIndex = (encodingSymbolID - windowSize + i + 1) % windowSize;
        struct sourceSymbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[sourceBufferIndex];

        /* Compute the maximum length of the source symbols */
        max_length = sourceSymbol->packet_length > max_length ? sourceSymbol->packet_length : max_length;
    }

    uint16_t coded_length = 0;

    for (uint8_t i = 0; i < windowSize; ++i) {
        /* Get the source symbol in order in the window */
        uint8_t sourceBufferIndex = (encodingSymbolID - windowSize + i + 1) % windowSize;
        struct sourceSymbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[sourceBufferIndex];
        //printf("Source symbol #%d with idx=%u at index %d=%x with coef=%u\n", i, sourceBufferIndex, sourceBufferIndex, sourceSymbol->packet[142], coefs[i]);

        /* Encode the source symbol in the packet */
        //printf("Source symbol packet length: %u\n", sourceSymbol->packet_length);
        symbol_add_scaled(repairSymbol->packet, coefs[i], sourceSymbol->packet, MAX_PACKET_SIZE, rlc->muls);
        symbol_add_scaled(&coded_length, coefs[i], &sourceSymbol->packet_length, sizeof(uint16_t), rlc->muls);
    }
    printf("Passage 1\n");

    /* Now add and complete the TLV */
    memcpy(&repairSymbol->tlv, tlv, sizeof(struct tlvRepair__convo_t));
    printf("Passage 3\n");

    /* Also add the remaining parameter */
    struct tlvRepair__convo_t *tlv_rs = (struct tlvRepair__convo_t *)&repairSymbol->tlv;
    tlv_rs->coded_payload_len = coded_length; // Get the coded length here
    printf("Passage 2\n");

    /* And finally the length of the repair symbol is the maximum length instead of the coded length */
    repairSymbol->packet_length = max_length;
    printf("Passage 4\n");

    free(coefs);
    printf("Passage 1\n");
    
    return 0;
}

int rlc__generate_repair_symbols(fecConvolution_t *fecConvolution, encode_rlc_t *rlc, int sfd, struct sockaddr_in6 *src, struct sockaddr_in6 *dst) {
    int err;
    for (int i = 0; i < RLC_RS_NUMBER; ++i) {
        // Generate repair symbol #i
        printf("Enter here\n");
        rlc__generate_a_repair_symbol(fecConvolution, rlc, i);
        struct repairSymbol_t *repairSymbol = rlc->repairSymbol;
        printf("Send raw socket\n");
        err = send_raw_socket(sfd, repairSymbol, *src, *dst);
        if (err < 0) {
            perror("Cannot send repair symbol");
        }
    }
    return 0;
}

encode_rlc_t *initialize_rlc() {
    encode_rlc_t *my_rlc = malloc(sizeof(encode_rlc_t));
    if (!my_rlc) return NULL;

    /* Create and fill in the products */
    uint8_t *muls = malloc(256 * 256 * sizeof(uint8_t));
    if (!muls) {
        free(my_rlc);
        return NULL;
    }
    for (int i = 0; i < 256; ++i) {
        for (int j = 0; j < 256; ++j) {
            muls[i * 256 + j] = gf256_mul_formula(i, j);
        }
    }
    my_rlc->muls = muls;

    /* Create and set the repair symbol */
    struct repairSymbol_t *repairSymbol = malloc(sizeof(struct repairSymbol_t));
    if (!repairSymbol) {
        free(muls);
        free(my_rlc);
        return NULL;
    }
    memset(repairSymbol, 0, sizeof(struct repairSymbol_t));
    my_rlc->repairSymbol = repairSymbol;

    return my_rlc;
}

void free_rlc(encode_rlc_t *rlc) {
    free(rlc->muls);
    free(rlc->repairSymbol);
    free(rlc);
}