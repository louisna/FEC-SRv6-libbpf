#include <stdint.h>
#include "../prng/tinymt32.c"
#include "../gf256/swif_symbol.c"
#include "../encoder.h"

static void rlc__get_coefs(tinymt32_t *prng, uint32_t seed, int n, uint8_t coefs[n]) {
    tinymt32_init(prng, seed);
    int i;
    for (i = 0 ; i < n ; i++) {
        coefs[i] = (uint8_t) tinymt32_generate_uint32(prng);
        if (coefs[i] == 0)
            coefs[i] = 1;
    }
}

static int rlc__generateRepairSymbols(fecConvolution_t *fecConvolution, encode_rlc_t *rlc) {
    uint16_t max_length = 0;
    uint32_t encodingSymbolID = fecConvolution->encodingSymbolID;
    struct repairSymbol_t *repairSymbol = rlc->repairSymbol;

    tinymt32_t prng;
    prng.mat1 = 0x8f7011ee;
    prng.mat2 = 0xfc78ff1f;
    prng.tmat = 0x3793fdff;

    uint8_t *coefs = malloc(sizeof(uint8_t) * RLC_WINDOW_SIZE);
    if (!coefs) return -1;

    rlc__get_coefs(&prng, fecConvolution->repairKey, RLC_WINDOW_SIZE, coefs);
    printf("repairKey is %d\n", fecConvolution->repairKey);
    for (int jj = 0; jj < RLC_WINDOW_SIZE; ++jj) {
        printf("Valeur du coef: %d\n", coefs[jj]);
    }

    for (uint8_t i = 0; i < RLC_WINDOW_SIZE; ++i) {
        /* Get the source symbol in order in the window */
        uint8_t sourceBufferIndex = (encodingSymbolID - RLC_WINDOW_SIZE + i + 1) % RLC_BUFFER_SIZE;
        struct sourceSymbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[sourceBufferIndex];

        /* Compute the maximum length of the source symbols */
        max_length = sourceSymbol->packet_length > max_length ? sourceSymbol->packet_length : max_length;
    }

    uint16_t coded_length = 0;

    for (uint8_t i = 0; i < RLC_WINDOW_SIZE; ++i) {
        /* Get the source symbol in order in the window */
        uint8_t sourceBufferIndex = (encodingSymbolID - RLC_WINDOW_SIZE + i + 1) % RLC_BUFFER_SIZE;
        struct sourceSymbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[sourceBufferIndex];
        //printf("Source symbol #%d with idx=%u at index %d=%x with coef=%u\n", i, sourceBufferIndex, sourceBufferIndex, sourceSymbol->packet[142], coefs[i]);

        /* Encode the source symbol in the packet */
        symbol_add_scaled(repairSymbol->packet, coefs[i], sourceSymbol->packet, MAX_PACKET_SIZE, rlc->muls);
        symbol_add_scaled(&coded_length, coefs[i], &sourceSymbol->packet_length, sizeof(uint16_t), rlc->muls);
    }

    /* Now add and complete the TLV */
    memcpy(&repairSymbol->tlv, &fecConvolution->repairTlv, sizeof(struct tlvRepair__convo_t));

    /* Also add the remaining parameter */
    struct tlvRepair__convo_t *tlv = (struct tlvRepair__convo_t *)&repairSymbol->tlv;
    tlv->coded_payload_len = coded_length; // Get the coded length here

    /* And finally the length of the repair symbol is the maximum length instead of the coded length */
    repairSymbol->packet_length = max_length;

    /*for (int l = 0; l < MAX_PACKET_SIZE; ++l) {
        printf("Repair symbol after encoding at index %d=%x\n", l, repairSymbol->packet[l]);
    }*/

    free(coefs);
    
    return 0;
}

encode_rlc_t *initialize_rlc() {
    encode_rlc_t *rlc = malloc(sizeof(encode_rlc_t));
    if (!rlc) return NULL;

    /* Create and fill in the products */
    uint8_t *muls = malloc(256 * 256 * sizeof(uint8_t));
    if (!muls) {
        free(rlc);
        return NULL;
    }
    for (int i = 0; i < 256; ++i) {
        for (int j = 0; j < 256; ++j) {
            muls[i * 256 + j] = gf256_mul_formula(i, j);
        }
    }
    rlc->muls = muls;

    /* Create and set the repair symbol */
    struct repairSymbol_t *repairSymbol = malloc(sizeof(struct repairSymbol_t));
    if (!repairSymbol) {
        free(muls);
        free(rlc);
    }
    memset(repairSymbol, 0, sizeof(struct repairSymbol_t));
    rlc->repairSymbol = repairSymbol;

    return rlc;
}

void free_rlc(encode_rlc_t *rlc) {
    free(rlc->muls);
    free(rlc->repairSymbol);
    free(rlc);
}