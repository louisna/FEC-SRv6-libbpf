#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define __u8 uint8_t
#define __u16 uint16_t
#define __u32 uint32_t

#include "../../src/fec_scheme/window_rlc_gf256/rlc_gf256_decode.c"

static uint16_t get_prng_length(tinymt32_t *prng, uint16_t seed) {
    tinymt32_init(prng, seed);
    uint16_t length = tinymt32_generate_uint32(prng) % MAX_PACKET_SIZE;
    return MAX(length, 100);
}

int call_rlc__fec_recover(uint8_t window_size, uint8_t window_step, uint8_t repetitions, uint8_t nb_window, uint8_t nb_lost_sym) {
    fecConvolution_t *fecConvolution = malloc(sizeof(fecConvolution_t));
    if (!fecConvolution) return -1;

    uint8_t total_source_symbols = window_size + window_step * (nb_window - 1);

    memset(fecConvolution, 0, sizeof(fecConvolution_t));

    // Fill basic fields of the structure
    fecConvolution->encodingSymbolID = total_source_symbols - 1;
    fecConvolution->controller_repair = 0;
    fecConvolution->repairKey = 0;
    fecConvolution->ringBuffSize = total_source_symbols;
    // Do not use the controller => keep values to 0

    // Define prng parameters
    tinymt32_t prng;
    prng.mat1 = 0x8f7011ee;
    prng.mat2 = 0xfc78ff1f;
    prng.tmat = 0x3793fdff;
    uint16_t seed = 42;

    // Complete fake source symbols
    for (int i = 0; i < total_source_symbols; ++i) {
        source_symbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[i];
        sourceSymbol->packet_length = 2;//get_prng_length(&prng, seed);
        for (int j = 0; j < sourceSymbol->packet_length; ++j) {
            sourceSymbol->packet[i] = i + 41;
        }

        // Complete the TLV of the source symbol
        struct tlvSource__convo_t *tlv = (struct tlvSource__convo_t *)&sourceSymbol->tlv;
        tlv->tlv_type = 28;
        tlv->len = sizeof(struct tlvSource__convo_t) - 2;
        tlv->controller_update = 0;
        tlv->encodingSymbolID = i;

        // Update seed for next call
        seed = sourceSymbol->packet_length;
    }

    // Complete fake repair symbols
    for (int i = 0; i < nb_window; ++i) {
        uint8_t idx = window_size + i * window_step - 1;;
        window_info_t *windowInfo = &fecConvolution->windowInfoBuffer[idx];
        windowInfo->received_rs = 1;
        windowInfo->received_ss = window_size - 1;

        repair_symbol_t *repairSymbol = &windowInfo->repairSymbol;
        repairSymbol->packet_length = MAX_PACKET_SIZE - 1;
        for (int j = 0; j < repairSymbol->packet_length; ++j) {
            repairSymbol->packet[j] = idx + 42;
        }

        // Complete the TLV
        struct tlvRepair__convo_t *tlv = (struct tlvRepair__convo_t *)&repairSymbol->tlv;
        tlv->tlv_type = 29;
        tlv->len = sizeof(struct tlvRepair__convo_t) - 2;
        tlv->controller_update = 0;
        tlv->encodingSymbolID = idx;
        tlv->repairFecInfo = (15 << (16 + 8)) + (window_step << 16) + i;
        tlv->coded_payload_len = 41; // Hope this will not give troubles
        tlv->nss = window_size;
        tlv->nrs = 1;
    }

    // Create decode structure
    decode_rlc_t *decode_rlc = initialize_rlc_decode();
    if (!decode_rlc) {
        free(fecConvolution);
        return -1;
    }

    // Add losses: the decoder considers a source symbol as lost if the encodingSymbolID is wront
    int losses[] = {14, 1, 5, 6, 9, 11, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 68, 70};
    //int losses[] = {14};
    for (int i = 0; i < nb_lost_sym; ++i) {
        source_symbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[total_source_symbols - 1 - i * 2];
        struct tlvSource__convo_t *tlv = (struct tlvSource__convo_t *)&sourceSymbol->tlv;
        tlv->encodingSymbolID = 0;
    }

    // TEST //
    double results[repetitions];
    struct sockaddr_in6 nope;
    memset(&nope, 0, sizeof(struct sockaddr_in6));
    int err;

    for (int i = 0; i < repetitions; ++i) {
        clock_t begin = clock();

        err = rlc__fec_recover(fecConvolution, decode_rlc, -1, nope);

        clock_t end = clock();

        if (err < 0) {
            free(fecConvolution);
            free(decode_rlc);
            return -1;
        }

        results[i] = (double) (end - begin) / CLOCKS_PER_SEC;
    }

    // Print the results in a json format
    printf("[\n");
    for (int i = 0; i < repetitions; ++i) {
        printf("%lf", results[i]);
        if (i + 1 < repetitions) printf(",");
    }
    printf("]\n");

    free(fecConvolution);
    free_rlc_decode(decode_rlc);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Need 4 arguments\n");
        return -1;
    }
    int window_size = atoi(argv[1]);
    int window_step = atoi(argv[2]);
    int repetitions = atoi(argv[3]);
    int nb_lost_sym = atoi(argv[4]);
    if (window_size <= 0 || window_step <= 0 || repetitions <= 0 || nb_lost_sym < 0) {
        fprintf(stderr, "Give correct values !\n");
        return -1;
    }
    if (window_size > MAX_RLC_WINDOW_SIZE || window_step > MAX_RLC_WINDOW_SLIDE || nb_lost_sym > 50) {
        fprintf(stderr, "Give values in ranges\n");
        return -1;
    }
    call_rlc__fec_recover(window_size, window_step, repetitions, nb_lost_sym, nb_lost_sym);
    return 0;
}