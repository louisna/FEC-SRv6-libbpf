#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define __u8 uint8_t
#define __u16 uint16_t
#define __u32 uint32_t

#define MAX(a, b) a > b ? a : b

#include "../../src/fec_scheme/window_rlc_gf256/rlc_gf256.c"

static uint16_t get_prng_length(tinymt32_t *prng, uint16_t seed) {
    tinymt32_init(prng, seed);
    uint16_t length = tinymt32_generate_uint32(prng) % MAX_PACKET_SIZE;
    return MAX(length, 100);
}

int call_rlc_generate_a_repair_symbol(uint8_t window_size, uint8_t window_step, uint8_t repetitions) {
    // SETUP //
    fecConvolution_user_t *fecConvolution = malloc(sizeof(fecConvolution_user_t));
    if (!fecConvolution) return -1;

    memset(fecConvolution, 0, sizeof(fecConvolution_user_t));

    // Fill basic fields of the structure
    fecConvolution->encodingSymbolID = window_size - 1;
    fecConvolution->repairKey = 0;
    fecConvolution->ringBuffSize = window_size; // Simulate full window
    fecConvolution->currentWindowSize = window_size;
    fecConvolution->currentWindowSlide = window_step;
    // Do not use the controller => keep values to 0

    // Complete a fake repair symbol TLV
    struct tlvRepair__convo_t *tlv = (struct tlvRepair__convo_t *)&fecConvolution->repairTlv[0];
    tlv->tlv_type = 29;
    tlv->len = sizeof(struct tlvRepair__convo_t) - 2;
    tlv->controller_update = 0;
    tlv->encodingSymbolID = window_size - 1;
    tlv->repairFecInfo = (15 << (16 + 8)) + (window_step << 16) + 0;
    tlv->coded_payload_len = 0; // Be filled by the encoder
    tlv->nss = window_size;
    tlv->nrs = window_step;

    // Define prng parameters
    tinymt32_t prng;
    prng.mat1 = 0x8f7011ee;
    prng.mat2 = 0xfc78ff1f;
    prng.tmat = 0x3793fdff;
    uint16_t seed = 42;

    // Complete fake source symbols
    for (int i = 0; i < window_size; ++i) {
        source_symbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[i];
        sourceSymbol->packet_length = get_prng_length(&prng, seed);
        for (int j = 0; j < sourceSymbol->packet_length; ++j) {
            sourceSymbol->packet[j] = i + 41;
        }
        
        // Update seed for next call
        seed = sourceSymbol->packet_length;
    }

    // Create and complete encode_rlc_t structure
    encode_rlc_t *encode_rlc = initialize_rlc();
    if (!encode_rlc) {
        free(fecConvolution);
        return -1;
    }

    // TEST //
    double results[repetitions];

    for (int i = 0; i < repetitions; ++i) {
        clock_t begin = clock();

        rlc__generate_a_repair_symbol(fecConvolution, encode_rlc, 0);

        clock_t end = clock();

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
    free(encode_rlc);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Need 3 arguments\n");
        return -1;
    }
    int window_size = atoi(argv[1]);
    int window_step = atoi(argv[2]);
    int repetitions = atoi(argv[3]);
    if (window_size <= 0 || window_step <= 0 || repetitions <= 0) {
        fprintf(stderr, "Give correct values !\n");
        return -1;
    }
    if (window_size > MAX_RLC_WINDOW_SIZE || window_step > MAX_RLC_WINDOW_SLIDE) {
        fprintf(stderr, "Give values in ranges\n");
        return -1;
    }
    call_rlc_generate_a_repair_symbol(window_size, window_step, repetitions);
    return 0;
}