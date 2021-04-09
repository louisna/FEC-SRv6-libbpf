#include <stdint.h>
#include "../prng/tinymt32.c"
#include "../gf256/swif_symbol.c"
#include "../decoder.h"

#define MIN(a, b) ((a < b) ? a : b)
#define MAX_WINDOW_CHECK 3

void swap(uint8_t **a, int i, int j) {
    uint8_t *tmp = a[j];
    a[j] = a[i];
    a[i] = tmp;
}

int cmp_eq(uint8_t *a, uint8_t *b, int idx, int n_unknowns) {
    if (a[idx] < b[idx]) return -1;
    else if (a[idx] > b[idx]) return 1;
    return 0;
}

void sort_system(uint8_t **a, uint8_t **constant_terms, int n_eq, int n_unknowns) {
    for (int i = 0; i < n_eq; ++i) {
        int max = i;
        for (int j = i + 1; j < n_eq; ++j) {
            if (cmp_eq(a[max], a[j], i, n_unknowns) < 0) {
                max = j;
            }
        }
        swap(a, i, max);
        swap(constant_terms, i, max);
    }
}

static void rlc__get_coefs(tinymt32_t *prng, uint32_t seed, int n, uint8_t *coefs) {
    tinymt32_init(prng, seed);
    int i;
    for (i = 0 ; i < n ; i++) {
        coefs[i] = (uint8_t) tinymt32_generate_uint32(prng);
        if (coefs[i] == 0)
            coefs[i] = 1;
    }
}

void gaussElimination(int n_eq, int n_unknowns, uint8_t **a, uint8_t *constant_temps[n_eq], uint8_t *x[n_eq], bool undetermined[n_unknowns], uint32_t symbol_size, uint8_t *mul, uint8_t *inv) {
    sort_system(a, constant_temps, n_eq, n_unknowns);
    int i, j, k;
    for (i = 0; i < n_eq - 1; ++i) {
        for (k = i + 1; k < n_eq; ++k) {
            if (k > i) { // WTF ?
                uint8_t mulnum = a[k][i];
                uint8_t mulden = a[i][i];
                uint8_t term = gf256_mul(mulnum, inv[mulden], mul);
                for (j = 0; j < n_unknowns; ++j) {
                    a[k][j] = gf256_sub(a[k][j], gf256_mul(term, a[i][j], mul));
                }
                symbol_sub_scaled(constant_temps[k], term, constant_temps[i], symbol_size, mul);
            }
        }
    }
    int candidate = n_unknowns - 1;
    for (i = n_eq - 1; i >= 0; --i) {
        while (a[i][candidate] == 0 && candidate >= 0) {
            undetermined[candidate--] = true;
        }
        memcpy(x[candidate], constant_temps[i], symbol_size);
        for (int j = 0; j < candidate; ++j) {
            if (a[i][j] != 0) {
                undetermined[candidate] = true;
                break;
            }
        }
        for (j = candidate + 1; j < n_unknowns; ++j) {
            if (a[i][j] != 0) {
                if (undetermined[j]) {
                    undetermined[candidate] = true;
                } else {
                    symbol_sub_scaled(x[candidate], a[i][j], x[j], symbol_size, mul);
                    a[i][j] = 0;
                }
            }
        }
        if (symbol_is_zero(x[candidate], symbol_size) || a[i][candidate] == 0) {
            undetermined[candidate] = true;
        } else if (!undetermined[candidate]) {
            symbol_mul(x[candidate], inv[a[i][candidate]], symbol_size, mul);
            a[i][candidate] = gf256_mul(a[i][candidate], inv[a[i][candidate]], mul);
        } 
        candidate--;
    }
    if (candidate >= 0) {
        memset(undetermined, true, (candidate + 1) * sizeof(bool));
    }
}

static int rlc__fec_recover(fecConvolution_t *fecConvolution, decode_rlc_t *rlc) {
    uint16_t max_length = 0;
    // ID of the last received repair symbol
    uint32_t encodingSymbolID = fecConvolution->encodingSymbolID;
    
    tinymt32_t prng;
    prng.mat1 = 0x8f7011ee;
    prng.mat2 = 0xfc78ff1f;
    prng.tmat = 0x3793fdff;

    uint8_t *muls = rlc->muls;
    // TODO: check again if we can recover ?
    // plugins/fec-pquic/fec_scheme_protoops/rlc_fec_scheme_gf256.c
    // line 140 to see how we should do it

    /* Find all lost symbols in the last 3 windows if we have the repair symbol of the window */
    int max_source_symbols = (MAX_WINDOW_CHECK - 1) * RLC_WINDOW_SLIDE + RLC_WINDOW_SIZE;
    uint8_t **source_symbols_array = malloc(max_source_symbols); // TODO: check malloc
    for (int i = 0; i < max_source_symbols; ++i) {
        source_symbols_array[i] = malloc(MAX_PACKET_SIZE);
        memset(source_symbols_array[i], 0, MAX_PACKET_SIZE);
    }
    struct repairSymbol_t **repair_symbols_array = malloc(MAX_WINDOW_CHECK); // TODO: check malloc
    for (int i = 0; i < MAX_WINDOW_CHECK; ++i) {
        repair_symbols_array[i] = malloc(sizeof(struct repairSymbol_t));
        memset(repair_symbols_array[i], 0, MAX_PACKET_SIZE);
    }

    uint8_t nb_unknowns = 0;
    uint8_t *unknowns_idx = malloc(max_source_symbols); // Mapping x => source symbol
    uint8_t *missing_indexes = malloc(max_source_symbols); // Mapping source symbol => x
    memset(missing_indexes, -1, max_source_symbols);

    bool *protected_symbol = malloc(sizeof(bool) * max_source_symbols);
    memset(protected_symbol, 0, max_source_symbols * sizeof(bool));

    uint32_t id_first_ss_first_window = encodingSymbolID - max_source_symbols + 1;
    uint32_t id_first_rs_first_window = encodingSymbolID - (MAX_WINDOW_CHECK - 1) * RLC_WINDOW_SLIDE;
    // TODO: check if we do not have the repair symbol ?

    /* Store the source and repair symbols in a new structure to merge US and KS */
    for (int i = 0; i < MAX_WINDOW_CHECK; ++i) {
        uint32_t idx = (id_first_rs_first_window + RLC_WINDOW_SLIDE * i) % RLC_RECEIVER_BUFFER_SIZE;
        memcpy(repair_symbols_array[i], &fecConvolution->windowInfoBuffer[idx].repairSymbol, MAX_PACKET_SIZE);
    }
    for (int i = 0; i < max_source_symbols; ++i) {
        uint32_t idx = (id_first_ss_first_window + i) % RLC_RECEIVER_BUFFER_SIZE;
        uint32_t id_from_buffer = ((struct tlvSource__convo_t *)&fecConvolution->sourceRingBuffer[idx].tlv)->encodingSymbolID;
        uint32_t id_from_recover = rlc->recoveredSources[idx]->encodingSymbolID;
        uint32_t theoric_id = id_first_ss_first_window + i;
        if (id_from_buffer == theoric_id) {
            memcpy(source_symbols_array[i], fecConvolution->sourceRingBuffer[idx].packet, MAX_PACKET_SIZE);
        } else if (id_from_recover == theoric_id) {
            memcpy(source_symbols_array[i], rlc->recoveredSources[idx]->packet, MAX_PACKET_SIZE);
        } else {
            unknowns_idx[nb_unknowns] = i; // Store index of the lost packet (unknown for the equation system)
            missing_indexes[i] = nb_unknowns;
            ++nb_unknowns;
        }
    }



    // System is Ax=b

    int n_eq = MIN(nb_unknowns, MAX_WINDOW_CHECK);
    uint8_t *coefs = malloc(RLC_WINDOW_SIZE); // changed
    uint8_t **unknowns = malloc(nb_unknowns * sizeof(uint8_t *)); // Table of (lost) packets to be recovered = x
    uint8_t **system_coefs = malloc(n_eq * sizeof(uint8_t *)); // Double dimension array = A
    uint8_t **constant_terms = malloc(nb_unknowns * sizeof(uint8_t)); // independent term = b
    bool *undetermined = malloc(nb_unknowns * sizeof(bool)); // Indicates which (lost) source symbols could not be recovered
    memset(undetermined, 0, sizeof(nb_unknowns * sizeof(bool)));

    for (int i = 0 ; i < n_eq ; i++) {
        system_coefs[i] = malloc(nb_unknowns);
        if (!system_coefs[i]) {
            return -1;
        }
    }

    for (int j = 0; j < nb_unknowns; ++j) {
        unknowns[j] = malloc(MAX_PACKET_SIZE);
        memset(unknowns[j], 0, MAX_PACKET_SIZE);
    }

    int i = 0;

    /*tinymt32_t *shuffle_prng = malloc(sizeof(tinymt32_t));
    shuffle_prng->mat1 = 0x8f7011ee;
    shuffle_prng->mat2 = 0xfc78ff1f;
    shuffle_prng->tmat = 0x3793fdff;
    tinymt32_init(shuffle_prng, encodingSymbolID * 4 - 5*14); // TODO: change seed ?
    shuffle repair symbols ?
    */

    for (int rs = 0; rs < MAX_WINDOW_CHECK; ++rs) {
        struct repairSymbol_t *repairSymbol = repair_symbols_array[rs];
        bool protect_at_least_one_ss = false;
        // Check if this repair symbol protects at least one lost source symbol
        for (int k = 0; k < RLC_WINDOW_SIZE; ++k) {
            int idx = rs * RLC_WINDOW_SLIDE + k;
            if (!source_symbols_array[idx] && !protected_symbol[idx]) {
                protect_at_least_one_ss = true;
                protected_symbol[idx] = true;
                break;
            }
        }
        if (protect_at_least_one_ss) {
            constant_terms[i] = malloc(MAX_PACKET_SIZE);
            if (!constant_terms[i]) return -1;
        
            memset(constant_terms[i], 0, MAX_PACKET_SIZE);
            memcpy(constant_terms[i], repairSymbol->packet, MAX_PACKET_SIZE);
            memset(system_coefs[i], 0, nb_unknowns);
            uint16_t repairKey = ((struct tlvRepair__convo_t *)&repairSymbol->tlv)->repairFecInfo >> 4;
            rlc__get_coefs(&prng, repairKey, RLC_WINDOW_SIZE, coefs); // TODO: coefs specific ? line 454
            int current_unknown = 0;
            for (int j = 0; j < RLC_WINDOW_SIZE; ++j) {
                int idx = rs * RLC_WINDOW_SLIDE + j;
                if (source_symbols_array[idx]) { // This protected source symbol is received
                    symbol_sub_scaled(constant_terms[i], coefs[j], source_symbols_array[idx], MAX_PACKET_SIZE, muls);
                } else if (current_unknown < nb_unknowns) {
                    if (missing_indexes[idx] != -1) {
                        system_coefs[i][missing_indexes[idx]] = coefs[j];
                    } else {
                        printf("Erreur ici 3452\n");
                    }
                }
            }
            ++i;
        }
    }
    free(protected_symbol);
    int n_effective_equations = i;

    bool can_recover = n_effective_equations >= nb_unknowns;
    if (can_recover) {
        gaussElimination(n_effective_equations, nb_unknowns, system_coefs, constant_terms, unknowns, undetermined, MAX_PACKET_SIZE, muls, rlc->table_inv);
    } else {
        printf("Cannot recover\n");
    }
    
    int current_unknown = 0;
    int err = 0;
    for (int j = 0; j < nb_unknowns; ++j) {
        int idx = unknowns_idx[j];
        if (can_recover && !source_symbols_array[idx] && !undetermined[idx] && !symbol_is_zero(unknowns[current_unknown], MAX_PACKET_SIZE)) {
            recoveredSource_t *recovered = malloc(sizeof(recoveredSource_t));
            recovered->encodingSymbolID = id_first_ss_first_window + idx;
            memcpy(recovered->packet, unknowns[current_unknown], MAX_PACKET_SIZE);

            /* Add the recovered packet in the recovered buffer */
            int bufferIdx = recovered->encodingSymbolID % RLC_RECEIVER_BUFFER_SIZE;
            if (rlc->recoveredSources[bufferIdx]) free(rlc->recoveredSources[bufferIdx]);
            rlc->recoveredSources[recovered->encodingSymbolID % RLC_RECEIVER_BUFFER_SIZE] = recovered;
            // TODO: get the length also
            // TODO: send the packet
            
        }
        free(unknowns[current_unknown++]);
    }

    /* Free the system */
    for (i = 0; i < n_eq; ++i) {
        free(system_coefs[i]);
        if (i < n_effective_equations) {
            free(constant_terms[i]);
        }
    }
    for (int i = 0; i < max_source_symbols; ++i) {
        free(source_symbols_array[i]);
    }
    for (int i = 0; i < MAX_WINDOW_CHECK; ++i) {
        free(repair_symbols_array[i]);
    }
    free(source_symbols_array);
    free(repair_symbols_array);
    free(system_coefs);
    free(constant_terms);
    free(unknowns);
    free(coefs);
    free(undetermined);
    free(unknowns_idx);
    
    return err;
}


decode_rlc_t *initialize_rlc_decode() {
    decode_rlc_t *rlc = malloc(sizeof(decode_rlc_t));
    if (!rlc) return 0;

    /* Create and fill the products */
    uint8_t *muls = malloc(256 * 256 * sizeof(uint8_t));
    if (!muls) {
        free(rlc);
        return 0;
    }
    for (int i = 0; i < 256; ++i) {
        for (int j = 0; j < 256; ++j) {
            muls[i * 256 + j] = gf256_mul_formula(i, j);
        }
    }
    rlc->muls = muls;

    /* Create and set the inverse muls array */
    uint8_t *table_inv = malloc(256 * sizeof(uint8_t));
    if (!table_inv) {
        free(muls);
        free(rlc);
        return 0;
    }
    assign_inv(table_inv);
    rlc->table_inv = table_inv;

    return rlc;
}

void free_rlc_decode(decode_rlc_t *rlc) {
    free(rlc->muls);
    free(rlc->table_inv);
    free(rlc);
}