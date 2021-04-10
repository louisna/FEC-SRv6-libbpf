#include <stdint.h>
#include "../prng/tinymt32.c"
#include "../gf256/swif_symbol.c"
#include "../decoder.h"

#define MIN(a, b) ((a < b) ? a : b)
#define MAX_WINDOW_CHECK 3
#define LOOP for(int ____i = 0; ____i < 1000; ____i++) {}

void print_recovered(recoveredSource_t *recoveredPacket) {
    uint8_t *packet = recoveredPacket->packet;
    for (int i = 0; i < 158; ++i) {
        printf("idx=%d    val=%u\n", i, packet[i]);
    }
    printf("\n\n");
}

void swap(uint8_t **a, int i, int j) {
    uint8_t *tmp = a[j];
    a[j] = a[i];
    a[i] = tmp;
}

int cmp_eq_i(uint8_t *a, uint8_t *b, int idx, int n_unknowns) {
    if (a[idx] < b[idx]) return -1;
    else if (a[idx] > b[idx]) return 1;
    else if (a[idx] != 0) return 0;
    return 0;
}

int cmp_eq(uint8_t *a, uint8_t *b, int idx, int n_unknowns) {
    for (int i = 0 ; i < n_unknowns ; i++) {
        int cmp = 0;
        if ((cmp = cmp_eq_i(a, b, i, n_unknowns)) != 0) {
            return cmp;
        }
    }
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

int first_non_zero_idx(const uint8_t *a, int n_unknowns) {
    for (int i = 0 ; i < n_unknowns ; i++) {
        if (a[i] != 0) {
            return i;
        }
    }
    return -1;
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
    
    sort_system(a, constant_temps, n_eq, n_unknowns);

    for (i = 0 ; i < n_eq-1 ; i++) {
        int first_nz_id = first_non_zero_idx(a[i], n_unknowns);
        if (first_nz_id == -1) {
            break;
        }
        for (j = first_nz_id + 1 ; j < n_unknowns && a[i][j] != 0; j++) {
            for (k = i + 1 ; k < n_eq ; k++) {
                int first_nz_id_below = first_non_zero_idx(a[k], n_unknowns);
                if (j > first_nz_id_below) {
                    break;
                } else if (first_nz_id_below == j) {
                    uint8_t term = gf256_mul(a[i][j], inv[a[k][j]], mul);
                    for (int l = j ; l < n_unknowns ; l++) {
                        a[i][l] = gf256_sub(a[i][l], gf256_mul(term, a[k][l], mul));
                    }
                    symbol_sub_scaled(constant_temps[i], term, constant_temps[k], symbol_size, mul);
                    break;
                }
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

    uint8_t effective_window_check = 0;
    uint8_t current_encodingSymbolID = encodingSymbolID;
    for (int i = 0; i < MAX_WINDOW_CHECK; ++i) {
        window_info_t *window_info = &fecConvolution->windowInfoBuffer[current_encodingSymbolID % RLC_RECEIVER_BUFFER_SIZE];
        if (current_encodingSymbolID == ((struct tlvRepair__convo_t *)&window_info->repairSymbol.tlv)->encodingSymbolID) {
            ++effective_window_check;
            current_encodingSymbolID -= RLC_WINDOW_SLIDE;
        } else {
            break; // Gap in the repair symbols, we stop
        }
    }
    uint8_t source_symbol_nb = (effective_window_check - 1) * RLC_WINDOW_SLIDE + RLC_WINDOW_SIZE;

    /* Find all lost symbols in the last 3 windows if we have the repair symbol of the window */
    uint8_t **source_symbols_array = malloc(source_symbol_nb * sizeof(uint8_t *)); // TODO: check malloc
    memset(source_symbols_array, 0, sizeof(uint8_t *) * source_symbol_nb);
    /*for (int i = 0; i < source_symbol_nb; ++i) {
        source_symbols_array[i] = malloc(MAX_PACKET_SIZE);
        memset(source_symbols_array[i], 0, MAX_PACKET_SIZE);
    }*/
    struct repairSymbol_t **repair_symbols_array = malloc(effective_window_check * sizeof(struct repairSymbol_t *)); // TODO: check malloc
    memset(repair_symbols_array, 0, sizeof(struct repairSymbol_t *) * effective_window_check);
    for (int i = 0; i < effective_window_check; ++i) {
        repair_symbols_array[i] = malloc(sizeof(struct repairSymbol_t));
        memset(repair_symbols_array[i], 0, sizeof(struct repairSymbol_t));
    }

    printf("Passage 1\n");

    uint8_t nb_unknowns = 0;
    uint8_t *unknowns_idx = malloc(source_symbol_nb); // Mapping x => source symbol
    memset(unknowns_idx, 0, source_symbol_nb);
    uint8_t *missing_indexes = malloc(source_symbol_nb); // Mapping source symbol => x
    memset(missing_indexes, -1, source_symbol_nb);

    bool *protected_symbol = malloc(sizeof(bool) * source_symbol_nb);
    memset(protected_symbol, 0, source_symbol_nb * sizeof(bool));

    uint32_t id_first_ss_first_window = encodingSymbolID - source_symbol_nb + 1;
    uint32_t id_first_rs_first_window = encodingSymbolID - (effective_window_check - 1) * RLC_WINDOW_SLIDE;

    printf("Passage 2\n");

    /* Store the source and repair symbols in a new structure to merge US and KS */
    for (int i = 0; i < effective_window_check; ++i) {
        uint32_t idx = (id_first_rs_first_window + RLC_WINDOW_SLIDE * i) % RLC_RECEIVER_BUFFER_SIZE;
        memcpy(repair_symbols_array[i], &fecConvolution->windowInfoBuffer[idx].repairSymbol, MAX_PACKET_SIZE);
    }
    printf("Passage 3\n");
    for (int i = 0; i < source_symbol_nb; ++i) {
        printf("Passage ?\n");
        uint32_t idx = (id_first_ss_first_window + i) % RLC_RECEIVER_BUFFER_SIZE;
        printf("idx=%u, maxss=%u, i=%d, id first=%u\n", idx, source_symbol_nb, i, id_first_ss_first_window);
        printf("id first rs=%u, encodingSymbolID=%u\n", id_first_rs_first_window, encodingSymbolID);
        for (int j = 0; j < 1000; ++j) {}
        printf("Passage 3.1\n");
        uint32_t id_from_buffer = ((struct tlvSource__convo_t *)&fecConvolution->sourceRingBuffer[idx].tlv)->encodingSymbolID;
        uint32_t theoric_id = id_first_ss_first_window + i;
        printf("Passage 3.2\n");
        printf("id buffer: %d, theoric id=%d\n", id_from_buffer, theoric_id);
        for (int j = 0; j < 1000; ++j) {}
        if (id_from_buffer == theoric_id) {
            source_symbols_array[i] = malloc(MAX_PACKET_SIZE);
            memset(source_symbols_array[i], 0, MAX_PACKET_SIZE);
            memcpy(source_symbols_array[i], fecConvolution->sourceRingBuffer[idx].packet, MAX_PACKET_SIZE);
            for (int l = 0; l < 158; ++l) {
                printf("Source symbol #%d at index %d=%x\n", i, l, source_symbols_array[i][l]);
            }
        } else if (rlc->recoveredSources[idx]) {
            printf("Passage 3.4\n");
            for (int j = 0; j < 1000; ++j) {}
            if (rlc->recoveredSources[idx]->encodingSymbolID == theoric_id) {
                source_symbols_array[i] = malloc(MAX_PACKET_SIZE);
                memset(source_symbols_array[i], 0, MAX_PACKET_SIZE);
                memcpy(source_symbols_array[i], rlc->recoveredSources[idx]->packet, MAX_PACKET_SIZE);
            }
        } else {
            printf("Passage 3.3: %d %d\n", i, idx);
            for (int j = 0; j < 1000; ++j) {}
            unknowns_idx[nb_unknowns] = i; // Store index of the lost packet (unknown for the equation system)
            missing_indexes[i] = nb_unknowns;
            ++nb_unknowns;
        }
    }
    printf("Passage 4\n");

    // System is Ax=b

    int n_eq = MIN(nb_unknowns, effective_window_check);
    uint8_t *coefs = malloc(RLC_WINDOW_SIZE); // changed
    memset(coefs, 0, RLC_WINDOW_SIZE);
    uint8_t **unknowns = malloc(nb_unknowns * sizeof(uint8_t *)); // Table of (lost) packets to be recovered = x
    memset(unknowns, 0, nb_unknowns * sizeof(uint8_t *));
    uint8_t **system_coefs = malloc(n_eq * sizeof(uint8_t *)); // Double dimension array = A
    memset(system_coefs, 0, n_eq * sizeof(uint8_t *));
    uint8_t **constant_terms = malloc(nb_unknowns * sizeof(uint8_t *)); // independent term = b
    memset(constant_terms, 0, nb_unknowns * sizeof(uint8_t *));
    bool *undetermined = malloc(nb_unknowns * sizeof(bool)); // Indicates which (lost) source symbols could not be recovered
    memset(undetermined, 0, sizeof(nb_unknowns * sizeof(bool)));

    for (int i = 0 ; i < n_eq ; i++) {
        system_coefs[i] = malloc(nb_unknowns);
        if (!system_coefs[i]) {
            return -1;
        }
        memset(system_coefs[i], 0, nb_unknowns);
    }
    printf("Passage 5\n");

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

    /*for (int l = 0; l < MAX_PACKET_SIZE; ++l) {
        printf("Valeur du repair symbol 0 a index %d=%x\n", l, repair_symbols_array[0]->packet[l]);
    }*/

    for (int rs = 0; rs < effective_window_check; ++rs) {
        struct repairSymbol_t *repairSymbol = repair_symbols_array[rs];
        bool protect_at_least_one_ss = false;
        // Check if this repair symbol protects at least one lost source symbol
        for (int k = 0; k < RLC_WINDOW_SIZE; ++k) {
            int idx = rs * RLC_WINDOW_SLIDE + k;
            printf("Value of idx=%d\n", idx);
            if (!source_symbols_array[idx] && !protected_symbol[idx]) {
                protect_at_least_one_ss = true;
                protected_symbol[idx] = true;
                printf("Enter protects");
                break;
            }
        }
        printf("protects at least one ? %d\n", protect_at_least_one_ss);
        if (protect_at_least_one_ss) {
            constant_terms[i] = malloc(MAX_PACKET_SIZE);
            if (!constant_terms[i]) return -1;
        
            memset(constant_terms[i], 0, MAX_PACKET_SIZE);
            memcpy(constant_terms[i], repairSymbol->packet, MAX_PACKET_SIZE);
            memset(system_coefs[i], 0, nb_unknowns);
            uint16_t repairKey = 1;//((struct tlvRepair__convo_t *)&repairSymbol->tlv)->repairFecInfo >> 4;
            rlc__get_coefs(&prng, repairKey, RLC_WINDOW_SIZE, coefs); // TODO: coefs specific ? line 454
            printf("repairKey is %d\n", repairKey);
            for (int jj = 0; jj < RLC_WINDOW_SIZE; ++jj) {
                printf("Valeur du coef: %d\n", coefs[jj]);
            }
            int current_unknown = 0;
            printf("Passage 5.1\n");
            LOOP
            for (int j = 0; j < RLC_WINDOW_SIZE; ++j) {
                int idx = rs * RLC_WINDOW_SLIDE + j;
                if (source_symbols_array[idx]) { // This protected source symbol is received
                printf("Source symbol #%d at index %d=%x with coef=%d\n", j, j, source_symbols_array[idx][142], coefs[j]);
                    symbol_sub_scaled(constant_terms[i], coefs[j], source_symbols_array[idx], MAX_PACKET_SIZE, muls);
                } else if (current_unknown < nb_unknowns) {
                    if (missing_indexes[idx] != -1) {
                        printf("Passage 5.2\n");
                        LOOP
                        system_coefs[i][missing_indexes[idx]] = coefs[j];
                        printf("Passage 5.3 avec coef=%d missing idx=%d\n", coefs[j], missing_indexes[idx]);
                        LOOP
                    } else {
                        printf("Erreur ici 3452\n");
                    }
                }
            }
            ++i;
        }
    }
    printf("Passage 6\n");
    free(protected_symbol);
    int n_effective_equations = i;

    bool can_recover = n_effective_equations >= nb_unknowns;
    printf("neffe eq=%d, nb_unknown=%d\n", n_effective_equations, nb_unknowns);
    if (can_recover) {
        gaussElimination(n_effective_equations, nb_unknowns, system_coefs, constant_terms, unknowns, undetermined, MAX_PACKET_SIZE, muls, rlc->table_inv);
    } else {
        printf("Cannot recover\n");
    }
    printf("Passage 7\n");
    
    int current_unknown = 0;
    int err = 0;
    for (int j = 0; j < nb_unknowns; ++j) {
        int idx = unknowns_idx[j];
        if (can_recover && !source_symbols_array[idx] && !undetermined[idx] && !symbol_is_zero(unknowns[current_unknown], MAX_PACKET_SIZE)) {
            recoveredSource_t *recovered = malloc(sizeof(recoveredSource_t));
            memset(recovered, 0, sizeof(recoveredSource_t));
            recovered->encodingSymbolID = id_first_ss_first_window + idx;
            memcpy(recovered->packet, unknowns[current_unknown], MAX_PACKET_SIZE);

            /* Add the recovered packet in the recovered buffer */
            int bufferIdx = recovered->encodingSymbolID % RLC_RECEIVER_BUFFER_SIZE;
            if (rlc->recoveredSources[bufferIdx]) free(rlc->recoveredSources[bufferIdx]);
            rlc->recoveredSources[recovered->encodingSymbolID % RLC_RECEIVER_BUFFER_SIZE] = recovered;
            // TODO: get the length also
            // TODO: send the packet
            print_recovered(recovered);
            send_raw_socket_recovered(recovered);
            
        }
        free(unknowns[current_unknown++]);
    }

    printf("Passage 8\n");

    /* Free the system */
    for (i = 0; i < n_eq; ++i) {
        free(system_coefs[i]);
        if (i < n_effective_equations) {
            free(constant_terms[i]);
        }
    }
    for (int i = 0; i < source_symbol_nb; ++i) {
        if (source_symbols_array[i])
            free(source_symbols_array[i]);
    }
    for (int i = 0; i < effective_window_check; ++i) {
        if (repair_symbols_array[i])
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
    printf("Passage 9\n");
    
    return err;
}


decode_rlc_t *initialize_rlc_decode() {
    decode_rlc_t *rlc = malloc(sizeof(decode_rlc_t));
    if (!rlc) return 0;

    memset(rlc, 0, sizeof(decode_rlc_t));

    /* Create and fill the products */
    uint8_t *muls = malloc(256 * 256 * sizeof(uint8_t));
    if (!muls) {
        free(rlc);
        return 0;
    }
    memset(muls, 0, 256 * 256 * sizeof(uint8_t));
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
    memset(table_inv, 0, 256 * sizeof(uint8_t));
    assign_inv(table_inv);
    rlc->table_inv = table_inv;

    return rlc;
}

void free_rlc_decode(decode_rlc_t *rlc) {
    printf("Free 1\n");
    free(rlc->muls);
    printf("Free 2\n");
    free(rlc->table_inv);
    printf("Free 3\n");
    for (int i = 0; i < RLC_RECEIVER_BUFFER_SIZE; ++i) {
        if (rlc->recoveredSources[i]) free(rlc->recoveredSources[i]);
    }
    printf("Free 4\n");
    free(rlc);
    printf("Free 5\n");
}