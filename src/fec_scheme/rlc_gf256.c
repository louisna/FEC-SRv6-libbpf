#include <stdint.h>
#include "../prng/tinymt32.c"
#include "../gf256/swif_symbol.c"

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

    for (uint8_t i = 0; i < RLC_WINDOW_SIZE; ++i) {
        /* Get the source symbol in order in the window */
        uint8_t sourceBufferIndex = (encodingSymbolID - RLC_WINDOW_SIZE + i) % RLC_BUFFER_SIZE;
        struct sourceSymbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[sourceBufferIndex];

        /* Compute the maximum length of the source symbols */
        max_length = sourceSymbol->packet_length > max_length ? sourceSymbol->packet_length : max_length;
    }

    for (uint8_t i = 0; i < RLC_WINDOW_SIZE; ++i) {
        /* Get the source symbol in order in the window */
        uint8_t sourceBufferIndex = (encodingSymbolID - RLC_WINDOW_SIZE + i) % RLC_BUFFER_SIZE;
        struct sourceSymbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[sourceBufferIndex];

        /* Encode the source symbol in the packet */
        symbol_add_scaled(repairSymbol->packet, coefs[i], sourceSymbol, max_length, rlc->muls);
    }

    /* Now add and complete the TLV */
    memcpy(&repairSymbol->tlv, &fecConvolution->repairTlv, sizeof(struct tlvRepair__convo_t));

    /* Also add the remaining parameter */
    struct tlvRepair__convo_t *tlv = (struct tlvRepair__convo_t *)&repairSymbol->tlv;
    tlv->payload_len = max_length; // TODO: Should be set to the coding of each payload length !

    /* And finally the length of the repair symbol is the maximum length */
    repairSymbol->packet_length = max_length;

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

void assign_inv(uint8_t *array) {
        array[0] = 0; array[1] = 1; array[2] = 142; array[3] = 244; array[4] = 71; array[5] = 167; array[6] = 122; array[7] = 186; array[8] = 173; array[9] = 157; array[10] = 221; array[11] = 152; array[12] = 61; array[13] = 170; array[14] = 93; array[15] = 150; array[16] = 216; array[17] = 114; array[18] = 192; array[19] = 88; array[20] = 224; array[21] = 62; array[22] = 76; array[23] = 102; array[24] = 144; array[25] = 222; array[26] = 85; array[27] = 128; array[28] = 160; array[29] = 131; array[30] = 75; array[31] = 42; array[32] = 108; array[33] = 237; array[34] = 57; array[35] = 81; array[36] = 96; array[37] = 86; array[38] = 44; array[39] = 138; array[40] = 112; array[41] = 208; array[42] = 31; array[43] = 74; array[44] = 38; array[45] = 139; array[46] = 51; array[47] = 110; array[48] = 72; array[49] = 137; array[50] = 111; array[51] = 46; array[52] = 164; array[53] = 195; array[54] = 64; array[55] = 94; array[56] = 80; array[57] = 34; array[58] = 207; array[59] = 169; array[60] = 171; array[61] = 12; array[62] = 21; array[63] = 225; array[64] = 54; array[65] = 95; array[66] = 248; array[67] = 213; array[68] = 146; array[69] = 78; array[70] = 166; array[71] = 4; array[72] = 48; array[73] = 136; array[74] = 43; array[75] = 30; array[76] = 22; array[77] = 103; array[78] = 69; array[79] = 147; array[80] = 56; array[81] = 35; array[82] = 104; array[83] = 140; array[84] = 129; array[85] = 26; array[86] = 37; array[87] = 97; array[88] = 19; array[89] = 193; array[90] = 203; array[91] = 99; array[92] = 151; array[93] = 14; array[94] = 55; array[95] = 65; array[96] = 36; array[97] = 87; array[98] = 202; array[99] = 91; array[100] = 185; array[101] = 196; array[102] = 23; array[103] = 77; array[104] = 82; array[105] = 141; array[106] = 239; array[107] = 179; array[108] = 32; array[109] = 236; array[110] = 47; array[111] = 50; array[112] = 40; array[113] = 209; array[114] = 17; array[115] = 217; array[116] = 233; array[117] = 251; array[118] = 218; array[119] = 121; array[120] = 219; array[121] = 119; array[122] = 6; array[123] = 187; array[124] = 132; array[125] = 205; array[126] = 254; array[127] = 252; array[128] = 27; array[129] = 84; array[130] = 161; array[131] = 29; array[132] = 124; array[133] = 204; array[134] = 228; array[135] = 176; array[136] = 73; array[137] = 49; array[138] = 39; array[139] = 45; array[140] = 83; array[141] = 105; array[142] = 2; array[143] = 245; array[144] = 24; array[145] = 223; array[146] = 68; array[147] = 79; array[148] = 155; array[149] = 188; array[150] = 15; array[151] = 92; array[152] = 11; array[153] = 220; array[154] = 189; array[155] = 148; array[156] = 172; array[157] = 9; array[158] = 199; array[159] = 162; array[160] = 28; array[161] = 130; array[162] = 159; array[163] = 198; array[164] = 52; array[165] = 194; array[166] = 70; array[167] = 5; array[168] = 206; array[169] = 59; array[170] = 13; array[171] = 60; array[172] = 156; array[173] = 8; array[174] = 190; array[175] = 183; array[176] = 135; array[177] = 229; array[178] = 238; array[179] = 107; array[180] = 235; array[181] = 242; array[182] = 191; array[183] = 175; array[184] = 197; array[185] = 100; array[186] = 7; array[187] = 123; array[188] = 149; array[189] = 154; array[190] = 174; array[191] = 182; array[192] = 18; array[193] = 89; array[194] = 165; array[195] = 53; array[196] = 101; array[197] = 184; array[198] = 163; array[199] = 158; array[200] = 210; array[201] = 247; array[202] = 98; array[203] = 90; array[204] = 133; array[205] = 125; array[206] = 168; array[207] = 58; array[208] = 41; array[209] = 113; array[210] = 200; array[211] = 246; array[212] = 249; array[213] = 67; array[214] = 215; array[215] = 214; array[216] = 16; array[217] = 115; array[218] = 118; array[219] = 120; array[220] = 153; array[221] = 10; array[222] = 25; array[223] = 145; array[224] = 20; array[225] = 63; array[226] = 230; array[227] = 240; array[228] = 134; array[229] = 177; array[230] = 226; array[231] = 241; array[232] = 250; array[233] = 116; array[234] = 243; array[235] = 180; array[236] = 109; array[237] = 33; array[238] = 178; array[239] = 106; array[240] = 227; array[241] = 231; array[242] = 181; array[243] = 234; array[244] = 3; array[245] = 143; array[246] = 211; array[247] = 201; array[248] = 66; array[249] = 212; array[250] = 232; array[251] = 117; array[252] = 127; array[253] = 255; array[254] = 126; array[255] = 253;
}