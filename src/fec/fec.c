#define MAX_RECOVERED_IN_ONE_ROW 4

int recover_block(fecConvolution_t *fecConvolution) {
    uint32_t encodingSymbolID = fecConvolution->encodingSymbolID;

    uint8_t *to_recover = malloc(MAX_RECOVERED_IN_ONE_ROW);
    if (!to_recover) return -1;

    /* Detect the packets that will be recovered and sent */
    int n_to_recover = 0;
    for (uint8_t i = 0; i < RLC_WINDOW_SIZE && i < MAX_RECOVERED_IN_ONE_ROW; ++i) {
        uint8_t sourceBufferIndex = (encodingSymbolID - RLC_WINDOW_SIZE + i) % RLC_RECEIVER_BUFFER_SIZE;
        struct sourceSymbol_t *sourceSymbol = &fecConvolution->sourceRingBuffer[sourceBufferIndex];
        if (sourceSymbol->tlv.encodingSymbolID != encodingSymbolID - RLC_WINDOW_SIZE + i) {
            to_recover[n_to_recover++] = i;
        }
    }

    /* Decode packets packets */

}