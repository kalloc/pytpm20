#include "utils.h"

#define LEN 32


TPM2_RC get_random(context *ctx, unsigned char **secret, size_t *secret_size) {
    TPM2B_DIGEST *tpm2_buf;
    TSS2_RC rc;

    rc = Esys_GetRandom(ctx->ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, LEN, &tpm2_buf);

    if(rc == TSS2_RC_SUCCESS) {
        memcpy(&(secret)[*secret_size], &tpm2_buf->buffer[0], tpm2_buf->size);
        *secret_size += tpm2_buf->size;
        free(tpm2_buf);
    }
    return rc;
}
