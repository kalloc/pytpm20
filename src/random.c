#include "utils.h"

#define LEN 32


TPM2_RC get_random(context *ctx, unsigned char **secret, size_t *secret_size) {
    TPM2B_DIGEST *tpm2_buf = NULL;
    TSS2_RC rc;
    rc = Esys_GetRandom(ctx->ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, *secret_size, &tpm2_buf);

    if(rc == TSS2_RC_SUCCESS) {
        memcpy(secret, &tpm2_buf->buffer, tpm2_buf->size);
        *secret_size = tpm2_buf->size;
        free(tpm2_buf);
    }
    return rc;
}

