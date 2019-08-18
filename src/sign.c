#include "utils.h"
#include <openssl/pem.h>


static unsigned char * extract_ecdsa(TPMS_SIGNATURE_ECDSA *ecdsa, size_t *size) {

    /*
     * This code is a bit of hack for converting from a TPM ECDSA
     * signature, to an ASN1 encoded one for things like OSSL.
     *
     * The problem here, is that it is unclear the proper OSSL
     * calls to make the SEQUENCE HEADER populate.
     *
     * AN ECDSA Signature is an ASN1 sequence of 2 ASNI Integers,
     * the R and the S portions of the signature.
     */
    static const unsigned SEQ_HDR_SIZE = 2;

    unsigned char *buf = NULL;
    unsigned char *buf_r = NULL;
    unsigned char *buf_s = NULL;

    TPM2B_ECC_PARAMETER *R = &ecdsa->signatureR;
    TPM2B_ECC_PARAMETER *S = &ecdsa->signatureS;

    /*
     * 1. Calculate the sizes of the ASN1 INTEGERS
     *    DER encoded.
     * 2. Allocate an array big enough for them and
     *    the SEQUENCE header.
     * 3. Set the header 0x30 and length
     * 4. Copy in R then S
     */
    ASN1_INTEGER *asn1_r = ASN1_INTEGER_new();
    ASN1_INTEGER *asn1_s = ASN1_INTEGER_new();
    if (!asn1_r || !asn1_s) {
       /* LOG_ERR("oom"); */
        goto out;
    }

    /*
     * I wanted to calc the total size with i2d_ASN1_INTEGER
     * using a NULL output buffer, per the man page this should
     * work, however the code was dereferencing the pointer.
     *
     * I'll just let is alloc the buffers
     */
    ASN1_STRING_set(asn1_r, R->buffer, R->size);
    int size_r = i2d_ASN1_INTEGER(asn1_r, &buf_r);
    if (size_r < 0) {
       /*  LOG_ERR("Error converting R to ASN1");*/
        goto out;
    }

    ASN1_STRING_set(asn1_s, S->buffer, S->size);
    int size_s = i2d_ASN1_INTEGER(asn1_s, &buf_s);
    if (size_s < 0) {
       /*  LOG_ERR("Error converting R to ASN1");*/
        goto out;
    }

    /*
     * If the size doesn't fit in a byte my
     * encoding hack for ASN1 Sequence won't
     * work, so fail...loudly.
     */
    if (size_s + size_r > 0xFF) {
       /* LOG_ERR("Cannot encode ASN1 Sequence, too big!");*/
        goto out;
    }

    buf = malloc(size_s + size_r + SEQ_HDR_SIZE);
    if (!buf) {
        /* LOG_ERR("oom");*/
        goto out;
    }

    unsigned char *p = buf;

    /* populate header and skip */
    p[0] = 0x30;
    p[1] = size_r + size_s;
    p += 2;

    memcpy(p, buf_r, size_r);
    p += size_r;
    memcpy(p, buf_s, size_s);

    *size = size_r + size_s + SEQ_HDR_SIZE;

out:
    if (asn1_r) {
        ASN1_INTEGER_free(asn1_r);
    }

    if (asn1_s) {
        ASN1_INTEGER_free(asn1_s);
    }

    free(buf_r);
    free(buf_s);

    return buf;
}

TPM2_RC sign(
        context *ctx,
        unsigned char *input, size_t input_size,
        unsigned char **signature_raw, size_t *signature_size
    ) {
    TPM2B_DIGEST *digest = {0};
    TPMT_TK_HASHCHECK *validation = {0};
    TPMT_SIGNATURE *signature;
    TPM2B_MAX_BUFFER buffer;
    TPMT_SIG_SCHEME in_scheme = {
        .scheme = TPM2_ALG_ECDSA,
        .details = {
            .ecdsa = {
                .hashAlg = TPM2_ALG_SHA256
            }
        }
    };
    TSS2_RC rc;
    ESYS_TR signingkey_obj_session_handle = ESYS_TR_NONE;
    ESYS_TR object = ESYS_TR_NONE;

    tpm_start_auth_session(ctx, &signingkey_obj_session_handle);
    object_from_tpm(ctx, &object, NULL);

    memcpy(&buffer.buffer, input, input_size);
    buffer.size = input_size;

    /* make hash from buffer*/
    rc = Esys_Hash(
        ctx->ectx,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &buffer,
        TPM2_ALG_SHA256,
        TPM2_RH_NULL,
        &digest,
        &validation);

    check_rc(rc);

    rc = Esys_Sign(
            ctx->ectx,
            object,
            signingkey_obj_session_handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            digest,
            &in_scheme,
            validation,
            &signature);
    check_rc(rc);

    rc = Esys_TR_Close(ctx->ectx, &object);
    check_rc(rc);

    rc = Esys_FlushContext(ctx->ectx, signingkey_obj_session_handle);
    check_rc(rc);

    *signature_raw = extract_ecdsa(&signature->signature.ecdsa, signature_size);
    return TSS2_RC_SUCCESS;
}
