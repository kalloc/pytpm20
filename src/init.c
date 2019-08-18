#include "utils.h"

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>


TPM2_RC tpm_start_auth_session(context *ctx, ESYS_TR *session) {
    TPM2_RC rc;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};
    rc = Esys_StartAuthSession(
        ctx->ectx,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        0, TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256, session
    );
    return rc;
}

TPM2_RC make_object_tpm(context *ctx, ESYS_TR *object) {
    TPM2_RC rc;
    ESYS_TR session = ESYS_TR_NONE, 
            primaryHandle = ESYS_TR_NONE,
            primaryPersistentHandle = ESYS_TR_NONE;

    TPM2B_SENSITIVE_CREATE inSensitive = {0};
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (
                TPMA_OBJECT_USERWITHAUTH |
                TPMA_OBJECT_SIGN_ENCRYPT |
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT |
                TPMA_OBJECT_SENSITIVEDATAORIGIN
            ),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.eccDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL,
                 },
                 .scheme = {
                     .scheme = TPM2_ALG_ECDSA,
                     .details = {
                         .ecdsa =
                         {.hashAlg = TPM2_ALG_SHA256}
                     }
                 },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {.scheme = TPM2_ALG_NULL,
                         .details = {}
                  }
             },
            .unique.ecc = {
                 .x = {.size = 0,.buffer = {0}},
                 .y = {.size = 0,.buffer = {0}}
             }
            ,
        }
    };
    TPM2B_AUTH authValue = {0};
    TPM2B_DATA outsideInfo = {0};
    TPML_PCR_SELECTION creationPCR = {0};

    rc = tpm_start_auth_session(ctx, &session);
    check_rc(rc);

    rc = Esys_TR_SetAuth(ctx->ectx, ESYS_TR_RH_OWNER, &authValue);
    check_rc(rc);

    rc = Esys_CreatePrimary(
        ctx->ectx, ESYS_TR_RH_OWNER, 
        session, ESYS_TR_NONE, ESYS_TR_NONE,
        &inSensitive, &inPublic,
        &outsideInfo, &creationPCR, &primaryHandle,
        NULL, NULL, NULL, NULL
    );
    check_rc(rc);

    rc = Esys_EvictControl(
        ctx->ectx, 
        ESYS_TR_RH_OWNER, primaryHandle,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        OBJECT_PRIMARY_HANDLE, 
        &primaryPersistentHandle
    );
    check_rc(rc);

    *object = primaryPersistentHandle;
    rc = Esys_FlushContext(ctx->ectx, primaryHandle);
    return rc;
}


TPM2_RC object_from_tpm(context *ctx, ESYS_TR *object, TPM2B_PUBLIC **public) {
    TPM2_RC rc;
    TPM2B_NAME *name, *qualified_name;

    rc = Esys_TR_FromTPMPublic(
        ctx->ectx, OBJECT_PRIMARY_HANDLE, 
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        object
    );

    if(rc != TPM2_RC_SUCCESS) {
        rc = make_object_tpm(ctx, object);
        check_rc(rc);
    }

    if(public) {
        rc = Esys_ReadPublic(
            ctx->ectx, *object,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            public, &name, &qualified_name
        );
        check_rc(rc);
    } 
    return rc;
}


bool convert_pubkey_ECC(TPMT_PUBLIC *public, unsigned char **buf, size_t *len) {

    BIGNUM *x = NULL, *y = NULL;
    EC_KEY *key = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;
    BIO *bio = NULL;
    bool result = false;
    int rc;

    TPMS_ECC_POINT *tpm_point = &public->unique.ecc;

    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) {
        return false;
    }

    group = EC_KEY_get0_group(key);
    if (!group) {
        goto out;
    }

    point = EC_POINT_new(group);

    x = BN_bin2bn(tpm_point->x.buffer, tpm_point->x.size, NULL);
    if (!x) {
        goto out;
    }

    y = BN_bin2bn(tpm_point->y.buffer, tpm_point->y.size, NULL);
    if (!y) {
        goto out;
    }

    rc = EC_POINT_set_affine_coordinates_GFp(group, point, x, y, NULL);
    if (!rc) {
        /* Could not set affine coordinates */;
        goto out;
    }

    rc = EC_KEY_set_public_key(key, point);
    if (!rc) {
        goto out;
    }
	
    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		/* Cannot create buffer */
		goto out;
	}

    if(!(i2d_EC_PUBKEY_bio(bio, key))) {
        /* cannot export key */
        goto out;
    }

    if ((*len = BIO_get_mem_data(bio, buf)) <= 0) {
		goto out;
    }

    result = true;

out:
    if (x) {
        BN_free(x);
    }
    if (y) {
        BN_free(y);
    }
    if (point) {
        EC_POINT_free(point);
    }
    if (key) {
        EC_KEY_free(key);
    }

    return result;
}


TPM2_RC init_tpm_device(const char *tcti, context *ctx) {
    TSS2_TCTI_CONTEXT *tcti_context;

    TSS2_RC rc;

    rc = Tss2_TctiLdr_Initialize(tcti, &tcti_context);
    check_rc(rc);

    rc = Esys_Initialize(&ctx->ectx, tcti_context, NULL);
    check_rc(rc);

    rc = Esys_Startup(ctx->ectx, TPM2_SU_CLEAR);
    check_rc(rc);

    return rc;
}

void cleanup_tpm_device(context *ctx) {
    Esys_Finalize(&ctx->ectx);
}
