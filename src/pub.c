#include "utils.h"


TPM2_RC pub(context *ctx, unsigned char **pubkey, size_t *pubkey_size) {
    TPM2_RC rc;
    TPM2B_PUBLIC * public = {0};
    ESYS_TR object;

    rc = object_from_tpm(ctx, &object, &public);
    check_rc(rc);

    if(convert_pubkey_ECC(&public->publicArea, pubkey, pubkey_size) != true) {
        return TSS2_BASE_RC_MALFORMED_RESPONSE;
    }
    return rc;
}
