#include "utils.h"


context get_pub(context ctx, unsigned char **pubkey, size_t *pubkey_size) {
    bool rc;
    TPM2B_PUBLIC * public = {0};
    ESYS_TR object;

    context result = object_from_tpm(ctx, &object, &public);
    check_rc(result.rc, "");

    if((rc = convert_pubkey_ECC(&public->publicArea, pubkey, pubkey_size)) != true) {
        return (context){TSS2_BASE_RC_MALFORMED_RESPONSE, NULL, "Unable to convert pubkey"};
    }
    return makeContext(TSS2_RC_SUCCESS, ctx.esys_ctx);
}
