#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>


typedef struct Context {
    TSS2_RC rc;
    ESYS_CONTEXT *esys_ctx;
    char *verbose;
} context;

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))
#define makeContext(rc, ctx) (context){rc, ctx, ""};
#define check_rc(rc, verbose) \
    if(rc != TSS2_RC_SUCCESS) { \
        printf("Error in %s:%d -> %s\n", __FILE__, __LINE__, Tss2_RC_Decode(rc)); \
        return (context){rc, NULL, ""}; \
    }

#define OBJECT_PRIMARY_HANDLE 0x81010010
#define OBJECT_HANDLE 0x81010011

context get_random(context, unsigned char **, size_t *);
context get_pub(context, unsigned char **, size_t *);
context clear(context);
context sign(context, unsigned char *, size_t, unsigned char **, size_t *);
context init_tpm_device(const char *);
context object_from_tpm(context ctx, ESYS_TR *, TPM2B_PUBLIC **);
context tpm_start_auth_session(context, ESYS_TR *);
context make_object_tpm(context, ESYS_TR *);
bool convert_pubkey_ECC(TPMT_PUBLIC *, unsigned char **, size_t *); 
void export_to_file(const char *, unsigned char *, size_t);
void export_to_stdout(unsigned char *, size_t);


