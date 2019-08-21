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
    ESYS_CONTEXT *ectx;
    TSS2_TCTI_CONTEXT *tcti_context;
    char device[1024];
} context;

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))
#define check_rc(ret) \
    if(rc != TSS2_RC_SUCCESS) { \
        return rc; \
    }

#define check_rc_and_go(ret, label) \
    if(rc != TSS2_RC_SUCCESS) { \
        goto label; \
    }


#define OBJECT_PRIMARY_HANDLE 0x81010010

TPM2_RC get_random(context *, unsigned char **, size_t *);
TPM2_RC pub(context *, unsigned char **, size_t *);
TPM2_RC clear(context *);
TPM2_RC sign(context *, unsigned char *, size_t, unsigned char **, size_t *);
TPM2_RC init_tpm_device(const char *, context *);
TPM2_RC object_from_tpm(context *, ESYS_TR *, TPM2B_PUBLIC **);
TPM2_RC tpm_start_auth_session(context *, ESYS_TR *);
TPM2_RC make_object_tpm(context *, ESYS_TR *);
void cleanup_tpm_device(context *ctx);
bool convert_pubkey_ECC(TPMT_PUBLIC *, unsigned char **, size_t *); 
void export_to_file(const char *, unsigned char *, size_t);
void export_to_stdout(unsigned char *, size_t);


