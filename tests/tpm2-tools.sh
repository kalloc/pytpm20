#!/bin/bash

HASH_ALG=sha256
SIGN_ALG=ecc

set -e
tpm2_clear
tpm2_startup -c
echo "ZEX" > message.dat

tpm2_createprimary -g ${HASH_ALG} -G ${SIGN_ALG} -c primary.ctx
tpm2_print -t TPMS_CONTEXT primary.ctx
tpm2_create -C primary.ctx -g ${HASH_ALG} -G ${SIGN_ALG} -u key.pub -r key.priv
tpm2_evictcontrol -C o -c primary.ctx 0x81010010
tpm2_flushcontext -t
tpm2_load -C 0x81010010 -u key.pub -r key.priv -c obj.ctx
tpm2_print -t TPMS_CONTEXT obj.ctx

tpm2_evictcontrol -C o -c obj.ctx 0x81010011
rm *.ctx key.*
tpm2_sign -c 0x81010011 -g ${HASH_ALG} -o message.dat.sig -f plain message.dat
tpm2_readpublic -c 0x81010011 -o key.pem -f pem
openssl dgst -verify key.pem -keyform pem -sha256 -signature message.dat.sig message.dat
rm -rf message.dat message.dat.sig key.der
