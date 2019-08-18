#!/bin/bash

HASH_ALG=sha256
SIGN_ALG=ecc

set -e
tpm2_clear
tpm2_startup -c
echo "ZEX" > message.dat

ROOT=$(dirname $(dirname $(realpath $0)))
CMD=${ROOT}/.build/src/tools

if [[ ! -f ${CMD} ]]; then
    echo ${CMD} is not found
    exit
fi

${CMD} -T device -p -o key.der
openssl asn1parse -inform der -in key.der
${CMD} -T device -s -i message.dat -o message.dat.sig
openssl dgst -verify key.der -keyform der -sha256 -signature message.dat.sig message.dat
rm -rf message.dat message.dat.sig key.der

