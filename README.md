# Simple TPM 2.0 Wrapper


## Requirements

- python-dev 
- gcc
- tpm2-tss 
- tpm2-tools
- automake
- autoconf
- autoconf-archive
- openssl
- libssl-dev

### TPM2-TSS

git clone https://github.com/tpm2-software/tpm2-tss;
and install following INSTALL.md instructions

### TPM2-TOOLS

git clone https://github.com/tpm2-software/tpm2-tools
and install following INSTALL.md instructions

## Build Python module

```
python setup.py build -b .build install
```

## Test

```bash
python tests/test.py
```


## Usage


### Sign

```python
from tpm20 import tpm20
data = b"to be signed data"
signature = tpm20.sign(data)
```


### Extract public key

```python
from tpm20 import tpm20
pubkey = tpm20.public_key
```
