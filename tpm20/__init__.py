from hashlib import sha256

import _tpm20
from ecdsa import VerifyingKey
from ecdsa.util import sigdecode_der


class TPM20:
    def __init__(self):
        _tpm20.setup()

    def sign(self, data: bytes) -> bytes:
        return _tpm20.sign(data)

    def random(self, size: int) -> bytes:
        return _tpm20.random(size)

    @property
    def public_key(self) -> bytes:
        return _tpm20.public()

    def verify(self, signature: bytes, message: bytes) -> bool:
        vk = VerifyingKey.from_der(self.public_key)
        return vk.verify(signature, message, hashfunc=sha256, sigdecode=sigdecode_der)


tpm20 = TPM20()
del TPM20

__all__ = ('tpm20')
__version__ = '0.1.0'
