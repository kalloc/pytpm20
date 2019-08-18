from tpm20 import tpm20

TEST_MESSAGE = b"ZEX" * 40

signature = tpm20.sign(TEST_MESSAGE)
is_ok = tpm20.verify(tpm20.public_key, signature, TEST_MESSAGE) is True
print("Verified {}".format("OK" if is_ok else "Failed"))
