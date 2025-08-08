#!/usr/bin/env python3
from common import open_client
import os

def test_gcm_encrypt_decrypt():
    pt   = b"The quick brown fox jumps over the lazy dog."
    key  = bytes.fromhex("00112233445566778899aabbccddeeff")  # 16B -> AES-GCM-128
    nonce= os.urandom(12)
    aad  = b"ironveil-aad"

    with open_client() as iv:
        iv.clear_key()
        iv.set_key(key)

        ct, tag = iv.encrypt(pt, nonce, aad=aad)
        assert len(ct) == len(pt) and len(tag) == 16

        # Wrong-tag should fail
        bad = bytes([x ^ 0xFF for x in tag])
        try:
            _ = iv.decrypt(ct, bad, nonce, aad=aad)
            raise AssertionError("decrypt succeeded with WRONG tag (expected failure)")
        except OSError:
            pass  # expected: kernel returns -EBADMSG -> OSError in userspace

        # Correct decrypt
        dec = iv.decrypt(ct, tag, nonce, aad=aad)
        assert dec == pt, "GCM decrypt mismatch"

if __name__ == "__main__":
    test_gcm_encrypt_decrypt()
    print("[PASS] test_crypto_gcm")
