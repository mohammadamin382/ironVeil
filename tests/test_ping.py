#!/usr/bin/env python3
from common import open_client

def test_ping():
    with open_client() as iv:
        cookie = 0x0123456789ABCDEF
        out = iv.ping(cookie)
        assert out == (cookie ^ 0xA5A5A5A5A5A5A5A5), f"PING mismatch: {out:#x}"

if __name__ == "__main__":
    test_ping()
    print("[PASS] test_ping")
