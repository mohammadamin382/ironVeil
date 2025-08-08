#!/usr/bin/env python3
from common import open_client, alloc_page_aligned, fill_pattern

def test_va2pa_basic():
    mm, va = alloc_page_aligned(8192)
    try:
        fill_pattern(mm, b"\x55\xaa")
        with open_client() as iv:
            pa, covered = iv.va2pa(va, 4096, writable=True)
            assert pa != 0 and 1 <= covered <= 4096
            # Cross-page coverage
            pa2, covered2 = iv.va2pa(va+4096, 4096, writable=True)
            assert pa2 != pa and 1 <= covered2 <= 4096
    finally:
        mm.close()

if __name__ == "__main__":
    test_va2pa_basic()
    print("[PASS] test_va2pa_basic")
