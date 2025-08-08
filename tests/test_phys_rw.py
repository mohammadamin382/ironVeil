#!/usr/bin/env python3
from common import open_client, alloc_page_aligned, fill_pattern, hexdump

def test_phys_read_write_roundtrip():
    # Allocate 1 page, write a pattern, then read phys->user and compare.
    mm, va = alloc_page_aligned(4096)
    try:
        fill_pattern(mm, b"\x13\x37\xca\xfe")
        snap = bytes(mm[:64])  # sample window
        with open_client() as iv:
            pa, cov = iv.va2pa(va, 4096, writable=True)
            # Read back from physical address into a new buffer:
            rb = iv.read_phys(pa, 64)
            assert rb == snap, f"phys read mismatch\nexp={hexdump(snap)}\n got={hexdump(rb)}"

            # Now write a new pattern via physical write and confirm process memory changed:
            new = bytes([0xAB]) * 64
            iv.write_phys(pa, new)
            assert bytes(mm[:64]) == new, "phys write did not reflect into process memory"
    finally:
        mm.close()

if __name__ == "__main__":
    test_phys_read_write_roundtrip()
    print("[PASS] test_phys_rw_roundtrip")
