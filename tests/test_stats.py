#!/usr/bin/env python3
from common import open_client, alloc_page_aligned, fill_pattern

def test_stats_progress():
    with open_client() as iv:
        before = iv.get_stats()

        # Do a few ops
        cookie = 0xdeadbeef
        _ = iv.ping(cookie)
        mm, va = alloc_page_aligned(4096)
        try:
            fill_pattern(mm, b"\x42")
            pa, cov = iv.va2pa(va, 4096, writable=True)
            _ = iv.read_phys(pa, 64)
        finally:
            mm.close()

        after = iv.get_stats()
        assert after["ops_ioctl"] >= before["ops_ioctl"] + 3
        assert after["ops_va2pa"]  >= before["ops_va2pa"]  + 1
        assert after["ops_read_phys"] >= before["ops_read_phys"] + 1

if __name__ == "__main__":
    test_stats_progress()
    print("[PASS] test_stats_progress")
