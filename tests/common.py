#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, mmap, ctypes as c, resource, time
from typing import Tuple
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tools.py.agent import IronVeilClient

DEV = "/dev/ironveil"

def require_root():
    if os.geteuid() != 0:
        raise SystemExit("These tests must be run as root (CAP_SYS_RAWIO).")

def require_device():
    if not os.path.exists(DEV):
        raise SystemExit(f"{DEV} not found. Load the module first: sudo insmod ./ironveil.ko")

def open_client() -> IronVeilClient:
    require_root(); require_device()
    return IronVeilClient(DEV)

def alloc_page_aligned(length: int) -> Tuple[mmap.mmap, int]:
    """Allocate RW anonymous memory and return (mmap_obj, user_va_as_int)."""
    length = ((length + mmap.PAGESIZE - 1) // mmap.PAGESIZE) * mmap.PAGESIZE
    mm = mmap.mmap(-1, length, flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS, prot=mmap.PROT_READ|mmap.PROT_WRITE)
    # get pointer address of the mmap buffer
    buf_t = c.c_char * length
    buf = buf_t.from_buffer(mm)
    addr = c.addressof(buf)
    return mm, addr

def fill_pattern(mm: mmap.mmap, pattern: bytes):
    n = len(mm); pat = pattern
    while len(pat) < n: pat += pattern
    mm[:] = pat[:n]

def hexdump(b: bytes, width=16) -> str:
    return "".join(f"{x:02x}" for x in b)
