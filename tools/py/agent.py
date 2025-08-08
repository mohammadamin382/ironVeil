#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IronVeil — tools/py/agent.py
User-space agent for /dev/ironveil using fcntl.ioctl

Requirements:
  - Python 3.8+
  - Run as root with CAP_SYS_RAWIO
"""

import os
import fcntl
import ctypes as c
import struct
from typing import Optional, Tuple

DEV_PATH = "/dev/ironveil"

# ===== ABI mirror (kpm_abi.h) ================================================

IV_DEV_NAME          = "ironveil"
IV_ABI_VERSION_MAJOR = 1
IV_ABI_VERSION_MINOR = 0

IV_IOC_MAGIC = ord('K')

IV_MAX_IO_BYTES = 16 * 1024 * 1024
IV_AES_GCM_MAX_KEYBYTES = 32
IV_AES_GCM_NONCE_BYTES  = 12
IV_AES_GCM_TAG_BYTES    = 16

# Crypto enum
IV_CRYPTO_NONE         = 0
IV_CRYPTO_AES_GCM_128  = 1
IV_CRYPTO_AES_GCM_256  = 2

# ioctl encodings (re-implement _IOC macros)
_IOC_NRBITS   = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_DIRBITS  = 2
_IOC_NRSHIFT   = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT   + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT  = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_NONE  = 0
_IOC_WRITE = 1
_IOC_READ  = 2

def _IOC(dir_, type_, nr, size):
    return ((dir_  << _IOC_DIRSHIFT)  |
            (type_ << _IOC_TYPESHIFT) |
            (nr    << _IOC_NRSHIFT)   |
            (size  << _IOC_SIZESHIFT))

def _IO(type_, nr):
    return _IOC(_IOC_NONE, type_, nr, 0)

def _IOR(type_, nr, size):
    return _IOC(_IOC_READ, type_, nr, size)

def _IOW(type_, nr, size):
    return _IOC(_IOC_WRITE, type_, nr, size)

def _IOWR(type_, nr, size):
    return _IOC(_IOC_READ | _IOC_WRITE, type_, nr, size)

# ===== ctypes structs (packed) ===============================================

class iv_hdr(c.Structure):
    _pack_ = 1
    _fields_ = [
        ("abi_major", c.c_uint32),
        ("abi_minor", c.c_uint32),
        ("flags",     c.c_uint32),
        ("_pad",      c.c_uint32),
    ]

class iv_ping(c.Structure):
    _pack_ = 1
    _fields_ = [
        ("hdr",       iv_hdr),
        ("cookie_in",  c.c_uint64),
        ("cookie_out", c.c_uint64),
    ]

class iv_va2pa_req(c.Structure):
    _pack_ = 1
    _fields_ = [
        ("hdr",          iv_hdr),
        ("user_vaddr",   c.c_uint64),
        ("length",       c.c_uint64),
        ("out_phys_addr",c.c_uint64),
        ("out_covered",  c.c_uint64),
        ("writable",     c.c_uint32),
        ("_rsvd",        c.c_uint32),
    ]

class iv_phys_rw(c.Structure):
    _pack_ = 1
    _fields_ = [
        ("hdr",       iv_hdr),
        ("phys_addr", c.c_uint64),
        ("length",    c.c_uint64),
        ("user_buf",  c.c_uint64),
        ("write",     c.c_uint32),
        ("_rsvd",     c.c_uint32),
    ]

class iv_set_key(c.Structure):
    _pack_ = 1
    _fields_ = [
        ("hdr",       iv_hdr),
        ("algo",      c.c_uint32),
        ("key_bytes", c.c_uint32),
        ("key",       c.c_uint8 * IV_AES_GCM_MAX_KEYBYTES),
        ("_pad",      c.c_uint8 * (32 - IV_AES_GCM_MAX_KEYBYTES)),
    ]

class iv_clear_key(c.Structure):
    _pack_ = 1
    _fields_ = [
        ("hdr",  iv_hdr),
        ("algo", c.c_uint32),
        ("_rsvd",c.c_uint32),
    ]

class iv_crypto_req(c.Structure):
    _pack_ = 1
    _fields_ = [
        ("hdr",       iv_hdr),
        ("algo",      c.c_uint32),
        ("encrypt",   c.c_uint32),
        ("user_in",   c.c_uint64),
        ("user_out",  c.c_uint64),
        ("aad",       c.c_uint64),
        ("in_len",    c.c_uint64),
        ("aad_len",   c.c_uint64),
        ("nonce",     c.c_uint8 * IV_AES_GCM_NONCE_BYTES),
        ("tag",       c.c_uint8 * IV_AES_GCM_TAG_BYTES),
        ("nonce_len", c.c_uint16),
        ("tag_len",   c.c_uint16),
        ("_rsvd",     c.c_uint32),
    ]

class iv_stats(c.Structure):
    _pack_ = 1
    _fields_ = [
        ("hdr",             iv_hdr),
        ("ops_ioctl",       c.c_uint64),
        ("ops_va2pa",       c.c_uint64),
        ("ops_read_phys",   c.c_uint64),
        ("ops_write_phys",  c.c_uint64),
        ("ops_encrypt",     c.c_uint64),
        ("ops_decrypt",     c.c_uint64),
        ("bytes_read_phys", c.c_uint64),
        ("bytes_write_phys",c.c_uint64),
        ("bytes_crypto_in", c.c_uint64),
        ("bytes_crypto_out",c.c_uint64),
        ("last_err",        c.c_uint64),
    ]

# ioctl numbers (mirror of kpm_abi.h)
IV_IOC_PING        = _IOWR(IV_IOC_MAGIC, 0x00, c.sizeof(iv_ping))
IV_IOC_VA2PA       = _IOWR(IV_IOC_MAGIC, 0x20, c.sizeof(iv_va2pa_req))
IV_IOC_READ_PHYS   = _IOWR(IV_IOC_MAGIC, 0x40, c.sizeof(iv_phys_rw))
IV_IOC_WRITE_PHYS  = _IOWR(IV_IOC_MAGIC, 0x41, c.sizeof(iv_phys_rw))
IV_IOC_SET_KEY     = _IOW (IV_IOC_MAGIC, 0x60, c.sizeof(iv_set_key))
IV_IOC_CLEAR_KEY   = _IOW (IV_IOC_MAGIC, 0x61, c.sizeof(iv_clear_key))
IV_IOC_ENCRYPT     = _IOWR(IV_IOC_MAGIC, 0x62, c.sizeof(iv_crypto_req))
IV_IOC_DECRYPT     = _IOWR(IV_IOC_MAGIC, 0x63, c.sizeof(iv_crypto_req))
IV_IOC_GET_STATS   = _IOWR(IV_IOC_MAGIC, 0x80, c.sizeof(iv_stats))

def _init_hdr(h: iv_hdr):
    h.abi_major = IV_ABI_VERSION_MAJOR
    h.abi_minor = IV_ABI_VERSION_MINOR
    h.flags = 0
    h._pad = 0

# ===== Python agent ===========================================================

class IronVeilClient:
    def __init__(self, dev: str = DEV_PATH):
        self.fd = os.open(dev, os.O_RDWR | os.O_CLOEXEC)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    # Context manager support
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        self.close()

    # --- Ops ---
    def ping(self, cookie: int) -> int:
        req = iv_ping()
        _init_hdr(req.hdr)
        req.cookie_in = c.c_uint64(cookie).value
        fcntl.ioctl(self.fd, IV_IOC_PING, req, True)
        return int(req.cookie_out)

    def va2pa(self, user_vaddr: int, length: int, writable: bool = False) -> Tuple[int, int]:
        req = iv_va2pa_req()
        _init_hdr(req.hdr)
        req.user_vaddr = c.c_uint64(user_vaddr).value
        req.length     = c.c_uint64(length).value
        req.writable   = 1 if writable else 0
        fcntl.ioctl(self.fd, IV_IOC_VA2PA, req, True)
        return (int(req.out_phys_addr), int(req.out_covered))

    def read_phys(self, phys_addr: int, nbytes: int) -> bytes:
        if nbytes <= 0 or nbytes > IV_MAX_IO_BYTES:
            raise ValueError("invalid nbytes")
        buf = bytearray(nbytes)
        req = iv_phys_rw()
        _init_hdr(req.hdr)
        req.phys_addr = c.c_uint64(phys_addr).value
        req.length    = c.c_uint64(nbytes).value
        # user_buf must point into our process buffer
        # Use Python's buffer protocol to obtain address
        addr = self._addr_of(buf)
        req.user_buf  = c.c_uint64(addr).value
        req.write     = 0
        fcntl.ioctl(self.fd, IV_IOC_READ_PHYS, req, True)
        return bytes(buf)

    def write_phys(self, phys_addr: int, data: bytes) -> int:
        nbytes = len(data)
        if nbytes <= 0 or nbytes > IV_MAX_IO_BYTES:
            raise ValueError("invalid nbytes")
        buf = bytearray(data)  # mutable for potential in-place operations
        req = iv_phys_rw()
        _init_hdr(req.hdr)
        req.phys_addr = c.c_uint64(phys_addr).value
        req.length    = c.c_uint64(nbytes).value
        req.user_buf  = c.c_uint64(self._addr_of(buf)).value
        req.write     = 1
        fcntl.ioctl(self.fd, IV_IOC_WRITE_PHYS, req, True)
        return nbytes

    def set_key(self, key: bytes) -> None:
        if len(key) not in (16, 32):
            raise ValueError("AES-GCM key must be 16 or 32 bytes")
        req = iv_set_key()
        _init_hdr(req.hdr)
        req.algo = IV_CRYPTO_AES_GCM_128 if len(key) == 16 else IV_CRYPTO_AES_GCM_256
        req.key_bytes = len(key)
        for i, b in enumerate(key):
            req.key[i] = b
        fcntl.ioctl(self.fd, IV_IOC_SET_KEY, req)

    def clear_key(self) -> None:
        req = iv_clear_key()
        _init_hdr(req.hdr)
        req.algo = 0  # clear all
        fcntl.ioctl(self.fd, IV_IOC_CLEAR_KEY, req)

    def encrypt(self, plaintext: bytes, nonce: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        return self._crypt(True, plaintext, nonce, aad)

    def decrypt(self, ciphertext: bytes, tag: bytes, nonce: bytes, aad: Optional[bytes] = None) -> bytes:
        ct = ciphertext  # decrypt returns plaintext
        pt, _ = self._crypt(False, ct, nonce, aad, tag=tag)
        return pt

    def get_stats(self) -> dict:
        st = iv_stats()
        _init_hdr(st.hdr)
        fcntl.ioctl(self.fd, IV_IOC_GET_STATS, st, True)
        return {
            "ops_ioctl":       int(st.ops_ioctl),
            "ops_va2pa":       int(st.ops_va2pa),
            "ops_read_phys":   int(st.ops_read_phys),
            "ops_write_phys":  int(st.ops_write_phys),
            "ops_encrypt":     int(st.ops_encrypt),
            "ops_decrypt":     int(st.ops_decrypt),
            "bytes_read_phys": int(st.bytes_read_phys),
            "bytes_write_phys":int(st.bytes_write_phys),
            "bytes_crypto_in": int(st.bytes_crypto_in),
            "bytes_crypto_out":int(st.bytes_crypto_out),
            "last_err":        int(st.last_err),
        }

    # ===== helpers =====
    def _crypt(self, encrypt: bool, data: bytes, nonce: bytes, aad: Optional[bytes], tag: bytes = b"") -> Tuple[bytes, bytes]:
        if not (1 <= len(data) <= IV_MAX_IO_BYTES):
            raise ValueError("invalid data length")
        if not (1 <= len(nonce) <= IV_AES_GCM_NONCE_BYTES):
            raise ValueError("invalid nonce length")
        if aad is None:
            aad = b""
        if not encrypt:
            if not (1 <= len(tag) <= IV_AES_GCM_TAG_BYTES):
                raise ValueError("invalid tag length")

        # Make user buffers with stable memory addresses
        in_buf  = bytearray(data)
        out_buf = bytearray(len(data))
        aad_buf = bytearray(aad) if aad else None

        req = iv_crypto_req()
        _init_hdr(req.hdr)
        # algo inferred from set_key; still fill a valid one
        req.algo = IV_CRYPTO_AES_GCM_128 if True else IV_CRYPTO_AES_GCM_256
        req.encrypt = 1 if encrypt else 0
        req.user_in  = c.c_uint64(self._addr_of(in_buf)).value
        req.user_out = c.c_uint64(self._addr_of(out_buf)).value
        req.aad      = c.c_uint64(self._addr_of(aad_buf) if aad_buf is not None else 0).value
        req.in_len   = len(in_buf)
        req.aad_len  = len(aad_buf) if aad_buf is not None else 0
        for i, b in enumerate(nonce[:IV_AES_GCM_NONCE_BYTES]):
            req.nonce[i] = b
        req.nonce_len = len(nonce)
        req.tag_len   = IV_AES_GCM_TAG_BYTES if encrypt else len(tag)
        if not encrypt:
            # provide tag for decrypt
            for i, b in enumerate(tag[:IV_AES_GCM_TAG_BYTES]):
                req.tag[i] = b

        fcntl.ioctl(self.fd, IV_IOC_ENCRYPT if encrypt else IV_IOC_DECRYPT, req, True)

        # On encrypt: kernel filled req.tag
        if encrypt:
            out_tag = bytes(bytearray(req.tag)[:req.tag_len])
            return bytes(out_buf), out_tag
        else:
            return bytes(out_buf), b""

    @staticmethod
    def _addr_of(barr: Optional[bytearray]) -> int:
        if barr is None:
            return 0
        # CPython detail: get address of bytearray's internal buffer via ctypes
        c_char_array = c.c_char * len(barr)
        buf = c_char_array.from_buffer(barr)
        return c.addressof(buf)

# ===== Demo / CLI =============================================================

def _demo():
    import argparse, binascii
    p = argparse.ArgumentParser(description="IronVeil Python agent demo")
    p.add_argument("--dev", default=DEV_PATH)
    p.add_argument("--ping", action="store_true")
    p.add_argument("--va2pa", nargs=2, metavar=("ADDR","LEN"))
    p.add_argument("--read", nargs=2, metavar=("PA","LEN"))
    p.add_argument("--write", nargs=2, metavar=("PA","HEXDATA"))
    p.add_argument("--enc", action="store_true")
    p.add_argument("--dec", action="store_true")
    p.add_argument("--key", help="hex key (16 or 32 bytes)")
    p.add_argument("--nonce", help="hex nonce (<=12 bytes)")
    p.add_argument("--aad", help="hex AAD", default="")
    p.add_argument("--tag", help="hex tag (decrypt)")
    p.add_argument("--stats", action="store_true")
    args = p.parse_args()

    with IronVeilClient(args.dev) as iv:
        if args.ping:
            out = iv.ping(0x123456789abcdef0)
            print("PING:", hex(out))

        if args.va2pa:
            addr = int(args.va2pa[0], 0)
            ln   = int(args.va2pa[1], 0)
            pa, cov = iv.va2pa(addr, ln)
            print(f"VA2PA: pa=0x{pa:x} covered={cov}")

        if args.read:
            pa = int(args.read[0], 0)
            ln = int(args.read[1], 0)
            data = iv.read_phys(pa, ln)
            print("READ:", data.hex())

        if args.write:
            pa = int(args.write[0], 0)
            data = bytes.fromhex(args.write[1])
            n = iv.write_phys(pa, data)
            print("WROTE:", n)

        if args.key:
            key = bytes.fromhex(args.key)
            iv.set_key(key)
            print("Key set.")

        if args.enc:
            if not args.nonce:
                raise SystemExit("--nonce required for --enc")
            nonce = bytes.fromhex(args.nonce)
            aad = bytes.fromhex(args.aad) if args.aad else b""
            pt  = b"hello ironveil"
            ct, tag = iv.encrypt(pt, nonce, aad=aad)
            print("ENC CT:", ct.hex(), "TAG:", tag.hex())

        if args.dec:
            if not (args.nonce and args.tag):
                raise SystemExit("--nonce and --tag required for --dec")
            nonce = bytes.fromhex(args.nonce)
            aad = bytes.fromhex(args.aad) if args.aad else b""
            ct = b"hello ironveil"  # demo placeholder; replace with your ciphertext
            pt = iv.decrypt(ct, bytes.fromhex(args.tag), nonce, aad=aad)
            print("DEC PT:", pt)

        if args.stats:
            print("STATS:", iv.get_stats())

if __name__ == "__main__":
    _demo()
