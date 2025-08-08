// SPDX-License-Identifier: GPL-2.0
/*
 * IronVeil — tools/c/kpmctl.c
 * Minimal C CLI for /dev/ironveil using ioctl
 *
 * Build:
 *   cc -O2 -Wall -Wextra -o kpmctl kpmctl.c -I../../include
 *
 * Examples (run as root):
 *   ./kpmctl ping
 *   ./kpmctl va2pa 0x7ffff7dd7000 4096
 *   ./kpmctl read  0x100000 64 | xxd
 *   ./kpmctl write 0x100000 0011223344aabbccddeeff
 *   ./kpmctl setkey 00112233445566778899aabbccddeeff
 *   ./kpmctl enc 00112233445566778899aabbccddeeff "68656c6c6f" ""  // nonce pt aad
 *   ./kpmctl stats
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "kpm_abi.h"

#ifndef DEV_PATH
# define DEV_PATH "/dev/ironveil"
#endif

static void init_hdr(struct iv_hdr *h) {
    h->abi_major = IV_ABI_VERSION_MAJOR;
    h->abi_minor = IV_ABI_VERSION_MINOR;
    h->flags = 0;
    h->_pad = 0;
}

static uint8_t hex_nibble(char c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    return 0xFF;
}
static int hex_to_bytes(const char *hex, uint8_t **out, size_t *outlen) {
    size_t n = strlen(hex);
    if (n % 2) return -1;
    uint8_t *buf = malloc(n/2);
    if (!buf) return -1;
    for (size_t i=0;i<n;i+=2) {
        uint8_t hi = hex_nibble(hex[i]);
        uint8_t lo = hex_nibble(hex[i+1]);
        if (hi==0xFF || lo==0xFF) { free(buf); return -1; }
        buf[i/2] = (hi<<4)|lo;
    }
    *out = buf; *outlen = n/2;
    return 0;
}
static void dump_hex(const uint8_t *b, size_t n) {
    for (size_t i=0;i<n;i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

static int do_ping(int fd) {
    struct iv_ping req;
    init_hdr(&req.hdr);
    req.cookie_in = 0x123456789abcdef0ULL;
    if (ioctl(fd, IV_IOC_PING, &req) < 0) return -errno;
    printf("PING: in=%#llx out=%#llx\n",
           (unsigned long long)req.cookie_in,
           (unsigned long long)req.cookie_out);
    return 0;
}

static int do_va2pa(int fd, const char *addr_s, const char *len_s) {
    struct iv_va2pa_req req;
    init_hdr(&req.hdr);
    req.user_vaddr = strtoull(addr_s, NULL, 0);
    req.length     = strtoull(len_s,  NULL, 0);
    req.writable   = 0;
    if (ioctl(fd, IV_IOC_VA2PA, &req) < 0) return -errno;
    printf("VA2PA: va=0x%llx len=%llu -> pa=0x%llx covered=%llu\n",
           (unsigned long long)req.user_vaddr,
           (unsigned long long)req.length,
           (unsigned long long)req.out_phys_addr,
           (unsigned long long)req.out_covered);
    return 0;
}

static int do_read_phys(int fd, const char *pa_s, const char *len_s) {
    uint64_t pa = strtoull(pa_s, NULL, 0);
    size_t   ln = strtoull(len_s, NULL, 0);
    if (!ln || ln > IV_MAX_IO_BYTES) { fprintf(stderr, "invalid len\n"); return -EINVAL; }

    uint8_t *buf = malloc(ln);
    if (!buf) return -ENOMEM;

    struct iv_phys_rw req;
    init_hdr(&req.hdr);
    req.phys_addr = pa;
    req.length    = ln;
    req.user_buf  = (uintptr_t)buf;
    req.write     = 0;

    int rc = ioctl(fd, IV_IOC_READ_PHYS, &req);
    if (rc < 0) { rc = -errno; goto out; }

    dump_hex(buf, ln);
    rc = 0;
out:
    free(buf);
    return rc;
}

static int do_write_phys(int fd, const char *pa_s, const char *hexdata) {
    uint64_t pa = strtoull(pa_s, NULL, 0);
    uint8_t *data = NULL; size_t n = 0;
    if (hex_to_bytes(hexdata, &data, &n) < 0) { fprintf(stderr, "bad hex\n"); return -EINVAL; }
    if (!n || n > IV_MAX_IO_BYTES) { free(data); return -EINVAL; }

    struct iv_phys_rw req;
    init_hdr(&req.hdr);
    req.phys_addr = pa;
    req.length    = n;
    req.user_buf  = (uintptr_t)data;
    req.write     = 1;

    int rc = ioctl(fd, IV_IOC_WRITE_PHYS, &req);
    if (rc < 0) rc = -errno; else printf("WROTE: %zu bytes\n", n);
    free(data);
    return rc;
}

static int do_set_key(int fd, const char *hexkey) {
    uint8_t *key=NULL; size_t n=0;
    if (hex_to_bytes(hexkey, &key, &n) < 0) { fprintf(stderr, "bad key hex\n"); return -EINVAL; }
    if (!(n==16 || n==32)) { free(key); fprintf(stderr,"key must be 16 or 32 bytes\n"); return -EINVAL; }

    struct iv_set_key req;
    init_hdr(&req.hdr);
    req.algo = (n==16)? IV_CRYPTO_AES_GCM_128 : IV_CRYPTO_AES_GCM_256;
    req.key_bytes = n;
    memset(req.key, 0, sizeof(req.key));
    memcpy(req.key, key, n);

    int rc = ioctl(fd, IV_IOC_SET_KEY, &req);
    free(key);
    if (rc < 0) return -errno;
    puts("Key set.");
    return 0;
}

static int do_clear_key(int fd) {
    struct iv_clear_key req;
    init_hdr(&req.hdr);
    req.algo = 0;
    if (ioctl(fd, IV_IOC_CLEAR_KEY, &req) < 0) return -errno;
    puts("Key cleared.");
    return 0;
}

static int do_encrypt(int fd, const char *nonce_hex, const char *pt_hex, const char *aad_hex_opt) {
    uint8_t *nonce=NULL, *pt=NULL, *aad=NULL; size_t nnonce=0,npt=0,naad=0;
    if (hex_to_bytes(nonce_hex, &nonce, &nnonce) < 0) { fprintf(stderr,"bad nonce\n"); return -EINVAL; }
    if (hex_to_bytes(pt_hex, &pt, &npt) < 0) { free(nonce); fprintf(stderr,"bad plaintext\n"); return -EINVAL; }
    if (aad_hex_opt && *aad_hex_opt) {
        if (hex_to_bytes(aad_hex_opt, &aad, &naad) < 0) { free(nonce); free(pt); fprintf(stderr,"bad aad\n"); return -EINVAL; }
    }

    uint8_t *out = malloc(npt);
    if (!out) { free(nonce); free(pt); free(aad); return -ENOMEM; }

    struct iv_crypto_req req;
    init_hdr(&req.hdr);
    req.algo      = IV_CRYPTO_AES_GCM_128; /* inferred from key length in kernel; value must be valid */
    req.encrypt   = 1;
    req.user_in   = (uintptr_t)pt;
    req.user_out  = (uintptr_t)out;
    req.aad       = aad ? (uintptr_t)aad : 0;
    req.in_len    = npt;
    req.aad_len   = naad;
    memset(req.nonce, 0, sizeof(req.nonce));
    memcpy(req.nonce, nonce, nnonce > sizeof(req.nonce) ? sizeof(req.nonce) : nnonce);
    req.nonce_len = nnonce;
    req.tag_len   = IV_AES_GCM_TAG_BYTES;

    int rc = ioctl(fd, IV_IOC_ENCRYPT, &req);
    if (rc < 0) { rc = -errno; goto out; }

    printf("CT: ");  dump_hex(out, npt);
    printf("TAG: "); dump_hex(req.tag, req.tag_len);
    rc = 0;
out:
    free(out); free(nonce); free(pt); free(aad);
    return rc;
}

static int do_decrypt(int fd, const char *nonce_hex, const char *ct_hex, const char *tag_hex, const char *aad_hex_opt) {
    uint8_t *nonce=NULL, *ct=NULL, *tag=NULL, *aad=NULL; size_t nnonce=0,nct=0,ntag=0,naad=0;
    if (hex_to_bytes(nonce_hex, &nonce, &nnonce) < 0) { fprintf(stderr,"bad nonce\n"); return -EINVAL; }
    if (hex_to_bytes(ct_hex, &ct, &nct) < 0) { free(nonce); fprintf(stderr,"bad ciphertext\n"); return -EINVAL; }
    if (hex_to_bytes(tag_hex, &tag, &ntag) < 0) { free(nonce); free(ct); fprintf(stderr,"bad tag\n"); return -EINVAL; }
    if (aad_hex_opt && *aad_hex_opt) {
        if (hex_to_bytes(aad_hex_opt, &aad, &naad) < 0) { free(nonce); free(ct); free(tag); fprintf(stderr,"bad aad\n"); return -EINVAL; }
    }
    uint8_t *out = malloc(nct);
    if (!out) { free(nonce); free(ct); free(tag); free(aad); return -ENOMEM; }

    struct iv_crypto_req req;
    init_hdr(&req.hdr);
    req.algo      = IV_CRYPTO_AES_GCM_128;
    req.encrypt   = 0;
    req.user_in   = (uintptr_t)ct;
    req.user_out  = (uintptr_t)out;
    req.aad       = aad ? (uintptr_t)aad : 0;
    req.in_len    = nct;
    req.aad_len   = naad;
    memset(req.nonce, 0, sizeof(req.nonce));
    memcpy(req.nonce, nonce, nnonce > sizeof(req.nonce) ? sizeof(req.nonce) : nnonce);
    req.nonce_len = nnonce;
    req.tag_len   = ntag;
    memset(req.tag, 0, sizeof(req.tag));
    memcpy(req.tag, tag, ntag > sizeof(req.tag) ? sizeof(req.tag) : ntag);

    int rc = ioctl(fd, IV_IOC_DECRYPT, &req);
    if (rc < 0) { rc = -errno; goto out; }

    printf("PT: "); dump_hex(out, nct);
    rc = 0;
out:
    free(out); free(nonce); free(ct); free(tag); free(aad);
    return rc;
}

static int do_stats(int fd) {
    struct iv_stats st;
    init_hdr(&st.hdr);
    if (ioctl(fd, IV_IOC_GET_STATS, &st) < 0) return -errno;
    printf("ops_ioctl=%llu ops_va2pa=%llu ops_read=%llu ops_write=%llu enc=%llu dec=%llu\n",
           (unsigned long long)st.ops_ioctl,
           (unsigned long long)st.ops_va2pa,
           (unsigned long long)st.ops_read_phys,
           (unsigned long long)st.ops_write_phys,
           (unsigned long long)st.ops_encrypt,
           (unsigned long long)st.ops_decrypt);
    printf("bytes_read=%llu bytes_write=%llu crypto_in=%llu crypto_out=%llu last_err=%llu\n",
           (unsigned long long)st.bytes_read_phys,
           (unsigned long long)st.bytes_write_phys,
           (unsigned long long)st.bytes_crypto_in,
           (unsigned long long)st.bytes_crypto_out,
           (unsigned long long)st.last_err);
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s [--dev /dev/ironveil] <cmd> [args]\n"
        " cmds:\n"
        "  ping\n"
        "  va2pa <va> <len>\n"
        "  read  <pa> <len>\n"
        "  write <pa> <hex>\n"
        "  setkey <hex16|hex32>\n"
        "  clearkey\n"
        "  enc <nonce_hex> <pt_hex> [aad_hex]\n"
        "  dec <nonce_hex> <ct_hex> <tag_hex> [aad_hex]\n"
        "  stats\n", argv0);
}

int main(int argc, char **argv)
{
    const char *dev = DEV_PATH;
    int argi = 1;

    if (argc < 2) { usage(argv[0]); return 1; }

    if (argc >= 3 && strcmp(argv[1], "--dev") == 0) {
        dev = argv[2];
        argi = 3;
    }

    if (argi >= argc) { usage(argv[0]); return 1; }

    int fd = open(dev, O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("open"); return 1; }

    int rc = 0;

    if (strcmp(argv[argi], "ping") == 0) {
        rc = do_ping(fd);
    } else if (strcmp(argv[argi], "va2pa") == 0 && argi+2 < argc) {
        rc = do_va2pa(fd, argv[argi+1], argv[argi+2]);
    } else if (strcmp(argv[argi], "read") == 0 && argi+2 < argc) {
        rc = do_read_phys(fd, argv[argi+1], argv[argi+2]);
    } else if (strcmp(argv[argi], "write") == 0 && argi+2 < argc) {
        rc = do_write_phys(fd, argv[argi+1], argv[argi+2]);
    } else if (strcmp(argv[argi], "setkey") == 0 && argi+1 < argc) {
        rc = do_set_key(fd, argv[argi+1]);
    } else if (strcmp(argv[argi], "clearkey") == 0) {
        rc = do_clear_key(fd);
    } else if (strcmp(argv[argi], "enc") == 0 && (argi+2 < argc)) {
        const char *nonce = argv[argi+1];
        const char *pt    = argv[argi+2];
        const char *aad   = (argi+3 < argc) ? argv[argi+3] : "";
        rc = do_encrypt(fd, nonce, pt, aad);
    } else if (strcmp(argv[argi], "dec") == 0 && (argi+3 < argc)) {
        const char *nonce = argv[argi+1];
        const char *ct    = argv[argi+2];
        const char *tag   = argv[argi+3];
        const char *aad   = (argi+4 < argc) ? argv[argi+4] : "";
        rc = do_decrypt(fd, nonce, ct, tag, aad);
    } else if (strcmp(argv[argi], "stats") == 0) {
        rc = do_stats(fd);
    } else {
        usage(argv[0]);
        rc = -EINVAL;
    }

    if (rc < 0) {
        errno = -rc;
        perror("kpmctl");
        rc = 1;
    }

    close(fd);
    return rc;
}
