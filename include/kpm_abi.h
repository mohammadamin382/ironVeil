/* SPDX-License-Identifier: GPL-2.0 */
/*
 * IronVeil — kpm_abi.h
 * Public ABI between user-space and kernel module (ironveil.ko)
 */

#ifndef IRONVEIL_KPM_API_H
#define IRONVEIL_KPM_API_H

/* ---------- Type plumbing: kernel vs user ---------- */
#ifdef __KERNEL__
#  include <linux/types.h>
#  include <linux/ioctl.h>
   typedef __u8   iv_u8;
   typedef __u16  iv_u16;
   typedef __u32  iv_u32;
   typedef __u64  iv_u64;
#else
#  include <stdint.h>
#  include <sys/ioctl.h>
   typedef uint8_t   iv_u8;
   typedef uint16_t  iv_u16;
   typedef uint32_t  iv_u32;
   typedef uint64_t  iv_u64;
#endif

/* ---------- Constants & identities ---------- */
#define IV_DEV_NAME            "ironveil"
#define IV_CLASS_NAME          "ironveil"
#define IV_ABI_VERSION_MAJOR   1u
#define IV_ABI_VERSION_MINOR   0u

/* ioctl namespace (avoid collisions) */
#define IV_IOC_MAGIC           'K'   /* K for (K)ernel / (K)PM */

/* Hard caps to guard misuse; can be tuned at build-time if needed */
#define IV_MAX_VECTOR_ELEMS    64u          /* for scatter ops (future)   */
#define IV_MAX_IO_BYTES        (16u * 1024u * 1024u) /* 16 MiB per call  */
#define IV_MAX_PAGES_PER_REQ   (IV_MAX_IO_BYTES / 4096u)

/* Access mode flags (bitmask) for physical ranges/policy (future extensibility) */
#define IV_ACC_READ            (1u << 0)
#define IV_ACC_WRITE           (1u << 1)

/* Crypto selection */
typedef enum {
    IV_CRYPTO_NONE = 0,
    IV_CRYPTO_AES_GCM_128 = 1,
    IV_CRYPTO_AES_GCM_256 = 2,
} iv_crypto_algo_t;

/* Return/status codes (user sees -errno from kernel; these are ABI-side hints) */
typedef enum {
    IV_ST_OK              = 0,
    IV_ST_INVALID_ARG     = 1,
    IV_ST_RANGE_BLOCKED   = 2,
    IV_ST_NO_CAPABILITY   = 3,
    IV_ST_NO_KEY          = 4,
    IV_ST_CRYPTO_FAIL     = 5,
} iv_status_t;

/* Common header (versioning & future flags) for all requests */
struct iv_hdr {
    iv_u32 abi_major;   /* = IV_ABI_VERSION_MAJOR */
    iv_u32 abi_minor;   /* = IV_ABI_VERSION_MINOR */
    iv_u32 flags;       /* must be 0 for now */
    iv_u32 _pad;        /* reserved */
} __attribute__((packed));

/* -------- VA -> PA translation (user-space VA) -------- */
struct iv_va2pa_req {
    struct iv_hdr hdr;
    iv_u64 user_vaddr;     /* IN: user virtual address */
    iv_u64 length;         /* IN: bytes to cover (may span pages; capped) */
    iv_u64 out_phys_addr;  /* OUT: first physical address */
    iv_u64 out_covered;    /* OUT: bytes covered for the returned PA */
    iv_u32 writable;       /* IN: require writable pin (0/1) */
    iv_u32 _rsvd;
} __attribute__((packed));

/* -------- Physical read/write -------- */
struct iv_phys_rw {
    struct iv_hdr hdr;
    iv_u64 phys_addr;      /* IN: physical start */
    iv_u64 length;         /* IN: bytes (<= IV_MAX_IO_BYTES) */
    iv_u64 user_buf;       /* IN: user pointer to buffer */
    iv_u32 write;          /* IN: 0=read from phys->user, 1=write user->phys */
    iv_u32 _rsvd;
} __attribute__((packed));

/* -------- Crypto key management -------- */
#define IV_AES_GCM_MAX_KEYBYTES   32u   /* up to 256-bit */
#define IV_AES_GCM_NONCE_BYTES    12u   /* standard GCM nonce */
#define IV_AES_GCM_TAG_BYTES      16u

struct iv_set_key {
    struct iv_hdr hdr;
    iv_u32 algo;                   /* iv_crypto_algo_t */
    iv_u32 key_bytes;              /* 16 or 32 */
    iv_u8  key[IV_AES_GCM_MAX_KEYBYTES]; /* IN: key material */
    iv_u8  _pad[32 - IV_AES_GCM_MAX_KEYBYTES]; /* keep struct size stable */
} __attribute__((packed));

struct iv_clear_key {
    struct iv_hdr hdr;
    iv_u32 algo;       /* which slot to clear; 0 clears all */
    iv_u32 _rsvd;
} __attribute__((packed));

/* -------- Crypto operation (AES-GCM) -------- */
struct iv_crypto_req {
    struct iv_hdr hdr;
    iv_u32 algo;                   /* iv_crypto_algo_t */
    iv_u32 encrypt;                /* 0=decrypt, 1=encrypt */
    iv_u64 user_in;                /* IN: user ptr to input buffer */
    iv_u64 user_out;               /* IN: user ptr to output buffer */
    iv_u64 aad;                    /* IN: user ptr to AAD (nullable) */
    iv_u64 in_len;                 /* IN: bytes of input (no implicit pad) */
    iv_u64 aad_len;                /* IN: AAD length */
    iv_u8  nonce[IV_AES_GCM_NONCE_BYTES]; /* IN: unique per-op */
    iv_u8  tag[IV_AES_GCM_TAG_BYTES];     /* IN for decrypt, OUT for encrypt */
    iv_u16 nonce_len;              /* usually 12 */
    iv_u16 tag_len;                /* usually 16 */
    iv_u32 _rsvd;
} __attribute__((packed));

/* -------- Stats / telemetry (lightweight) -------- */
struct iv_stats {
    struct iv_hdr hdr;
    iv_u64 ops_ioctl;        /* total ioctl calls */
    iv_u64 ops_va2pa;
    iv_u64 ops_read_phys;
    iv_u64 ops_write_phys;
    iv_u64 ops_encrypt;
    iv_u64 ops_decrypt;
    iv_u64 bytes_read_phys;
    iv_u64 bytes_write_phys;
    iv_u64 bytes_crypto_in;
    iv_u64 bytes_crypto_out;
    iv_u64 last_err;         /* last -errno observed on fast-path */
} __attribute__((packed));

/* -------- Ping / sanity -------- */
struct iv_ping {
    struct iv_hdr hdr;
    iv_u64 cookie_in;   /* IN  */
    iv_u64 cookie_out;  /* OUT: kernel echoes/derives */
} __attribute__((packed));

/* ---------- IOCTL encodings ---------- */
/*
 * We keep numbers grouped:
 *   0x00-0x1F: control & ping
 *   0x20-0x3F: translation
 *   0x40-0x5F: physical IO
 *   0x60-0x7F: crypto
 *   0x80-0x9F: stats
 */
#define IV_IOC_PING         _IOWR(IV_IOC_MAGIC, 0x00, struct iv_ping)

#define IV_IOC_VA2PA        _IOWR(IV_IOC_MAGIC, 0x20, struct iv_va2pa_req)

#define IV_IOC_READ_PHYS    _IOWR(IV_IOC_MAGIC, 0x40, struct iv_phys_rw)
#define IV_IOC_WRITE_PHYS   _IOWR(IV_IOC_MAGIC, 0x41, struct iv_phys_rw)

#define IV_IOC_SET_KEY      _IOW (IV_IOC_MAGIC, 0x60, struct iv_set_key)
#define IV_IOC_CLEAR_KEY    _IOW (IV_IOC_MAGIC, 0x61, struct iv_clear_key)
#define IV_IOC_ENCRYPT      _IOWR(IV_IOC_MAGIC, 0x62, struct iv_crypto_req)
#define IV_IOC_DECRYPT      _IOWR(IV_IOC_MAGIC, 0x63, struct iv_crypto_req)

#define IV_IOC_GET_STATS    _IOWR(IV_IOC_MAGIC, 0x80, struct iv_stats)

/* ---------- ABI helpers ---------- */
#define IV_API_INIT_HDR(hdr_)                 \
    do {                                      \
        (hdr_).abi_major = IV_ABI_VERSION_MAJOR; \
        (hdr_).abi_minor = IV_ABI_VERSION_MINOR; \
        (hdr_).flags = 0u;                    \
        (hdr_)._pad  = 0u;                    \
    } while (0)

/* Optional compile-time size guards (user-space can mimic with _Static_assert) */
#ifdef __KERNEL__
#  include <linux/build_bug.h>
#  define IV_STATIC_ASSERT(c) BUILD_BUG_ON(!(c))
#else
#  if !defined(static_assert)
#    define IV_STATIC_ASSERT(c) _Static_assert((c), "IV static assert failed")
#  else
#    define IV_STATIC_ASSERT(c) static_assert((c), "IV static assert failed")
#  endif
#endif

/* Ensure packed sizes are as expected across archs */
IV_STATIC_ASSERT(sizeof(struct iv_hdr)         == 16);
IV_STATIC_ASSERT(sizeof(struct iv_ping)        == 32);
IV_STATIC_ASSERT(sizeof(struct iv_va2pa_req)   == 48);
IV_STATIC_ASSERT(sizeof(struct iv_phys_rw)     == 40);
IV_STATIC_ASSERT(sizeof(struct iv_set_key)     == 56);
IV_STATIC_ASSERT(sizeof(struct iv_clear_key)   == 24);
IV_STATIC_ASSERT(sizeof(struct iv_crypto_req)  == 96);
IV_STATIC_ASSERT(sizeof(struct iv_stats)       == 112);

#endif /* IRONVEIL_KPM_API_H */
