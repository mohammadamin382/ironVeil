// SPDX-License-Identifier: GPL-2.0
/*
 * IronVeil — ctl.c
 * ioctl dispatcher: validation, ABI versioning, safe user copies, routing
 */

#include "kpm.h"

#define IV_CHECK_ABI(hdrp) \
    ((hdrp)->abi_major == IV_ABI_VERSION_MAJOR)

/* ===== local helpers ===== */

static inline int iv_copy_from_user_exact(void *dst, const void __user *src, size_t len)
{
    if (!src || !dst) return -EINVAL;
    if (copy_from_user(dst, src, len)) return -EFAULT;
    return 0;
}

static inline int iv_copy_to_user_exact(void __user *dst, const void *src, size_t len)
{
    if (!src || !dst) return -EINVAL;
    if (copy_to_user(dst, src, len)) return -EFAULT;
    return 0;
}

static inline int iv_validate_hdr(const struct iv_hdr *h)
{
    if (!h) return -EINVAL;
    if (!IV_CHECK_ABI(h)) return -EPROTO;
    if (h->flags != 0)    return -EINVAL;
    return 0;
}

/* ===== PING ===== */

static long iv_handle_ping(struct file *filp, unsigned long arg)
{
    struct iv_dev *iv = filp->private_data;
    struct iv_ping req;
    int err;

    if (!iv) return -ENODEV;

    if ((err = iv_copy_from_user_exact(&req, (void __user *)arg, sizeof(req))))
        return err;

    if ((err = iv_validate_hdr(&req.hdr)))
        return err;

    /* Echo with a tiny derivation so caller can sanity-check round trip */
    req.cookie_out = req.cookie_in ^ 0xA5A5A5A5A5A5A5A5ULL;

    if ((err = iv_copy_to_user_exact((void __user *)arg, &req, sizeof(req))))
        return err;

    return 0;
}

/* ===== VA -> PA ===== */

static long iv_handle_va2pa(struct file *filp, unsigned long arg)
{
    struct iv_dev *iv = filp->private_data;
    struct iv_va2pa_req req;
    phys_addr_t pa = 0;
    size_t covered = 0;
    int err;

    if (!iv) return -ENODEV;

    if ((err = iv_copy_from_user_exact(&req, (void __user *)arg, sizeof(req))))
        return err;

    if ((err = iv_validate_hdr(&req.hdr)))
        return err;

    if (req.length == 0 || req.length > IV_MAX_IO_BYTES)
        return -EINVAL;

    err = iv_user_va2pa_first((unsigned long)req.user_vaddr,
                              (size_t)req.length,
                              req.writable != 0,
                              &pa, &covered);
    if (err)
        return err;

    req.out_phys_addr = (iv_u64)pa;
    req.out_covered   = (iv_u64)covered;

    return iv_copy_to_user_exact((void __user *)arg, &req, sizeof(req));
}

/* ===== Physical read/write ===== */

static long iv_handle_phys_rw(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct iv_dev *iv = filp->private_data;
    struct iv_phys_rw req;
    ssize_t sret;
    int err;
    bool is_write;

    if (!iv) return -ENODEV;

    if ((err = iv_copy_from_user_exact(&req, (void __user *)arg, sizeof(req))))
        return err;

    if ((err = iv_validate_hdr(&req.hdr)))
        return err;

    is_write = (cmd == IV_IOC_WRITE_PHYS) || (req.write != 0);

    if (!iv_len_ok(req.length))
        return -EINVAL;

    /* Policy gate: ranges + caps */
    err = iv_policy_allow_phys(&iv->policy, (phys_addr_t)req.phys_addr,
                               (size_t)req.length,
                               is_write ? (IV_ACC_READ|IV_ACC_WRITE) : IV_ACC_READ);
    if (err)
        return err;

    if (!iv_user_ptr_ok((void __user *)(uintptr_t)req.user_buf))
        return -EINVAL;

    if (is_write) {
        sret = iv_phys_write((phys_addr_t)req.phys_addr,
                             (const void __user *)(uintptr_t)req.user_buf,
                             (size_t)req.length, iv);
        if (sret < 0) return (long)sret;
        iv_stats_add(&iv->stats.global.bytes_write_phys, (u64)sret, &iv->stats);
        iv_stats_inc(&iv->stats.global.ops_write_phys, &iv->stats);
    } else {
        sret = iv_phys_read((phys_addr_t)req.phys_addr,
                            (void __user *)(uintptr_t)req.user_buf,
                            (size_t)req.length, iv);
        if (sret < 0) return (long)sret;
        iv_stats_add(&iv->stats.global.bytes_read_phys, (u64)sret, &iv->stats);
        iv_stats_inc(&iv->stats.global.ops_read_phys, &iv->stats);
    }

    /* Echo back unchanged struct for symmetry */
    return iv_copy_to_user_exact((void __user *)arg, &req, sizeof(req));
}

/* ===== Crypto key & process ===== */

static long iv_handle_set_key(struct file *filp, unsigned long arg)
{
    struct iv_dev *iv = filp->private_data;
    struct iv_set_key req;
    int err;

    if (!iv) return -ENODEV;

    if ((err = iv_copy_from_user_exact(&req, (void __user *)arg, sizeof(req))))
        return err;

    if ((err = iv_validate_hdr(&req.hdr)))
        return err;

    if (req.algo != IV_CRYPTO_AES_GCM_128 && req.algo != IV_CRYPTO_AES_GCM_256)
        return -EINVAL;

    if (!(req.key_bytes == 16 || req.key_bytes == 32))
        return -EINVAL;

    err = iv_crypto_set_key(&iv->crypto, req.algo, req.key, req.key_bytes);
    if (err) return err;

    return 0;
}

static long iv_handle_clear_key(struct file *filp, unsigned long arg)
{
    struct iv_dev *iv = filp->private_data;
    struct iv_clear_key req;
    int err;

    if (!iv) return -ENODEV;

    if ((err = iv_copy_from_user_exact(&req, (void __user *)arg, sizeof(req))))
        return err;

    if ((err = iv_validate_hdr(&req.hdr)))
        return err;

    return iv_crypto_clear_key(&iv->crypto, req.algo);
}

static long iv_handle_crypto(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct iv_dev *iv = filp->private_data;
    struct iv_crypto_req req;
    int err;
    bool encrypt;

    if (!iv) return -ENODEV;

    if ((err = iv_copy_from_user_exact(&req, (void __user *)arg, sizeof(req))))
        return err;

    if ((err = iv_validate_hdr(&req.hdr)))
        return err;

    if (req.algo != IV_CRYPTO_AES_GCM_128 && req.algo != IV_CRYPTO_AES_GCM_256)
        return -EINVAL;

    if (req.nonce_len == 0 || req.tag_len == 0)
        return -EINVAL;

    if (req.in_len > IV_MAX_IO_BYTES)
        return -EINVAL;

    encrypt = (cmd == IV_IOC_ENCRYPT) || (req.encrypt != 0);

    err = iv_crypto_process(&iv->crypto, (const struct iv_crypto_req __user *)(uintptr_t)arg, encrypt);
    if (err) return err;

    /* Note: iv_crypto_process انجام copy_to_user لازم برای tag/output را خودش می‌کند */
    if (encrypt)
        iv_stats_inc(&iv->stats.global.ops_encrypt, &iv->stats);
    else
        iv_stats_inc(&iv->stats.global.ops_decrypt, &iv->stats);

    iv_stats_add(&iv->stats.global.bytes_crypto_in,  req.in_len, &iv->stats);
    iv_stats_add(&iv->stats.global.bytes_crypto_out, req.in_len, &iv->stats); /* same length for GCM */

    return 0;
}

/* ===== Stats export ===== */

static long iv_handle_get_stats(struct file *filp, unsigned long arg)
{
    struct iv_dev *iv = filp->private_data;
    struct iv_stats req; /* used as output container */
    int err;

    if (!iv) return -ENODEV;

    /* Fill header for user convenience */
    req.hdr.abi_major = IV_ABI_VERSION_MAJOR;
    req.hdr.abi_minor = IV_ABI_VERSION_MINOR;
    req.hdr.flags = 0; req.hdr._pad = 0;

    err = iv_stats_export(&iv->stats, (struct iv_stats __user *)(uintptr_t)arg);
    return err;
}

/* ===== Dispatcher ===== */

long iv_ioctl_dispatch(struct file *filp, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case IV_IOC_PING:
        return iv_handle_ping(filp, arg);

    case IV_IOC_VA2PA:
        return iv_handle_va2pa(filp, arg);

    case IV_IOC_READ_PHYS:
    case IV_IOC_WRITE_PHYS:
        return iv_handle_phys_rw(filp, cmd, arg);

    case IV_IOC_SET_KEY:
        return iv_handle_set_key(filp, arg);

    case IV_IOC_CLEAR_KEY:
        return iv_handle_clear_key(filp, arg);

    case IV_IOC_ENCRYPT:
    case IV_IOC_DECRYPT:
        return iv_handle_crypto(filp, cmd, arg);

    case IV_IOC_GET_STATS:
        return iv_handle_get_stats(filp, arg);

    default:
        return -ENOTTY; /* unknown ioctl */
    }
}
