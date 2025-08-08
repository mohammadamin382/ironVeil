/* SPDX-License-Identifier: GPL-2.0 */
/*
 * IronVeil — kpm.h
 * Internal kernel-private header (not for user-space installation)
 */

#ifndef IRONVEIL_KPM_H
#define IRONVEIL_KPM_H

/* ===== Kernel includes ===== */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/ratelimit.h>
#include <linux/cred.h>
#include <linux/miscdevice.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <crypto/aead.h>

/* ===== Project includes (public ABI first, then compat/policy) ===== */
#include "kpm_abi.h"
#include "kpm_compat.h"
#include "kpm_policy.h"

/* ===== Module metadata ===== */
#define IV_MODNAME   "ironveil"
#define IV_DRV_DESC  "IronVeil: safe low-level memory & crypto tooling"
#define IV_AUTHOR    "You & ChatGPT (pair-programming)"
#define IV_LICENSE   "GPL v2"

/* ===== Build-time limits (internal) ===== */
#define IV_DEV_MINOR          MISC_DYNAMIC_MINOR
#define IV_RING_MAX_ORDER     4           /* up to 16 pages for optional ring */
#define IV_STATS_RL_INTERVAL  (HZ)        /* ratelimit interval for noisy logs */

/* ===== Logging helpers ===== */
#define iv_pr_info(fmt, ...)  pr_info(  IV_MODNAME ": " fmt, ##__VA_ARGS__)
#define iv_pr_warn(fmt, ...)  pr_warn(  IV_MODNAME ": " fmt, ##__VA_ARGS__)
#define iv_pr_err(fmt, ...)   pr_err(   IV_MODNAME ": " fmt, ##__VA_ARGS__)
#define iv_pr_dbg(fmt, ...)   pr_debug( IV_MODNAME ": " fmt, ##__VA_ARGS__)

#define iv_rl_err(fmt, ...)   do {                                   \
    static DEFINE_RATELIMIT_STATE(_rs, IV_STATS_RL_INTERVAL, 8);     \
    if (__ratelimit(&_rs))                                           \
        iv_pr_err(fmt, ##__VA_ARGS__);                                \
} while (0)

/* ===== Forward decls ===== */
struct iv_dev;
struct iv_policy;

/* ===== Per-CPU / global stats (lightweight) ===== */
struct iv_counters {
    u64 ops_ioctl;
    u64 ops_va2pa;
    u64 ops_read_phys;
    u64 ops_write_phys;
    u64 ops_encrypt;
    u64 ops_decrypt;
    u64 bytes_read_phys;
    u64 bytes_write_phys;
    u64 bytes_crypto_in;
    u64 bytes_crypto_out;
    u64 last_err;      /* last -errno on fast-path */
};

struct iv_stats_state {
    /* could be per-cpu later; start global + spinlock */
    struct iv_counters global;
    spinlock_t         lock;
};

/* ===== Crypto state ===== */
enum iv_key_state {
    IV_KEY_EMPTY = 0,
    IV_KEY_SET   = 1,
};

struct iv_crypto_state {
    struct crypto_aead *aead;    /* gcm(aes) */
    enum iv_key_state   state;
    u32                 key_bytes;   /* 16 or 32 */
    spinlock_t          lock;        /* protects aead/key state */
};

/* ===== Access policy (ranges, caps, etc.) ===== */
struct iv_policy {
    struct mutex  lock;
    u32           default_flags;     /* IV_ACC_READ/IV_ACC_WRITE mask */
    bool          require_cap_rawio; /* typically true */
    /* future: whitelist ranges list_head, etc. */
};

/* ===== Device state ===== */
struct iv_dev {
    struct miscdevice    miscdev;
    struct iv_stats_state stats;
    struct iv_crypto_state crypto;
    struct iv_policy     policy;

    /* Optional buffers / rings for mmap path */
    void                *ring_virt;
    size_t               ring_len;
    spinlock_t           ring_lock;

    /* Optional: netlink state holder (if you add per-instance state later) */
    /* void *nl; */
};

/* ===== Global accessor ===== */
extern struct iv_dev *iv_get_dev(void);

/* ===== Stats helpers ===== */
static inline void iv_stats_inc(u64 *ctr, struct iv_stats_state *st)
{
    unsigned long flags;
    spin_lock_irqsave(&st->lock, flags);
    (*ctr)++;
    spin_unlock_irqrestore(&st->lock, flags);
}
static inline void iv_stats_add(u64 *ctr, u64 delta, struct iv_stats_state *st)
{
    unsigned long flags;
    spin_lock_irqsave(&st->lock, flags);
    (*ctr) += delta;
    spin_unlock_irqrestore(&st->lock, flags);
}
static inline void iv_stats_set_last_err(long err, struct iv_stats_state *st)
{
    unsigned long flags;
    spin_lock_irqsave(&st->lock, flags);
    st->global.last_err = (u64)err;
    spin_unlock_irqrestore(&st->lock, flags);
}

/* ===== Capability gating ===== */
static inline bool iv_check_caller_caps(void)
{
    return iv_has_rawio_cap();
}

/* ===== Policy interface (policy.c) ===== */
int  iv_policy_init(struct iv_policy *plcy);
void iv_policy_fini(struct iv_policy *plcy);
/* Validate physical RW access; returns 0 if allowed */
int  iv_policy_allow_phys(const struct iv_policy *plcy, phys_addr_t start,
                          size_t len, u32 rw_flags);

/* ===== Core (core.c) ===== */
int  iv_core_init(struct iv_dev *iv);
void iv_core_fini(struct iv_dev *iv);

/* ===== IOCTL dispatch (ctl.c) ===== */
long iv_ioctl_dispatch(struct file *filp, unsigned int cmd, unsigned long arg);

/* ===== VA<->PA (vtop.c) ===== */
int iv_user_va2pa_first(unsigned long uaddr, size_t len, bool writable,
                        phys_addr_t *out_pa, size_t *out_covered);

/* ===== Physical IO (phys.c) ===== */
ssize_t iv_phys_read(phys_addr_t pa, void __user *dst, size_t len,
                     struct iv_dev *iv);
ssize_t iv_phys_write(phys_addr_t pa, const void __user *src, size_t len,
                      struct iv_dev *iv);

/* ===== Crypto (crypto.c) ===== */
int  iv_crypto_init(struct iv_crypto_state *cs);
void iv_crypto_fini(struct iv_crypto_state *cs);
int  iv_crypto_set_key(struct iv_crypto_state *cs, u32 algo,
                       const u8 *key, u32 key_bytes);
int  iv_crypto_clear_key(struct iv_crypto_state *cs, u32 algo);
int  iv_crypto_process(struct iv_crypto_state *cs,
                       const struct iv_crypto_req __user *ureq,
                       bool encrypt);

/* ===== Stats glue (stats.c) ===== */
void iv_stats_init(struct iv_stats_state *st);
void iv_stats_fini(struct iv_stats_state *st);
int  iv_stats_export(struct iv_stats_state *st, struct iv_stats __user *u);

/* ===== Optional mmap ring (mmap.c) ===== */
int  iv_mmap_init(struct iv_dev *iv);
void iv_mmap_fini(struct iv_dev *iv);
int  iv_mmap_file(struct file *filp, struct vm_area_struct *vma);

/* ===== Optional netlink (netlink.c) ===== */
int  iv_nl_init(struct iv_dev *iv);
void iv_nl_fini(struct iv_dev *iv);

/* ===== File operations (exposed by core.c) ===== */
extern const struct file_operations ironveil_fops;

/* ===== Misc helpers ===== */
static inline bool iv_len_ok(size_t len)
{
    return len > 0 && len <= IV_MAX_IO_BYTES;
}

static inline bool iv_user_ptr_ok(const void __user *p)
{
    return p != NULL;
}

/* ===== Debug helpers ===== */
#ifdef DEBUG
# define iv_dbg_hex(prefix, buf, len)                           \
    do {                                                        \
        size_t __i;                                             \
        pr_debug(IV_MODNAME ": %s len=%zu\n", prefix, (size_t)(len)); \
        for (__i = 0; __i < (len); __i++) {                     \
            if ((__i % 16) == 0) pr_debug(IV_MODNAME ": ");     \
            pr_cont("%02x ", ((const u8 *)(buf))[__i]);         \
            if ((__i % 16) == 15) pr_cont("\n");                \
        }                                                       \
        if ((len) % 16) pr_cont("\n");                          \
    } while (0)
#else
# define iv_dbg_hex(prefix, buf, len)  do { } while (0)
#endif

#endif /* IRONVEIL_KPM_H */
