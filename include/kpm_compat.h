/* SPDX-License-Identifier: GPL-2.0 */
/*
 * IronVeil — kpm_compat.h
 * Kernel compatibility shims for Linux 5.x / 6.x
 *
 * Scope:
 *  - Page pinning: pin_user_pages* vs get_user_pages*
 *  - memremap/memunmap helpers (prefer WB)
 *  - AEAD presence (GCM) and request helpers
 *  - ioctl function pointer signatures and compat_ioctl stub
 *  - helpers: zeroize, min/max/align, capability checks, array_size
 */

#ifndef IRONVEIL_KPM_COMPAT_H
#define IRONVEIL_KPM_COMPAT_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/ioctl.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/pagemap.h>
#include <linux/refcount.h>
#include <linux/bug.h>
#include <linux/string.h>
#include <crypto/aead.h>
#include <crypto/skcipher.h>

/* ===== Version gates ===== */
#ifndef LINUX_VERSION_CODE
# error "LINUX_VERSION_CODE not defined"
#endif

/* Convenience macros */
#ifndef KERNEL_VERSION
# define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

/* ===== Small helpers (always available) ===== */
#ifndef IV_MIN
# define IV_MIN(a,b) ((typeof(a))((a) < (b) ? (a) : (b)))
#endif

#ifndef IV_MAX
# define IV_MAX(a,b) ((typeof(a))((a) > (b) ? (a) : (b)))
#endif

#ifndef IV_ARRAY_SIZE
# define IV_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef IV_ALIGN_DOWN
# define IV_ALIGN_DOWN(x, a) ((x) & ~((typeof(x))((a) - 1)))
#endif

#ifndef IV_ALIGN_UP
# define IV_ALIGN_UP(x, a)   (IV_ALIGN_DOWN((x) + (a) - 1, (a)))
#endif

/* Explicit zeroization: prefer memzero_explicit when available */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
# define iv_zeroize(p, n) memzero_explicit((p), (n))
#else
# define iv_zeroize(p, n) memset((p), 0, (n))
#endif

/* Capability gate for raw memory ops */
static inline bool iv_has_rawio_cap(void)
{
    /* In most cases CAP_SYS_RAWIO suffices; extend with LSM hooks if needed. */
    return capable(CAP_SYS_RAWIO);
}

/* ===== memremap compatibility (prefer WB) ===== */
/* Guard against old trees missing flags; WB exists since long ago */
#ifndef MEMREMAP_WB
# define MEMREMAP_WB 0
#endif

static inline void __iomem *iv_memremap_wb(resource_size_t phys, size_t size)
{
    /* For physical RAM access, map as Write-Back when permitted */
    return memremap(phys, size, MEMREMAP_WB);
}

static inline void iv_memunmap(const void __iomem *addr)
{
    if (addr)
        memunmap((void __iomem *)addr);
}

/* ===== Page pinning: pin_user_pages vs get_user_pages =====
 *
 * pin_user_pages() appeared in 5.5, with important semantics differences.
 * We prefer PUP when available; otherwise fall back to GUP with care.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
# define IV_HAVE_PUP 1
# include <linux/gup.h>
static inline long iv_pin_user_pages(unsigned long start, unsigned long nr_pages,
                                     unsigned int gup_flags, struct page **pages,
                                     struct vm_area_struct **vmas)
{
    /* gup_flags: FOLL_WRITE when writable required */
    return pin_user_pages(start, nr_pages, gup_flags, pages, vmas);
}

static inline void iv_unpin_user_pages(struct page **pages, long npages)
{
    long i;
    for (i = 0; i < npages; i++)
        unpin_user_page(pages[i]);
}

#else /* < 5.5: fallback to get_user_pages() */
# define IV_HAVE_PUP 0
# include <linux/mm.h>
# include <linux/sched/mm.h>

#ifndef FOLL_WRITE
# define FOLL_WRITE 0x01
#endif
#ifndef FOLL_LONGTERM
# define FOLL_LONGTERM 0x0 /* not supported; ignored */
#endif

static inline long iv_pin_user_pages(unsigned long start, unsigned long nr_pages,
                                     unsigned int gup_flags, struct page **pages,
                                     struct vm_area_struct **vmas)
{
    /* WARNING: on older kernels this pins via GUP; avoid LONGTERM semantics */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
    int write = !!(gup_flags & FOLL_WRITE);
    /* current->mm assumed; pass NULL vmas if not needed */
    return get_user_pages(start, nr_pages, write ? FOLL_WRITE : 0, pages, vmas);
#else
    /* Very old API variants; not our target but keep a hard error */
# error "Kernel too old for IronVeil fallback safely"
#endif
}

static inline void iv_unpin_user_pages(struct page **pages, long npages)
{
    long i;
    for (i = 0; i < npages; i++)
        put_page(pages[i]);
}
#endif /* pin_user_pages vs get_user_pages */

/* ===== AEAD (AES-GCM) helpers =====
 * AEAD has been around for a long time; we provide thin wrappers for clarity.
 */

static inline struct crypto_aead *iv_aead_alloc(const char *alg)
{
    /* CRYPTO_ALG_ASYNC is fine; caller can choose flags=0 for sync paths */
    return crypto_alloc_aead(alg, 0, 0);
}

static inline void iv_aead_free(struct crypto_aead *tfm)
{
    if (tfm)
        crypto_free_aead(tfm);
}

static inline struct aead_request *iv_aead_req_alloc(struct crypto_aead *tfm, gfp_t gfp)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
    return aead_request_alloc(tfm, gfp);
#else
    /* Fallback path (rare) */
    return aead_request_alloc(tfm, gfp);
#endif
}

static inline void iv_aead_req_free(struct aead_request *req)
{
    if (req)
        aead_request_free(req);
}

/* ===== ioctl signatures & compat ===== */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
/* Modern kernels use .unlocked_ioctl in file_operations */
# define IV_FOP_IOCTL_MEMBER unlocked_ioctl
typedef long (*iv_ioctl_fn_t)(struct file *filp, unsigned int cmd, unsigned long arg);
#else
# error "Extremely old kernel not supported"
#endif

/* compat_ioctl presence is Kconfig-driven; offer weak stub macro */
#ifdef CONFIG_COMPAT
# define IV_HAVE_COMPAT_IOCTL 1
#else
# define IV_HAVE_COMPAT_IOCTL 0
#endif

/* ===== Randomness helper ===== */
static inline void iv_get_random(void *buf, size_t len)
{
    get_random_bytes(buf, len);
}

/* ===== Page/PA helpers ===== */
static inline phys_addr_t iv_page_to_phys(const struct page *page)
{
    return page_to_phys((struct page *)page);
}

/* Compute bytes remaining in current page from a virtual address offset */
static inline size_t iv_bytes_to_page_end(unsigned long addr)
{
    return PAGE_SIZE - (addr & (PAGE_SIZE - 1));
}

/* ===== Safe copy helpers (user copy with length check) ===== */
static inline int iv_copy_to_user_safe(void __user *dst, const void *src, size_t n)
{
    return copy_to_user(dst, src, n) ? -EFAULT : 0;
}

static inline int iv_copy_from_user_safe(void *dst, const void __user *src, size_t n)
{
    return copy_from_user(dst, src, n) ? -EFAULT : 0;
}

/* ===== Build-time guards ===== */
#ifndef BUILD_BUG_ON
# define BUILD_BUG_ON(x) do { switch (0) case 0: case (x): ; } while (0)
#endif

#endif /* IRONVEIL_KPM_COMPAT_H */
