// SPDX-License-Identifier: GPL-2.0
/*
 * IronVeil — phys.c
 * Safe physical memory I/O via memremap()/memunmap() and bounce buffer
 */

#include "../include/kpm.h"

#define IV_WINDOW_MAX   (1UL << 20)  /* map up to 1 MiB per window */
#define IV_BOUNCE_MAX   (64UL << 10) /* 64 KiB per copy chunk to/from user */

static inline size_t iv_phys_chunk_len(phys_addr_t pa, size_t remaining)
{
    /* Limit per window so that we don't map gigantic ranges at once. */
    size_t to_window = IV_MIN((size_t)IV_WINDOW_MAX, remaining);

    /* Also avoid crossing huge gaps unnecessarily; align to page boundary. */
    size_t page_left = (size_t)(PAGE_SIZE - (pa & (PAGE_SIZE - 1)));
    size_t first = IV_MIN(page_left, to_window);
    return first;
}

/* Copy from mapped __iomem to a kernel buffer */
static inline void iv_from_iomem(void *dst, const void __iomem *src, size_t n)
{
    memcpy_fromio(dst, src, n);
}

/* Copy from kernel buffer to mapped __iomem */
static inline void iv_to_iomem(void __iomem *dst, const void *src, size_t n)
{
    memcpy_toio(dst, src, n);
}

/*
 * iv_phys_read:
 *   Read 'len' bytes starting at physical address 'pa' into user buffer 'dst'.
 *   Returns number of bytes read (>=0) or -errno.
 */
ssize_t iv_phys_read(phys_addr_t pa, void __user *dst, size_t len, struct iv_dev *iv)
{
    ssize_t done = 0;
    void *bounce = NULL;
    size_t bounce_sz;
    int err = 0;

    if (!dst || !iv) return -EINVAL;
    if (!iv_len_ok(len)) return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
    if (!access_ok(dst, len)) return -EFAULT;
#endif

    /* Allocate a bounce buffer once; reuse per chunk */
    bounce_sz = IV_MIN((size_t)IV_BOUNCE_MAX, len);
    bounce = kmalloc(bounce_sz, GFP_KERNEL);
    if (!bounce)
        return -ENOMEM;

    while (len > 0) {
        size_t map_len = iv_phys_chunk_len(pa, len);
        void __iomem *io = iv_memremap_wb(pa, map_len);
        size_t copied = 0;

        if (!io) { err = -EIO; break; }

        /* Within this mapped window, copy out to user in smaller sub-chunks */
        while (copied < map_len) {
            size_t n = IV_MIN(bounce_sz, map_len - copied);

            /* Read from phys into bounce */
            iv_from_iomem(bounce, io + copied, n);

            /* Then copy to user */
            if (copy_to_user(dst + done, bounce, n)) {
                err = -EFAULT;
                break;
            }

            done += n;
            copied += n;
            len   -= n;
            pa    += n;
        }

        iv_memunmap(io);
        if (err) break;
    }

    iv_zeroize(bounce, bounce_sz);
    kfree(bounce);

    return err ? (done ? done : err) : done;
}

/*
 * iv_phys_write:
 *   Write 'len' bytes from user buffer 'src' to physical address 'pa'.
 *   Returns number of bytes written (>=0) or -errno.
 */
ssize_t iv_phys_write(phys_addr_t pa, const void __user *src, size_t len, struct iv_dev *iv)
{
    ssize_t done = 0;
    void *bounce = NULL;
    size_t bounce_sz;
    int err = 0;

    if (!src || !iv) return -EINVAL;
    if (!iv_len_ok(len)) return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
    if (!access_ok(src, len)) return -EFAULT;
#endif

    bounce_sz = IV_MIN((size_t)IV_BOUNCE_MAX, len);
    bounce = kmalloc(bounce_sz, GFP_KERNEL);
    if (!bounce)
        return -ENOMEM;

    while (len > 0) {
        size_t map_len = iv_phys_chunk_len(pa, len);
        void __iomem *io = iv_memremap_wb(pa, map_len);
        size_t copied = 0;

        if (!io) { err = -EIO; break; }

        while (copied < map_len) {
            size_t n = IV_MIN(bounce_sz, map_len - copied);

            /* Copy from user to bounce first */
            if (copy_from_user(bounce, src + done, n)) {
                err = -EFAULT;
                break;
            }

            /* Then write bounce to phys */
            iv_to_iomem(io + copied, bounce, n);

            done += n;
            copied += n;
            len   -= n;
            pa    += n;
        }

        iv_memunmap(io);
        if (err) break;
    }

    iv_zeroize(bounce, bounce_sz);
    kfree(bounce);

    return err ? (done ? done : err) : done;
}
