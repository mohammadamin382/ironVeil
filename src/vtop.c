// SPDX-License-Identifier: GPL-2.0
/*
 * IronVeil — vtop.c
 * User VA -> first PA translation (with proper pin/unpin and bounds)
 */

#include "../include/kpm.h"

int iv_user_va2pa_first(unsigned long uaddr, size_t len, bool writable,
                        phys_addr_t *out_pa, size_t *out_covered)
{
    unsigned long start;
    unsigned long offset_in_page;
    unsigned long total = len;
    unsigned long nr_pages;
    unsigned int gup_flags = 0;
    struct page **pages = NULL;
    long pinned = 0;
    phys_addr_t pa0;
    size_t covered0;
    int ret = 0;

    if (!out_pa || !out_covered)
        return -EINVAL;
    *out_pa = 0;
    *out_covered = 0;

    if (len == 0 || len > IV_MAX_IO_BYTES)
        return -EINVAL;

    /* Optional: quick user pointer check (doesn't guarantee pin success) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
    if (!access_ok((void __user *)uaddr, len))
        return -EFAULT;
#endif

    offset_in_page = uaddr & (PAGE_SIZE - 1);
    start = uaddr - offset_in_page;

    /* Pages needed to cover [uaddr, uaddr+len) */
    {
        unsigned long end = uaddr + len;
        unsigned long last = (end - 1) & PAGE_MASK;
        nr_pages = ((last - start) / PAGE_SIZE) + 1;
        if (nr_pages > IV_MAX_PAGES_PER_REQ)
            return -E2BIG;
    }

    /* Allocate page array */
    pages = kcalloc(nr_pages, sizeof(*pages), GFP_KERNEL);
    if (!pages)
        return -ENOMEM;

    /* Build flags for pin/get_user_pages */
    if (writable)
        gup_flags |= FOLL_WRITE;
    /* We avoid FOLL_LONGTERM here; callers can request a different path later */

    /* Pin pages (PUP preferred; fallback handled in kpm_compat.h) */
    pinned = iv_pin_user_pages(start, nr_pages, gup_flags, pages, NULL);
    if (pinned < 0) {
        ret = (int)pinned;
        goto out_free;
    }
    if (pinned == 0) {
        ret = -EFAULT;
        goto out_free;
    }
    if ((unsigned long)pinned < nr_pages) {
        /* Partial pin: we'll still compute first PA if page 0 is pinned,
         * but generally better to fail to avoid surprising callers.
         */
        ret = -EFAULT;
        goto out_unpin;
    }

    /* Compute first PA and how many bytes are covered on that first page */
    pa0 = iv_page_to_phys(pages[0]) + offset_in_page;
    covered0 = IV_MIN((size_t)(PAGE_SIZE - offset_in_page), total);

    *out_pa = pa0;
    *out_covered = covered0;

    ret = 0;

out_unpin:
    iv_unpin_user_pages(pages, pinned);
out_free:
    kfree(pages);
    return ret;
}
