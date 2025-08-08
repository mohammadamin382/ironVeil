// SPDX-License-Identifier: GPL-2.0
/*
 * IronVeil — policy.c
 * Access policy for physical memory operations
 */

#include "kpm.h"

static inline bool iv_phys_range_ok(phys_addr_t start, size_t len)
{
    /* non-zero and no wrap-around */
    if (len == 0) return false;
    if ((start + len) < start) return false;
    return true;
}

/* Consider a PFN as RAM if it's valid and not reserved */
static inline bool iv_pfn_is_system_ram(unsigned long pfn)
{
    if (!pfn_valid(pfn))
        return false;
    /* pfn_to_page is safe after pfn_valid */
    return !PageReserved(pfn_to_page(pfn));
}

int iv_policy_init(struct iv_policy *plcy)
{
    if (!plcy) return -EINVAL;

    mutex_init(&plcy->lock);
    plcy->default_flags = IV_ACC_READ | IV_ACC_WRITE;
    plcy->require_cap_rawio = true;

    return 0;
}

void iv_policy_fini(struct iv_policy *plcy)
{
    /* nothing dynamic yet */
    (void)plcy;
}

/*
 * Validate that [start, start+len) is allowed:
 *  - Caller has CAP_SYS_RAWIO (if required).
 *  - Entire range lies within System RAM (no MMIO).
 *  - rw_flags must be subset of default_flags.
 */
int iv_policy_allow_phys(const struct iv_policy *plcy, phys_addr_t start,
                         size_t len, u32 rw_flags)
{
    unsigned long first_pfn, last_pfn, pfn;

    if (!plcy) return -EINVAL;

    if (!iv_phys_range_ok(start, len))
        return -EINVAL;

    /* Basic rights mask */
    if ((rw_flags & ~plcy->default_flags) != 0)
        return -EACCES;

    /* Capability gate (in addition to open()) */
    if (plcy->require_cap_rawio && !iv_has_rawio_cap())
        return -EPERM;

    /* Check that the entire range is System RAM (page-by-page) */
    first_pfn = (unsigned long)(start >> PAGE_SHIFT);
    last_pfn  = (unsigned long)((start + len - 1) >> PAGE_SHIFT);

    for (pfn = first_pfn; pfn <= last_pfn; pfn++) {
        if (!iv_pfn_is_system_ram(pfn))
            return -EACCES;
        /* Guard against extremely large spans (shouldn't happen due to IV_MAX_IO_BYTES) */
        if (pfn - first_pfn > IV_MAX_PAGES_PER_REQ)
            return -E2BIG;
    }

    return 0;
}
