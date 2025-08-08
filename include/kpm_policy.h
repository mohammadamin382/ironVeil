/* SPDX-License-Identifier: GPL-2.0 */
/*
 * IronVeil — kpm_policy.h
 * Access policy for physical memory operations
 *
 * Default policy: allow only System RAM (no MMIO), and require CAP_SYS_RAWIO.
 * Range allowlists/overrides can be added later if needed.
 */

#ifndef IRONVEIL_KPM_POLICY_H
#define IRONVEIL_KPM_POLICY_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/page-flags.h>
#include <linux/mmzone.h>

#include "kpm_compat.h"
#include "kpm_abi.h"

/* Forward decl */
struct iv_policy;

/* Initialize/finalize policy */
int  iv_policy_init(struct iv_policy *plcy);
void iv_policy_fini(struct iv_policy *plcy);

/*
 * Validate that [start .. start+len) physical range is allowed for the given
 * access (IV_ACC_READ/IV_ACC_WRITE). Returns 0 if allowed, -EPERM / -EACCES
 * / -EINVAL otherwise.
 *
 * Default behavior:
 *  - Caller must have CAP_SYS_RAWIO (enforced here in addition to open gate).
 *  - Every page in range must be a valid RAM page: pfn_valid && !PageReserved.
 *  - Length > 0 and reasonable (checked earlier typically).
 */
int  iv_policy_allow_phys(const struct iv_policy *plcy, phys_addr_t start,
                          size_t len, u32 rw_flags);

#endif /* IRONVEIL_KPM_POLICY_H */
