// SPDX-License-Identifier: GPL-2.0
/*
 * IronVeil — stats.c
 * Counters/telemetry export for IV_IOC_GET_STATS
 */

#include "../include/kpm.h"
#include "../include/kpm_trace.h"

void iv_stats_init(struct iv_stats_state *st)
{
    if (!st) return;
    memset(&st->global, 0, sizeof(st->global));
    spin_lock_init(&st->lock);
}

void iv_stats_fini(struct iv_stats_state *st)
{
    /* nothing dynamic to free yet */
    (void)st;
}

int iv_stats_export(struct iv_stats_state *st, struct iv_stats __user *u)
{
    struct iv_stats out;
    unsigned long flags;

    if (!st || !u) return -EINVAL;

    memset(&out, 0, sizeof(out));
    out.hdr.abi_major = IV_ABI_VERSION_MAJOR;
    out.hdr.abi_minor = IV_ABI_VERSION_MINOR;

    spin_lock_irqsave(&st->lock, flags);
    out.ops_ioctl        = st->global.ops_ioctl;
    out.ops_va2pa        = st->global.ops_va2pa;
    out.ops_read_phys    = st->global.ops_read_phys;
    out.ops_write_phys   = st->global.ops_write_phys;
    out.ops_encrypt      = st->global.ops_encrypt;
    out.ops_decrypt      = st->global.ops_decrypt;
    out.bytes_read_phys  = st->global.bytes_read_phys;
    out.bytes_write_phys = st->global.bytes_write_phys;
    out.bytes_crypto_in  = st->global.bytes_crypto_in;
    out.bytes_crypto_out = st->global.bytes_crypto_out;
    out.last_err         = st->global.last_err;
    spin_unlock_irqrestore(&st->lock, flags);

    if (copy_to_user(u, &out, sizeof(out)))
        return -EFAULT;

    iv_trace_stats_export(0);
    return 0;
}
