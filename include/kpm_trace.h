/* SPDX-License-Identifier: GPL-2.0 */
/*
 * IronVeil — kpm_trace.h
 * Lightweight tracing hooks (debug-friendly, rate-limited)
 *
 * Goals:
 *  - Zero overhead when DEBUG off (compile-time noop).
 *  - Low overhead when DEBUG on (no dynamic fmt build unless enabled).
 *  - Easy upgrade path to real tracepoints if needed.
 */

#ifndef IRONVEIL_KPM_TRACE_H
#define IRONVEIL_KPM_TRACE_H

#include <linux/ratelimit.h>
#include <linux/ktime.h>
#include "kpm.h"

/* Global toggle (compile-time). */
#ifdef DEBUG
#define IV_TRACE_ENABLED 1
#else
#define IV_TRACE_ENABLED 0
#endif

/* Per-callsite ratelimit helper */
#define IV_TRACE_RL_INTERVAL (HZ) /* 1s */
#define IV_TRACE_RL_BURST    8

#if IV_TRACE_ENABLED

#define __iv_trace_rl(fmt, ...) do {                                     \
    static DEFINE_RATELIMIT_STATE(_iv_trs_, IV_TRACE_RL_INTERVAL, IV_TRACE_RL_BURST); \
    if (__ratelimit(&_iv_trs_))                                           \
        pr_debug(IV_MODNAME ": " fmt, ##__VA_ARGS__);                     \
} while (0)

/* High-level trace helpers */
static inline void iv_trace_ping(u64 cookie_in, u64 cookie_out)
{
    __iv_trace_rl("trace: PING in=%#llx out=%#llx\n",
                  (unsigned long long)cookie_in,
                  (unsigned long long)cookie_out);
}

static inline void iv_trace_va2pa(unsigned long uaddr, size_t len,
                                  phys_addr_t pa, size_t covered, int rc)
{
    __iv_trace_rl("trace: VA2PA uaddr=%p len=%zu -> pa=%pa covered=%zu rc=%d\n",
                  (void *)uaddr, len, &pa, covered, rc);
}

static inline void iv_trace_phys_rw(bool write, phys_addr_t pa, size_t len, int rc)
{
    __iv_trace_rl("trace: %s pa=%pa len=%zu rc=%d\n",
                  write ? "WRITE_PHYS" : "READ_PHYS", &pa, len, rc);
}

static inline void iv_trace_crypto(bool enc, size_t in_len, size_t aad_len,
                                   unsigned tag_len, int rc)
{
    __iv_trace_rl("trace: %s_GCM in=%zu aad=%zu tag=%u rc=%d\n",
                  enc ? "ENC" : "DEC", in_len, aad_len, tag_len, rc);
}

static inline void iv_trace_stats_export(int rc)
{
    __iv_trace_rl("trace: GET_STATS rc=%d\n", rc);
}

#else /* !IV_TRACE_ENABLED */

static inline void iv_trace_ping(u64 a, u64 b) { (void)a; (void)b; }
static inline void iv_trace_va2pa(unsigned long a, size_t b, phys_addr_t c, size_t d, int e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; }
static inline void iv_trace_phys_rw(bool a, phys_addr_t b, size_t c, int d)
{ (void)a; (void)b; (void)c; (void)d; }
static inline void iv_trace_crypto(bool a, size_t b, size_t c, unsigned d, int e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; }
static inline void iv_trace_stats_export(int a) { (void)a; }

#endif /* IV_TRACE_ENABLED */

#endif /* IRONVEIL_KPM_TRACE_H */
