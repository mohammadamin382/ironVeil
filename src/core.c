// SPDX-License-Identifier: GPL-2.0
/*
 * IronVeil — core.c
 * Module init/exit, miscdevice registration, file ops, global state
 */

#include "kpm.h"

static struct iv_dev g_iv;            /* single-device instance */
static struct iv_dev *g_iv_ptr = &g_iv;

struct iv_dev *iv_get_dev(void)
{
    return g_iv_ptr;
}

/* ========== File operations ========== */

static int ironveil_open(struct inode *ino, struct file *filp)
{
    struct iv_dev *iv = iv_get_dev();

    /* Gate raw memory ops behind CAP_SYS_RAWIO (and future policy hooks) */
    if (!iv_check_caller_caps())
        return -EPERM;

    filp->private_data = iv;

    /* Enforce non-seekable semantics */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
    nonseekable_open(ino, filp);
#endif
    iv_pr_dbg("open: pid=%d comm=%s\n", current->pid, current->comm);
    return 0;
}

static int ironveil_release(struct inode *ino, struct file *filp)
{
    iv_pr_dbg("release: pid=%d comm=%s\n", current->pid, current->comm);
    filp->private_data = NULL;
    return 0;
}

static long ironveil_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    long ret;
    struct iv_dev *iv = (struct iv_dev *)filp->private_data;

    if (!iv) return -ENODEV;

    /* Stats: total ioctl count (best-effort; light locking inside helpers) */
    iv_stats_inc(&iv->stats.global.ops_ioctl, &iv->stats);

    ret = iv_ioctl_dispatch(filp, cmd, arg);
    if (ret < 0)
        iv_stats_set_last_err(ret, &iv->stats);

    return ret;
}

#if IV_HAVE_COMPAT_IOCTL
static long ironveil_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    /* For now we route to same dispatcher; structures are packed/fixed-width */
    return ironveil_unlocked_ioctl(filp, cmd, arg);
}
#endif

const struct file_operations ironveil_fops = {
    .owner          = THIS_MODULE,
    .open           = ironveil_open,
    .release        = ironveil_release,
    .IV_FOP_IOCTL_MEMBER = ironveil_unlocked_ioctl,
#if IV_HAVE_COMPAT_IOCTL
    .compat_ioctl   = ironveil_compat_ioctl,
#endif
    .llseek         = no_llseek,
};

/* ========== Core init/fini (internal) ========== */

int iv_core_init(struct iv_dev *iv)
{
    int ret;

    /* Init stats */
    iv_stats_init(&iv->stats);

    /* Init crypto state */
    ret = iv_crypto_init(&iv->crypto);
    if (ret) {
        iv_pr_err("crypto init failed: %d\n", ret);
        goto err_stats;
    }

    /* Init policy (caps + range whitelist, etc.) */
    ret = iv_policy_init(&iv->policy);
    if (ret) {
        iv_pr_err("policy init failed: %d\n", ret);
        goto err_crypto;
    }

    /* Optional ring buffer (disabled until mmap.c arrives) */
    iv->ring_virt = NULL;
    iv->ring_len  = 0;
    spin_lock_init(&iv->ring_lock);

    /* Register misc device */
    iv->miscdev.minor = IV_DEV_MINOR;
    iv->miscdev.name  = IV_DEV_NAME;
    iv->miscdev.fops  = &ironveil_fops;
    iv->miscdev.mode  = 0; /* permissions controlled via caps/policy */

    ret = misc_register(&iv->miscdev);
    if (ret) {
        iv_pr_err("misc_register failed: %d\n", ret);
        goto err_policy;
    }

    iv_pr_info("initialized (ABI %u.%u)\n", IV_ABI_VERSION_MAJOR, IV_ABI_VERSION_MINOR);
    return 0;

err_policy:
    iv_policy_fini(&iv->policy);
err_crypto:
    iv_crypto_fini(&iv->crypto);
err_stats:
    iv_stats_fini(&iv->stats);
    return ret;
}

void iv_core_fini(struct iv_dev *iv)
{
    misc_deregister(&iv->miscdev);
    iv_policy_fini(&iv->policy);
    iv_crypto_fini(&iv->crypto);
    iv_stats_fini(&iv->stats);
}

/* ========== Module init/exit ========== */

static int __init ironveil_init(void)
{
    int ret;

    memset(&g_iv, 0, sizeof(g_iv));

    ret = iv_core_init(&g_iv);
    if (ret) {
        iv_pr_err("core init failed: %d\n", ret);
        return ret;
    }

    return 0;
}

static void __exit ironveil_exit(void)
{
    iv_core_fini(&g_iv);
    iv_pr_info("unloaded\n");
}

module_init(ironveil_init);
module_exit(ironveil_exit);

MODULE_DESCRIPTION(IV_DRV_DESC);
MODULE_AUTHOR(IV_AUTHOR);
MODULE_LICENSE("GPL v2");
