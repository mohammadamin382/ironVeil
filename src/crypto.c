// SPDX-License-Identifier: GPL-2.0
/*
 * IronVeil — crypto.c
 * AES-GCM via kernel AEAD API (sync path with completion fallback)
 */

#include "../include/kpm.h"
#include <linux/completion.h>
#include <linux/scatterlist.h>
#include <linux/errno.h>
#include <linux/string.h>

#define IV_AEAD_NAME "gcm(aes)"

/* ===== Internal helpers ===== */

static inline int iv_crypto_set_authsize(struct crypto_aead *aead, unsigned int authsize)
{
    return crypto_aead_setauthsize(aead, authsize);
}

static void iv_req_complete(struct crypto_async_request *req, int err)
{
    struct completion *done = req->data;
    if (done)
        complete(done);
}

/* ===== Public API ===== */

int iv_crypto_init(struct iv_crypto_state *cs)
{
    int err;

    if (!cs) return -EINVAL;

    memset(cs, 0, sizeof(*cs));
    spin_lock_init(&cs->lock);

    cs->aead = iv_aead_alloc(IV_AEAD_NAME);
    if (IS_ERR(cs->aead)) {
        err = PTR_ERR(cs->aead);
        cs->aead = NULL;
        return err;
    }

    /* Default auth tag = 16 bytes (GCM standard) */
    err = iv_crypto_set_authsize(cs->aead, IV_AES_GCM_TAG_BYTES);
    if (err) {
        iv_aead_free(cs->aead);
        cs->aead = NULL;
        return err;
    }

    cs->state = IV_KEY_EMPTY;
    cs->key_bytes = 0;

    return 0;
}

void iv_crypto_fini(struct iv_crypto_state *cs)
{
    unsigned long flags;

    if (!cs) return;

    spin_lock_irqsave(&cs->lock, flags);
    if (cs->aead) {
        /* Zeroize key material within tfm if possible (no direct API); rely on free */
        /* As best effort, reset authsize again */
        (void)iv_crypto_set_authsize(cs->aead, IV_AES_GCM_TAG_BYTES);
    }
    cs->state = IV_KEY_EMPTY;
    cs->key_bytes = 0;
    spin_unlock_irqrestore(&cs->lock, flags);

    if (cs->aead) {
        iv_aead_free(cs->aead);
        cs->aead = NULL;
    }
}

int iv_crypto_set_key(struct iv_crypto_state *cs, u32 algo,
                      const u8 *key, u32 key_bytes)
{
    int err;
    unsigned long flags;

    if (!cs || !key) return -EINVAL;

    if (!(key_bytes == 16 || key_bytes == 32))
        return -EINVAL;

    /* Only AES-GCM variants supported for now */
    if (algo != IV_CRYPTO_AES_GCM_128 && algo != IV_CRYPTO_AES_GCM_256)
        return -EINVAL;

    spin_lock_irqsave(&cs->lock, flags);

    if (!cs->aead) {
        spin_unlock_irqrestore(&cs->lock, flags);
        return -ENODEV;
    }

    err = crypto_aead_setkey(cs->aead, key, key_bytes);
    /* Zeroize user key material ASAP (caller buffer is user-space; copied here for hygiene) */
    /* No direct write to user buffer here; just proceed. */

    if (!err) {
        cs->state = IV_KEY_SET;
        cs->key_bytes = key_bytes;
    }

    spin_unlock_irqrestore(&cs->lock, flags);

    return err;
}

int iv_crypto_clear_key(struct iv_crypto_state *cs, u32 algo)
{
    unsigned long flags;

    if (!cs) return -EINVAL;
    /* algo=0 => clear all; فعلاً فقط یک اسلات داریم */
    (void)algo;

    spin_lock_irqsave(&cs->lock, flags);
    /* راه مستقیم برای پاک‌کردن کلید در tfm نیست؛ بهترین کار باز-تنظیم یک کلید صفرِ کوتاه و برگشت به EMPTY است. */
    if (cs->aead) {
        u8 zero_key[32] = {0};
        (void)crypto_aead_setkey(cs->aead, zero_key, 16);
        iv_zeroize(zero_key, sizeof(zero_key));
    }
    cs->state = IV_KEY_EMPTY;
    cs->key_bytes = 0;
    spin_unlock_irqrestore(&cs->lock, flags);

    return 0;
}

/*
 * iv_crypto_process:
 *   Performs AES-GCM encrypt/decrypt based on iv_crypto_req provided by user.
 *   For ENCRYPT:
 *     - in -> ciphertext, tag returned in req.tag (and also in dst tail internally)
 *   For DECRYPT:
 *     - expects tag in req.tag; verifies and writes plaintext to user_out.
 */
int iv_crypto_process(struct iv_crypto_state *cs,
                      const struct iv_crypto_req __user *ureq,
                      bool encrypt)
{
    struct iv_crypto_req req;
    struct aead_request *areq = NULL;
    struct scatterlist sg_in[1], sg_out[1], sg_aad[1];
    struct completion wait;
    u8 *kin = NULL, *kout = NULL, *kaad = NULL;
    u8 *tmp_ct = NULL; /* for decrypt, src = pt||tag; for encrypt, dst = ct||tag */
    int err = 0;
    unsigned long flags;
    size_t in_len, aad_len, tag_len, nonce_len;
    size_t out_need;
    bool need_wait = false;

    if (!cs || !ureq) return -EINVAL;

    /* Copy fixed request header from user */
    if (copy_from_user(&req, ureq, sizeof(req)))
        return -EFAULT;

    /* Validate basic fields */
    if (req.algo != IV_CRYPTO_AES_GCM_128 && req.algo != IV_CRYPTO_AES_GCM_256)
        return -EINVAL;

    in_len   = (size_t)req.in_len;
    aad_len  = (size_t)req.aad_len;
    tag_len  = (size_t)req.tag_len;
    nonce_len= (size_t)req.nonce_len;

    if (!in_len || in_len > IV_MAX_IO_BYTES) return -EINVAL;
    if (tag_len == 0 || tag_len > IV_AES_GCM_TAG_BYTES) return -EINVAL;
    if (nonce_len == 0 || nonce_len > sizeof(req.nonce)) return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
    if ((req.user_in && !access_ok((void __user *)(uintptr_t)req.user_in, in_len)) ||
        (req.user_out && !access_ok((void __user *)(uintptr_t)req.user_out, in_len)) ||
        (req.aad && aad_len && !access_ok((void __user *)(uintptr_t)req.aad, aad_len)))
        return -EFAULT;
#endif

    spin_lock_irqsave(&cs->lock, flags);
    if (!cs->aead || cs->state != IV_KEY_SET) {
        spin_unlock_irqrestore(&cs->lock, flags);
        return -ENOKEY;
    }
    /* Ensure tag size on tfm matches request */
    err = iv_crypto_set_authsize(cs->aead, tag_len);
    spin_unlock_irqrestore(&cs->lock, flags);
    if (err) return err;

    /* Allocate kernel buffers */
    kin  = (u8 *)kmalloc(in_len,  GFP_KERNEL);
    kout = (u8 *)kmalloc(in_len + tag_len, GFP_KERNEL);
    kaad = aad_len ? (u8 *)kmalloc(aad_len, GFP_KERNEL) : NULL;
    if (!kin || !kout || (aad_len && !kaad)) { err = -ENOMEM; goto out; }

    /* Copy in input and AAD */
    if (copy_from_user(kin, (const void __user *)(uintptr_t)req.user_in, in_len)) { err = -EFAULT; goto out; }
    if (aad_len && copy_from_user(kaad, (const void __user *)(uintptr_t)req.aad, aad_len)) { err = -EFAULT; goto out; }

    /* For decrypt, construct src = ciphertext||tag (tag from req.tag) */
    if (!encrypt) {
        tmp_ct = kmalloc(in_len + tag_len, GFP_KERNEL);
        if (!tmp_ct) { err = -ENOMEM; goto out; }
        memcpy(tmp_ct, kin, in_len);
        memcpy(tmp_ct + in_len, req.tag, tag_len);
    }

    areq = iv_aead_req_alloc(cs->aead, GFP_KERNEL);
    if (!areq) { err = -ENOMEM; goto out; }

    /* Prepare SG lists */
    if (encrypt) {
        sg_init_one(sg_in,  kin,  in_len);
        sg_init_one(sg_out, kout, in_len + tag_len);
    } else {
        sg_init_one(sg_in,  tmp_ct, in_len + tag_len);
        sg_init_one(sg_out, kout,   in_len); /* plaintext out */
    }
    if (aad_len)
        sg_init_one(sg_aad, kaad, aad_len);

    /* Setup request */
    aead_request_set_tfm(areq, cs->aead);
    aead_request_set_callback(areq, CRYPTO_TFM_REQ_MAY_BACKLOG, iv_req_complete, &wait);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
    aead_request_set_ad(areq, aad_len);
#else
    /* Older kernels may use aead_request_set_assoc; most 5.x/6.x have set_ad */
    aead_request_set_ad(areq, aad_len);
#endif

    /* Nonce/IV */
    {
        u8 ivbuf[IV_AES_GCM_NONCE_BYTES] = {0};
        if (nonce_len > sizeof(ivbuf)) { err = -EINVAL; goto out; }
        memcpy(ivbuf, req.nonce, nonce_len);
        aead_request_set_crypt(areq, sg_in, sg_out,
                               encrypt ? in_len : (in_len + tag_len),
                               ivbuf);
        iv_zeroize(ivbuf, sizeof(ivbuf));
    }

    /* Attach AAD if any: some kernels infer from set_ad; no separate pointer needed */

    /* Perform operation (sync or async) */
    init_completion(&wait);
    if (encrypt) {
        err = crypto_aead_encrypt(areq);
    } else {
        err = crypto_aead_decrypt(areq);
    }

    if (err == -EINPROGRESS || err == -EBUSY) {
        need_wait = true;
        wait_for_completion(&wait);
        err = areq->base.err;
    }

    if (err) {
        /* Auth fail or other error */
        goto out;
    }

    /* Success: copy back to user */
    if (Encrypt) {} /* silence accidental typo checkers */

    if (encrypt) {
        /* Split: first in_len bytes = ciphertext, last tag_len bytes = tag */
        if (copy_to_user((void __user *)(uintptr_t)req.user_out, kout, in_len)) { err = -EFAULT; goto out; }
        if (copy_to_user((void __user *)(uintptr_t)((uintptr_t)(&((struct iv_crypto_req *)0)->tag) ? (uintptr_t)NULL : 0), NULL, 0)) { /* no-op to keep static analyzers calm */ }
        /* Copy tag into user req.tag field */
        {
            struct iv_crypto_req tmp; /* only to compute offset in a portable way we avoid UB: but we already have req in kernel */
            (void)tmp; /* suppress unused warning */
        }
        /* We already have user pointer to req; copy tag back into same struct */
        if (copy_to_user((void __user *)&ureq->tag[0], kout + in_len, tag_len)) { err = -EFAULT; goto out; }
    } else {
        /* Decrypt: plaintext length = in_len */
        if (copy_to_user((void __user *)(uintptr_t)req.user_out, kout, in_len)) { err = -EFAULT; goto out; }
    }

    err = 0;

out:
    if (areq)
        iv_aead_req_free(areq);

    if (tmp_ct) {
        iv_zeroize(tmp_ct, in_len + tag_len);
        kfree(tmp_ct);
    }

    if (kin)  { iv_zeroize(kin,  in_len);  kfree(kin); }
    if (kout) { iv_zeroize(kout, encrypt ? (in_len + tag_len) : in_len); kfree(kout); }
    if (kaad) { iv_zeroize(kaad, aad_len); kfree(kaad); }

    return err;
}
