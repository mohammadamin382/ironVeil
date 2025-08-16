// SPDX-License-Identifier: GPL-2.0
/*
 * IronVeil — netlink.c
 * Optional Generic Netlink interface (async-friendly control/events)
 */

#include "../include/kpm.h"
#include <net/genetlink.h>

#define IV_NL_FAMILY_NAME   "IRONVEIL"
#define IV_NL_MCGRP_NAME    "ironveil_mc"
#define IV_NL_VERSION       1

/* Attributes */
enum {
    IV_NLA_UNSPEC,
    IV_NLA_U64,       /* generic 64-bit value */
    IV_NLA_BYTES,     /* binary blob */
    IV_NLA_TEXT,      /* string */
    __IV_NLA_MAX,
};
#define IV_NLA_MAX (__IV_NLA_MAX - 1)

/* Commands */
enum {
    IV_NLC_UNSPEC,
    IV_NLC_PING,      /* request/response */
    IV_NLC_ECHO,      /* broadcast to mcgrp */
    __IV_NLC_MAX,
};
#define IV_NLC_MAX (__IV_NLC_MAX - 1)

/* Policy */
static const struct nla_policy iv_nl_policy[IV_NLA_MAX + 1] = {
    [IV_NLA_U64]   = { .type = NLA_U64   },
    [IV_NLA_BYTES] = { .type = NLA_BINARY, .len = 256 },
    [IV_NLA_TEXT]  = { .type = NLA_NUL_STRING, .len = 256 },
};

static struct genl_family iv_nl_family;

enum {
    IV_MCGRP_EVENTS,
    __IV_MCGRP_MAX,
};
static const struct genl_multicast_group iv_nl_mcgrps[] = {
    [IV_MCGRP_EVENTS] = { .name = IV_NL_MCGRP_NAME },
};

/* ---------- Handlers ---------- */

static int iv_nl_cmd_ping(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *msg;
    void *hdr;
    u64 in = 0, out;

    if (info->attrs[IV_NLA_U64])
        in = nla_get_u64(info->attrs[IV_NLA_U64]);
    out = in ^ 0xDEADBEEFCAFEBABEULL;

    msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

    hdr = genlmsg_put_reply(msg, info, &iv_nl_family, 0, IV_NLC_PING);
    if (!hdr) {
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    if (nla_put_u64_64bit(msg, IV_NLA_U64, out, IV_NLA_UNSPEC)) {
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    genlmsg_end(msg, hdr);
    return genlmsg_reply(msg, info);
}

static int iv_nl_cmd_echo(struct sk_buff *skb, struct genl_info *info)
{
    const char *text = NULL;
    struct sk_buff *msg;
    void *hdr;

    if (info->attrs[IV_NLA_TEXT])
        text = nla_data(info->attrs[IV_NLA_TEXT]);

    msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

    hdr = genlmsg_put(msg, 0, 0, &iv_nl_family, 0, IV_NLC_ECHO);
    if (!hdr) {
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    if (text && nla_put_string(msg, IV_NLA_TEXT, text)) {
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    genlmsg_end(msg, hdr);
    /* multicast to group 0 (events) */
    return genlmsg_multicast(&iv_nl_family, msg, 0, IV_MCGRP_EVENTS, GFP_KERNEL);
}

/* ---------- Ops table ---------- */

static const struct genl_ops iv_nl_ops[] = {
    {
        .cmd = IV_NLC_PING,
        .flags = 0,
        .policy = iv_nl_policy,
        .doit = iv_nl_cmd_ping,
    },
    {
        .cmd = IV_NLC_ECHO,
        .flags = 0,
        .policy = iv_nl_policy,
        .doit = iv_nl_cmd_echo,
    },
};

/* ---------- Family ---------- */

static struct genl_family iv_nl_family = {
    .name    = IV_NL_FAMILY_NAME,
    .version = IV_NL_VERSION,
    .maxattr = IV_NLA_MAX,
    .module  = THIS_MODULE,
    .ops     = iv_nl_ops,
    .n_ops   = ARRAY_SIZE(iv_nl_ops),
    .mcgrps  = iv_nl_mcgrps,
    .n_mcgrps= ARRAY_SIZE(iv_nl_mcgrps),
};

/* ---------- Public API ---------- */

int iv_nl_init(struct iv_dev *iv)
{
    int err = genl_register_family(&iv_nl_family);
    if (err) {
        iv_pr_err("genl_register_family failed: %d\n", err);
        return err;
    }
    iv_pr_info("netlink family '%s' registered (ver=%u)\n",
               IV_NL_FAMILY_NAME, IV_NL_VERSION);
    return 0;
}

void iv_nl_fini(struct iv_dev *iv)
{
    genl_unregister_family(&iv_nl_family);
}
