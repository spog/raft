/*
 * netlink.c - The RAFT kernel module
 * Copyright (c) 2016 Samo Pogacnik
 *
 * This file is part of the kernel part of the Linux-RAFT implementation
 *
 * This RAFT implementation is free software;
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 */

#include <net/genetlink.h>

#include "raft.h"

static const struct nla_policy raft_nl_policy[RAFT_NLA_MAX + 1] = {
	[RAFT_NLA_UNSPEC]	= { .type = NLA_UNSPEC, },
	[RAFT_NLA_CLUSTER]	= { .type = NLA_NESTED, },
	[RAFT_NLA_DOMAIN]	= { .type = NLA_NESTED, },
	[RAFT_NLA_NODE]		= { .type = NLA_NESTED, },
};

/* Properties valid for cluster */
const struct nla_policy raft_nl_cluster_policy[RAFT_NLA_CLUSTER_MAX + 1] = {
	[RAFT_NLA_CLUSTER_UNSPEC]	= { .type = NLA_UNSPEC },
	[RAFT_NLA_CLUSTER_ID]		= { .type = NLA_U32 },
};

/* Properties valid for domain */
const struct nla_policy raft_nl_domain_policy[RAFT_NLA_DOMAIN_MAX + 1] = {
	[RAFT_NLA_DOMAIN_UNSPEC]	= { .type = NLA_UNSPEC },
	[RAFT_NLA_DOMAIN_ID]		= { .type = NLA_U32 },
	[RAFT_NLA_DOMAIN_HEARTBEAT]	= { .type = NLA_U32 },
	[RAFT_NLA_DOMAIN_ELECTION]	= { .type = NLA_U32 },
	[RAFT_NLA_DOMAIN_MAXNODES]	= { .type = NLA_U32 },
};

/* Properties valid for node */
const struct nla_policy raft_nl_node_policy[RAFT_NLA_NODE_MAX + 1] = {
	[RAFT_NLA_NODE_UNSPEC]		= { .type = NLA_UNSPEC },
	[RAFT_NLA_NODE_ID]		= { .type = NLA_U32 },
	[RAFT_NLA_NODE_CONTACT]		= { .type = NLA_U32 },
	[RAFT_NLA_NODE_UP]		= { .type = NLA_FLAG }
};

struct genl_family raft_genl_family = {
	.id		= GENL_ID_GENERATE,
	.name		= RAFT_GENL_V2_NAME,
	.version	= RAFT_GENL_V2_VERSION,
	.hdrsize	= 0,
	.maxattr	= RAFT_NLA_MAX,
	.netnsok	= true,
};

int raft_nl_cluster_add(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("Netlink RAFT cluster add called!\n");
	return 0;
}

int raft_nl_cluster_del(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("Netlink RAFT cluster delete called!\n");
	return 0;
}

int raft_nl_domain_add(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("Netlink RAFT domain add called!\n");
	return 0;
}

int raft_nl_domain_del(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("Netlink RAFT domain delete called!\n");
	return 0;
}

int raft_nl_node_add(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("Netlink RAFT node add called!\n");
	return 0;
}

int raft_nl_node_del(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("Netlink RAFT node delete called!\n");
	return 0;
}

static const struct genl_ops raft_genl_v2_ops[] = {
	{
		.cmd	= RAFT_NL_CLUSTER_ADD,
		.doit	= raft_nl_cluster_add,
		.policy = raft_nl_policy,
	},
	{
		.cmd	= RAFT_NL_CLUSTER_DEL,
		.doit	= raft_nl_cluster_del,
		.policy = raft_nl_policy,
	},
	{
		.cmd	= RAFT_NL_DOMAIN_ADD,
		.doit	= raft_nl_domain_add,
		.policy = raft_nl_policy,
	},
	{
		.cmd	= RAFT_NL_DOMAIN_DEL,
		.doit	= raft_nl_domain_del,
		.policy = raft_nl_policy,
	},
	{
		.cmd	= RAFT_NL_NODE_ADD,
		.doit	= raft_nl_node_add,
		.policy = raft_nl_policy,
	},
	{
		.cmd	= RAFT_NL_NODE_DEL,
		.doit	= raft_nl_node_del,
		.policy = raft_nl_policy,
	},
};

int raft_nlmsg_parse(const struct nlmsghdr *nlh, struct nlattr ***attr)
{
	u32 maxattr = raft_genl_family.maxattr;

	*attr = raft_genl_family.attrbuf;
	if (!*attr)
		return -EOPNOTSUPP;

	return nlmsg_parse(nlh, GENL_HDRLEN, *attr, maxattr, raft_nl_policy);
}

int raft_netlink_start(void)
{
	int res;

	res = genl_register_family_with_ops(&raft_genl_family,
					    raft_genl_v2_ops);
	if (res) {
		pr_err("Failed to register netlink interface\n");
		return res;
	}
	return 0;
}

void raft_netlink_stop(void)
{
	genl_unregister_family(&raft_genl_family);
}

