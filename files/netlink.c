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
	[RAFT_NLA_DOMAIN_CLUSTERID]	= { .type = NLA_U32 },
};

/* Properties valid for node */
const struct nla_policy raft_nl_node_policy[RAFT_NLA_NODE_MAX + 1] = {
	[RAFT_NLA_NODE_UNSPEC]		= { .type = NLA_UNSPEC },
	[RAFT_NLA_NODE_ID]		= { .type = NLA_U32 },
	[RAFT_NLA_NODE_CONTACT]		= { .type = NLA_U32 },
	[RAFT_NLA_NODE_DOMAINID]	= { .type = NLA_U32 },
	[RAFT_NLA_NODE_CLUSTERID]	= { .type = NLA_U32 },
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
	struct nlattr *na;
	struct sk_buff *rep;
	int rc;
	int err;
	uint32_t cluster_id;
	struct nlattr *attrs[RAFT_NLA_CLUSTER_MAX + 1];
	void *msg_head;
	char * mydata;
	struct net *net = genl_info_net(info);
	
	pr_info("Netlink RAFT cluster add called!\n");

	if (info == NULL)
		goto out;

	if (!info->attrs[RAFT_NLA_CLUSTER])
		return -EINVAL;

	err = nla_parse_nested(attrs, RAFT_NLA_CLUSTER_MAX,
				info->attrs[RAFT_NLA_CLUSTER],
				raft_nl_cluster_policy);
	if (err)
		return err;

	if (!attrs[RAFT_NLA_CLUSTER_ID])
		return -EINVAL;

	cluster_id = nla_get_u32(attrs[RAFT_NLA_CLUSTER_ID]);
	printk("Cluster ID %u\n", cluster_id);

	/* send a message back*/
	/* allocate some memory, since the size is not yet known use NLMSG_GOODSIZE*/	
	rep = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (rep == NULL)
		goto out;

	/* create the message headers */
	/* arguments of genlmsg_put: 
	   struct sk_buff *, 
	   int (sending) pid, 
	   int sequence number, 
	   struct genl_family *, 
	   int flags,
	   u8 command index (why do we need this?)
	*/
	msg_head = genlmsg_put(rep, 0, info->snd_seq+1, &raft_genl_family, 0, RAFT_NL_CLUSTER_ADD);
	if (msg_head == NULL) {
		rc = -ENOMEM;
		goto out;
	}
#if 1
	/* add a RAFT_NLA_CLUSTER attribute (actual value to be sent) */
	rc = nla_put_string(rep, RAFT_NLA_CLUSTER, "hello world from kernel space");
	if (rc != 0)
		goto out;
#endif

	/* finalize the message */
	genlmsg_end(rep, msg_head);

	/* send the message back */
	rc = genlmsg_unicast(net, rep, info->snd_portid);
	if (rc != 0)
		goto out;
	return 0;

out:
	printk("Error parsing attributes!\n");
	return 0;
}

int raft_nl_cluster_del(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t cluster_id;
	struct nlattr *attrs[RAFT_NLA_CLUSTER_MAX + 1];

	pr_info("Netlink RAFT cluster delete called!\n");

	if (info == NULL)
		goto out;

	if (!info->attrs[RAFT_NLA_CLUSTER])
		return -EINVAL;

	err = nla_parse_nested(attrs, RAFT_NLA_CLUSTER_MAX,
				info->attrs[RAFT_NLA_CLUSTER],
				raft_nl_cluster_policy);
	if (err)
		return err;

	if (!attrs[RAFT_NLA_CLUSTER_ID])
		return -EINVAL;

	cluster_id = nla_get_u32(attrs[RAFT_NLA_CLUSTER_ID]);
	printk("Cluster ID %u\n", cluster_id);

	return 0;

out:
	printk("Error parsing attributes!\n");
	return 0;
}

int raft_nl_cluster_set(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t cluster_id;
	struct nlattr *attrs[RAFT_NLA_CLUSTER_MAX + 1];

	pr_info("Netlink RAFT cluster set called!\n");

	if (info == NULL)
		goto out;

	if (!info->attrs[RAFT_NLA_CLUSTER])
		return -EINVAL;

	err = nla_parse_nested(attrs, RAFT_NLA_CLUSTER_MAX,
				info->attrs[RAFT_NLA_CLUSTER],
				raft_nl_cluster_policy);
	if (err)
		return err;

	if (!attrs[RAFT_NLA_CLUSTER_ID])
		return -EINVAL;

	cluster_id = nla_get_u32(attrs[RAFT_NLA_CLUSTER_ID]);
	printk("Cluster ID %u\n", cluster_id);

	return 0;

out:
	printk("Error parsing attributes!\n");
	return 0;
}

int raft_nl_cluster_show(struct sk_buff *skb, struct netlink_callback *cb)
{
	pr_info("Netlink RAFT cluster show called!\n");
	return 0;
}

int raft_nl_domain_add(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t domain_id;
	uint32_t heartbeat;
	uint32_t election;
	uint32_t maxnodes;
	uint32_t clusterid;
	struct nlattr *attrs[RAFT_NLA_DOMAIN_MAX + 1];

	pr_info("Netlink RAFT domain add called!\n");

	if (info == NULL)
		goto out;

	if (!info->attrs[RAFT_NLA_DOMAIN])
		return -EINVAL;

	err = nla_parse_nested(attrs, RAFT_NLA_DOMAIN_MAX,
				info->attrs[RAFT_NLA_DOMAIN],
				raft_nl_domain_policy);
	if (err)
		return err;

	if (!attrs[RAFT_NLA_DOMAIN_ID])
		return -EINVAL;

	domain_id = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ID]);
	printk("Domain ID %u\n", domain_id);

	if (!attrs[RAFT_NLA_DOMAIN_HEARTBEAT])
		heartbeat = 200;
	else
		heartbeat = nla_get_u32(attrs[RAFT_NLA_DOMAIN_HEARTBEAT]);
	printk("Heartbeat %u\n", heartbeat);

	if (!attrs[RAFT_NLA_DOMAIN_ELECTION])
		election = 300;
	else
		election = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ELECTION]);
	printk("Election %u\n", election);

	if (!attrs[RAFT_NLA_DOMAIN_MAXNODES])
		maxnodes = 0;
	else
		maxnodes = nla_get_u32(attrs[RAFT_NLA_DOMAIN_MAXNODES]);
	printk("Maxnodes %u\n", maxnodes);

	if (!attrs[RAFT_NLA_DOMAIN_CLUSTERID])
		return -EINVAL;

	clusterid = nla_get_u32(attrs[RAFT_NLA_DOMAIN_CLUSTERID]);
	printk("Cluster ID %u\n", clusterid);

	return 0;

out:
	printk("Error parsing attributes!\n");
	return 0;
}

int raft_nl_domain_del(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t domain_id;
	uint32_t heartbeat;
	uint32_t election;
	uint32_t maxnodes;
	uint32_t clusterid;
	struct nlattr *attrs[RAFT_NLA_DOMAIN_MAX + 1];

	pr_info("Netlink RAFT domain delete called!\n");

	if (info == NULL)
		goto out;

	if (!info->attrs[RAFT_NLA_DOMAIN])
		return -EINVAL;

	err = nla_parse_nested(attrs, RAFT_NLA_DOMAIN_MAX,
				info->attrs[RAFT_NLA_DOMAIN],
				raft_nl_domain_policy);
	if (err)
		return err;

	if (!attrs[RAFT_NLA_DOMAIN_ID])
		return -EINVAL;

	domain_id = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ID]);
	printk("Domain ID %u\n", domain_id);

	if (!attrs[RAFT_NLA_DOMAIN_HEARTBEAT])
		heartbeat = 200;
	else
		heartbeat = nla_get_u32(attrs[RAFT_NLA_DOMAIN_HEARTBEAT]);
	printk("Heartbeat %u\n", heartbeat);

	if (!attrs[RAFT_NLA_DOMAIN_ELECTION])
		election = 300;
	else
		election = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ELECTION]);
	printk("Election %u\n", election);

	if (!attrs[RAFT_NLA_DOMAIN_MAXNODES])
		maxnodes = 0;
	else
		maxnodes = nla_get_u32(attrs[RAFT_NLA_DOMAIN_MAXNODES]);
	printk("Maxnodes %u\n", maxnodes);

	if (!attrs[RAFT_NLA_DOMAIN_CLUSTERID])
		return -EINVAL;

	clusterid = nla_get_u32(attrs[RAFT_NLA_DOMAIN_CLUSTERID]);
	printk("Cluster ID %u\n", clusterid);

	return 0;

out:
	printk("Error parsing attributes!\n");
	return 0;
}

int raft_nl_domain_set(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t domain_id;
	uint32_t heartbeat;
	uint32_t election;
	uint32_t maxnodes;
	uint32_t clusterid;
	struct nlattr *attrs[RAFT_NLA_DOMAIN_MAX + 1];

	pr_info("Netlink RAFT domain set called!\n");

	if (info == NULL)
		goto out;

	if (!info->attrs[RAFT_NLA_DOMAIN])
		return -EINVAL;

	err = nla_parse_nested(attrs, RAFT_NLA_DOMAIN_MAX,
				info->attrs[RAFT_NLA_DOMAIN],
				raft_nl_domain_policy);
	if (err)
		return err;

	if (!attrs[RAFT_NLA_DOMAIN_ID])
		return -EINVAL;

	domain_id = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ID]);
	printk("Domain ID %u\n", domain_id);

	if (!attrs[RAFT_NLA_DOMAIN_HEARTBEAT])
		heartbeat = 200;
	else
		heartbeat = nla_get_u32(attrs[RAFT_NLA_DOMAIN_HEARTBEAT]);
	printk("Heartbeat %u\n", heartbeat);

	if (!attrs[RAFT_NLA_DOMAIN_ELECTION])
		election = 300;
	else
		election = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ELECTION]);
	printk("Election %u\n", election);

	if (!attrs[RAFT_NLA_DOMAIN_MAXNODES])
		maxnodes = 0;
	else
		maxnodes = nla_get_u32(attrs[RAFT_NLA_DOMAIN_MAXNODES]);
	printk("Maxnodes %u\n", maxnodes);

	if (!attrs[RAFT_NLA_DOMAIN_CLUSTERID])
		return -EINVAL;

	clusterid = nla_get_u32(attrs[RAFT_NLA_DOMAIN_CLUSTERID]);
	printk("Cluster ID %u\n", clusterid);

	return 0;

out:
	printk("Error parsing attributes!\n");
	return 0;
}

int raft_nl_domain_show(struct sk_buff *skb, struct netlink_callback *cb)
{
	pr_info("Netlink RAFT domain show called!\n");
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

int raft_nl_node_set(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("Netlink RAFT node set called!\n");
	return 0;
}

int raft_nl_node_show(struct sk_buff *skb, struct netlink_callback *cb)
{
	pr_info("Netlink RAFT node show called!\n");
	return 0;
}

static const struct genl_ops raft_genl_v2_ops[] = {
	{
		.cmd	= RAFT_NL_CLUSTER_ADD,
		.doit	= raft_nl_cluster_add,
//		.dumpit	= raft_nl_cluster_add,
		.policy = raft_nl_policy,
	},
	{
		.cmd	= RAFT_NL_CLUSTER_DEL,
		.doit	= raft_nl_cluster_del,
		.policy = raft_nl_policy,
	},
	{
		.cmd	= RAFT_NL_CLUSTER_SET,
		.doit	= raft_nl_cluster_set,
		.policy = raft_nl_policy,
	},
	{
		.cmd	= RAFT_NL_CLUSTER_SHOW,
		.dumpit	= raft_nl_cluster_show,
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
		.cmd	= RAFT_NL_DOMAIN_SET,
		.doit	= raft_nl_domain_set,
		.policy = raft_nl_policy,
	},
	{
		.cmd	= RAFT_NL_DOMAIN_SHOW,
		.dumpit	= raft_nl_domain_show,
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
	{
		.cmd	= RAFT_NL_NODE_SET,
		.doit	= raft_nl_node_set,
		.policy = raft_nl_policy,
	},
	{
		.cmd	= RAFT_NL_NODE_SHOW,
		.dumpit	= raft_nl_node_show,
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

