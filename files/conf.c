/*
 * conf.c - The RAFT kernel module
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/addrconf.h>
#include <net/inet_common.h>
#include <net/genetlink.h>

#include "raft.h"

static struct raft_net *rnet_static_ptr;

static int raft_config_cluster_add(struct raft_net *rnet, uint32_t cluster_id, struct raft_cluster **new)
{
	struct raft_cluster *cluster = NULL;
	struct raft_cluster *c_safe;
	int err;

	if (!new)
		return -EINVAL;

	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			return -EEXIST;

		if (cluster->cluster_id > cluster_id)
			break;

		if (list_is_last(&cluster->cluster_list, &rnet->clusters))
			break;
	}
	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	*new = kmalloc(sizeof(**new), GFP_ATOMIC);
	if (!(*new)) {
		err = -ENOMEM;
		goto err_nomem;
	}

	INIT_LIST_HEAD(&(*new)->domains);
	(*new)->cluster_id = cluster_id;
	printk("New Cluster ID %u\n", (*new)->cluster_id);

	if (cluster == &rnet->clusters) {
		printk("Beginning: New Cluster ID %u\n", (*new)->cluster_id);
		list_add(&(*new)->cluster_list, &rnet->clusters);
	} else if (cluster->cluster_id > cluster_id) {
		printk("Middle: New Cluster ID %u <= %u\n", (*new)->cluster_id, cluster->cluster_id);
		list_add_tail(&(*new)->cluster_list, &cluster->cluster_list);
	} else {
		printk("End: New Cluster ID %u\n", (*new)->cluster_id);
		list_add(&(*new)->cluster_list, &cluster->cluster_list);
	}

	return 0;

err_nomem:
	return err;
}

int raft_nl_cluster_add(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *na;
	struct sk_buff *rep;
	int rc;
	int err;
	uint32_t cluster_id;
	struct nlattr *attrs[RAFT_NLA_CLUSTER_MAX + 1];
	void *msg_head;
	struct raft_cluster *new = NULL;
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

	err = raft_config_cluster_add(rnet_static_ptr, cluster_id, &new);
	if (err)
		return err;

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

static int raft_config_cluster_del(struct raft_net *rnet, uint32_t cluster_id)
{
	struct raft_cluster *cluster = NULL;
	struct raft_cluster *c_safe;

	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if (cluster == &rnet->clusters) /*cluster not found*/
		return -EEXIST;

	if (!list_empty(&cluster->domains))
		return -EEXIST;

	list_del(&cluster->cluster_list);

	kfree(cluster);

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

	err = raft_config_cluster_del(rnet_static_ptr, cluster_id);
	if (err)
		return err;

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

static int raft_config_domain_add(struct raft_net *rnet, uint32_t cluster_id, uint32_t domain_id, struct raft_domain **new)
{
	struct raft_cluster *cluster = NULL;
	struct raft_cluster *c_safe;
	struct raft_domain *domain = NULL;
	struct raft_domain *d_safe;
	int err;

	if (!new)
		return -EINVAL;

	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if (cluster == &rnet->clusters) /*cluster not found*/
		return -EEXIST;

	printk("Domain list before search: &cluster->domains=%p\n", (void *)&cluster->domains);
	list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
		printk("Domain list in search: domain=%p\n", (void *)domain);
		if (domain->domain_id == domain_id)
			return -EEXIST;

		if (domain->domain_id > domain_id)
			break;

		if (list_is_last(&domain->domain_list, &cluster->domains))
			break;
	}
	printk("Domain list after search: domain=%p\n", (void *)domain);

	*new = kmalloc(sizeof(**new), GFP_ATOMIC);
	if (!(*new)) {
		err = -ENOMEM;
		goto err_nomem;
	}

	INIT_LIST_HEAD(&(*new)->nodes);
	(*new)->domain_id = domain_id;
	printk("New Domain ID %u\n", (*new)->domain_id);

	if (domain == &cluster->domains) {
		printk("Beginning: New Domain ID %u\n", (*new)->domain_id);
		list_add(&(*new)->domain_list, &cluster->domains);
	} else if (domain->domain_id > domain_id) {
		printk("Middle: New Domain ID %u\n", (*new)->domain_id);
		list_add_tail(&(*new)->domain_list, &domain->domain_list);
	} else {
		printk("End: New Domain ID %u\n", (*new)->domain_id);
		list_add(&(*new)->domain_list, &domain->domain_list);
	}

	return 0;

err_nomem:
	return err;
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
	struct raft_domain *new = NULL;

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

	if (!attrs[RAFT_NLA_DOMAIN_CLUSTERID])
		return -EINVAL;

	clusterid = nla_get_u32(attrs[RAFT_NLA_DOMAIN_CLUSTERID]);
	printk("Cluster ID %u\n", clusterid);

	if (!attrs[RAFT_NLA_DOMAIN_ID])
		return -EINVAL;

	domain_id = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ID]);
	printk("Domain ID %u\n", domain_id);

	err = raft_config_domain_add(rnet_static_ptr, clusterid, domain_id, &new);
	if (err)
		return err;

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
	int err;
	uint32_t node_id;
	uint32_t contact;
	uint32_t domainid;
	uint32_t clusterid;
	struct nlattr *attrs[RAFT_NLA_NODE_MAX + 1];

	pr_info("Netlink RAFT node add called!\n");

	if (info == NULL)
		goto out;

	if (!info->attrs[RAFT_NLA_NODE])
		return -EINVAL;

	err = nla_parse_nested(attrs, RAFT_NLA_NODE_MAX,
				info->attrs[RAFT_NLA_NODE],
				raft_nl_node_policy);
	if (err)
		return err;

	if (!attrs[RAFT_NLA_NODE_ID])
		return -EINVAL;

	node_id = nla_get_u32(attrs[RAFT_NLA_NODE_ID]);
	printk("Node ID %u\n", node_id);

	if (!attrs[RAFT_NLA_NODE_CONTACT])
		contact = 200;
	else
		contact = nla_get_u32(attrs[RAFT_NLA_NODE_CONTACT]);
	printk("Contact %u\n", contact);

	if (!attrs[RAFT_NLA_NODE_DOMAINID])
		return -EINVAL;

	domainid = nla_get_u32(attrs[RAFT_NLA_NODE_DOMAINID]);
	printk("Domain ID %u\n", domainid);

	if (!attrs[RAFT_NLA_NODE_CLUSTERID])
		return -EINVAL;

	clusterid = nla_get_u32(attrs[RAFT_NLA_NODE_CLUSTERID]);
	printk("Cluster ID %u\n", clusterid);

	return 0;

out:
	printk("Error parsing attributes!\n");
	return 0;
}

int raft_nl_node_del(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t node_id;
	uint32_t contact;
	uint32_t domainid;
	uint32_t clusterid;
	struct nlattr *attrs[RAFT_NLA_NODE_MAX + 1];

	pr_info("Netlink RAFT node delete called!\n");

	if (info == NULL)
		goto out;

	if (!info->attrs[RAFT_NLA_NODE])
		return -EINVAL;

	err = nla_parse_nested(attrs, RAFT_NLA_NODE_MAX,
				info->attrs[RAFT_NLA_NODE],
				raft_nl_node_policy);
	if (err)
		return err;

	if (!attrs[RAFT_NLA_NODE_ID])
		return -EINVAL;

	node_id = nla_get_u32(attrs[RAFT_NLA_NODE_ID]);
	printk("Node ID %u\n", node_id);

	if (!attrs[RAFT_NLA_NODE_CONTACT])
		contact = 200;
	else
		contact = nla_get_u32(attrs[RAFT_NLA_NODE_CONTACT]);
	printk("Contact %u\n", contact);

	if (!attrs[RAFT_NLA_NODE_DOMAINID])
		return -EINVAL;

	domainid = nla_get_u32(attrs[RAFT_NLA_NODE_DOMAINID]);
	printk("Domain ID %u\n", domainid);

	if (!attrs[RAFT_NLA_NODE_CLUSTERID])
		return -EINVAL;

	clusterid = nla_get_u32(attrs[RAFT_NLA_NODE_CLUSTERID]);
	printk("Cluster ID %u\n", clusterid);

	return 0;

out:
	printk("Error parsing attributes!\n");
	return 0;
}

int raft_nl_node_set(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t node_id;
	uint32_t contact;
	uint32_t domainid;
	uint32_t clusterid;
	struct nlattr *attrs[RAFT_NLA_NODE_MAX + 1];

	pr_info("Netlink RAFT node set called!\n");

	if (info == NULL)
		goto out;

	if (!info->attrs[RAFT_NLA_NODE])
		return -EINVAL;

	err = nla_parse_nested(attrs, RAFT_NLA_NODE_MAX,
				info->attrs[RAFT_NLA_NODE],
				raft_nl_node_policy);
	if (err)
		return err;

	if (!attrs[RAFT_NLA_NODE_ID])
		return -EINVAL;

	node_id = nla_get_u32(attrs[RAFT_NLA_NODE_ID]);
	printk("Node ID %u\n", node_id);

	if (!attrs[RAFT_NLA_NODE_CONTACT])
		contact = 200;
	else
		contact = nla_get_u32(attrs[RAFT_NLA_NODE_CONTACT]);
	printk("Contact %u\n", contact);

	if (!attrs[RAFT_NLA_NODE_DOMAINID])
		return -EINVAL;

	domainid = nla_get_u32(attrs[RAFT_NLA_NODE_DOMAINID]);
	printk("Domain ID %u\n", domainid);

	if (!attrs[RAFT_NLA_NODE_CLUSTERID])
		return -EINVAL;

	clusterid = nla_get_u32(attrs[RAFT_NLA_NODE_CLUSTERID]);
	printk("Cluster ID %u\n", clusterid);

	return 0;

out:
	printk("Error parsing attributes!\n");
	return 0;
}

int raft_nl_node_show(struct sk_buff *skb, struct netlink_callback *cb)
{
	pr_info("Netlink RAFT node show called!\n");
	return 0;
}

#ifdef CONFIG_PROC_FS
#if 0
static struct sock *raft_get_first(struct seq_file *seq, int start)
{
	struct sock *sk;
	struct raft_iter_state *state = seq->private;
	struct net *net = seq_file_net(seq);

	for (state->bucket = start; state->bucket <= state->raft_table->mask;
	     ++state->bucket) {
		struct raft_hslot *hslot = &state->raft_table->hash[state->bucket];

		if (hlist_empty(&hslot->head))
			continue;

		spin_lock_bh(&hslot->lock);
		sk_for_each(sk, &hslot->head) {
			if (!net_eq(sock_net(sk), net))
				continue;
			if (sk->sk_family == state->family)
				goto found;
		}
		spin_unlock_bh(&hslot->lock);
	}
	sk = NULL;
found:
	return sk;
}

static struct sock *raft_get_next(struct seq_file *seq, struct sock *sk)
{
	struct raft_iter_state *state = seq->private;
	struct net *net = seq_file_net(seq);

	do {
		sk = sk_next(sk);
	} while (sk && (!net_eq(sock_net(sk), net) || sk->sk_family != state->family));

	if (!sk) {
		if (state->bucket <= state->raft_table->mask)
			spin_unlock_bh(&state->raft_table->hash[state->bucket].lock);
		return raft_get_first(seq, state->bucket + 1);
	}
	return sk;
}

static struct sock *raft_get_idx(struct seq_file *seq, loff_t pos)
{
	struct sock *sk = raft_get_first(seq, 0);

	if (sk)
		while (pos && (sk = raft_get_next(seq, sk)) != NULL)
			--pos;
	return pos ? NULL : sk;
}

#define MAX_RAFT_PORTS 65536
static void *raft_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct raft_iter_state *state = seq->private;
	state->bucket = MAX_RAFT_PORTS;

	return *pos ? raft_get_idx(seq, *pos-1) : SEQ_START_TOKEN;
}

static void *raft_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sock *sk;

	if (v == SEQ_START_TOKEN)
		sk = raft_get_idx(seq, 0);
	else
		sk = raft_get_next(seq, v);

	++*pos;
	return sk;
}

static void raft_seq_stop(struct seq_file *seq, void *v)
{
	struct raft_iter_state *state = seq->private;

	if (state->bucket <= state->raft_table->mask)
		spin_unlock_bh(&state->raft_table->hash[state->bucket].lock);
}

int raft_seq_open(struct inode *inode, struct file *file)
{
	struct raft_seq_afinfo *afinfo = PDE_DATA(inode);
	struct raft_iter_state *s;
	int err;

	err = seq_open_net(inode, file, &afinfo->seq_ops,
			   sizeof(struct raft_iter_state));
	if (err < 0)
		return err;

	s = ((struct seq_file *)file->private_data)->private;
	s->family = afinfo->family;
	s->raft_table = afinfo->raft_table;
	return err;
}
//EXPORT_SYMBOL(raft_seq_open);

/* ------------------------------------------------------------------------ */
static void *raft_config_seq_start(struct seq_file *seq, loff_t *pos)
{
#if 0
	if (*pos < 0)
		*pos = 0;

	return (void *)pos;
#else
	return NULL;
#endif
}

static void raft_config_seq_stop(struct seq_file *seq, void *v)
{
}


static void *raft_config_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
#if 0
	return pos;
#else
	return NULL;
#endif
}
#endif

/* Display raft configuration (/proc/net/raft/config). */
static int raft_config_seq_show(struct seq_file *seq, void *v)
{
	struct raft_net *rnet = seq->private;
	struct raft_cluster *cluster;
	struct raft_cluster *c_safe;

	seq_printf(seq, "raft_config_seq_show: rnet = %p\n", rnet);

	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		struct raft_domain *domain;
		struct raft_domain *d_safe;

		seq_printf(seq, "Cluster: ID %u\n", cluster->cluster_id);
		list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
			struct raft_node *node;
			struct raft_node *n_safe;

			seq_printf(seq, "\tDomain: ID %u\n", domain->domain_id);
			seq_printf(seq, "\t\tHeartBeat %u\n", domain->heartbeat);
			seq_printf(seq, "\t\tElection %u\n", domain->election);
			seq_printf(seq, "\t\tMaxNodes %u\n", domain->maxnodes);
			seq_printf(seq, "\t\tclusterid %u\n", domain->clusterid);
#if 0
			list_for_each_entry_safe(node, n_safe, &domain->nodes, node_list) {
				seq_printf(seq, "\t\tNode: ID %u\n", node->node_id);
				seq_printf(seq, "\t\t\tContect %u\n", node->contact);
				seq_printf(seq, "\t\t\tdomainid %u\n", node->domainid);
				seq_printf(seq, "\t\t\tclusterid %u\n", node->clusterid);
			}
#endif
		}
	}

	return 0;
}

#if 0
static const struct seq_operations raft_config_sops = {
	.start = raft_config_seq_start,
	.next  = raft_config_seq_next,
	.stop  = raft_config_seq_stop,
	.show  = raft_config_seq_show,
};
#endif

static int raft_config_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int ret = -EINVAL;

#if 0
	ret = seq_open_net(inode, file, &raft_config_sops,
			    sizeof(struct seq_net_private));
#else
	ret = single_open(file, raft_config_seq_show, inode);
#endif
	if (ret)
		goto err;

	seq = file->private_data;
	seq->private = rnet_static_ptr;

	return 0;
err:
	return ret;
}

static const struct file_operations raft_config_seq_fops = {
	.open = raft_config_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_net,
};

/* Cleanup the proc fs entry for 'remaddr' object. */
void raft_config_proc_exit(struct net *net)
{
	remove_proc_entry("config", raft_net(net)->proc_net_raft);
}

int __net_init raft_config_proc_init(struct net *net)
{
	struct proc_dir_entry *p;

	p = proc_create("config", S_IRUGO, raft_net(net)->proc_net_raft,
			&raft_config_seq_fops);
	if (!p)
		return -ENOMEM;
	return 0;
}
//EXPORT_SYMBOL(raft_config_proc_init);

#if 0
void raft_proc_unregister(struct net *net, struct raft_seq_afinfo *afinfo)
{
	remove_proc_entry(afinfo->name, net->proc_net);
}
//EXPORT_SYMBOL(raft_proc_unregister);
#endif

/* ------------------------------------------------------------------------ */
static void raft_format_sock(struct sock *sp, struct seq_file *f,
		int bucket)
{
	struct inet_sock *inet = inet_sk(sp);
	__be32 dest = inet->inet_daddr;
	__be32 src  = inet->inet_rcv_saddr;
	__u16 destp	  = ntohs(inet->inet_dport);
	__u16 srcp	  = ntohs(inet->inet_sport);

	seq_printf(f, "%5d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d %pK %d",
		bucket, src, srcp, dest, destp, sp->sk_state,
		sk_wmem_alloc_get(sp),
		sk_rmem_alloc_get(sp),
		0, 0L, 0,
		from_kuid_munged(seq_user_ns(f), sock_i_uid(sp)),
		0, sock_i_ino(sp),
		atomic_read(&sp->sk_refcnt), sp,
		atomic_read(&sp->sk_drops));
}

int raft_seq_show(struct seq_file *seq, void *v)
{
	seq_setwidth(seq, 127);
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode ref pointer drops");
	else {
		struct raft_iter_state *state = seq->private;

		raft_format_sock(v, seq, state->bucket);
	}
	seq_pad(seq, '\n');
	return 0;
}

static struct raft_table raft_table __read_mostly;

static const struct file_operations raft_afinfo_seq_fops = {
	.owner    = THIS_MODULE,
	.open     = raft_seq_open,
	.read     = seq_read,
	.llseek   = seq_lseek,
	.release  = seq_release_net
};

/* ------------------------------------------------------------------------ */
static struct raft_seq_afinfo raft_seq_afinfo = {
	.name		= "raft",
	.family		= AF_INET,
	.raft_table	= &raft_table,
	.seq_fops	= &raft_afinfo_seq_fops,
	.seq_ops	= {
		.show		= raft_seq_show,
	},
};

static int __net_init raft_proc_init_net(struct net *net)
{
	struct raft_net *rnet = raft_net(net);

	if (!rnet)
		goto error;

	rnet_static_ptr = rnet;
	printk("raft_proc_init_net: rnet_static_ptr = %p\n", (void *)rnet_static_ptr);
	rnet->proc_net_raft = proc_net_mkdir(net, "raft", net->proc_net);
	if (!rnet->proc_net_raft)
		goto out_proc_net_raft;

	if (raft_config_proc_init(net))
		goto out_config_proc_init;

	return 0;

out_config_proc_init:
	remove_proc_entry("raft", net->proc_net);
	rnet->proc_net_raft = NULL;
out_proc_net_raft:
	return -ENOMEM;
error:
	return -EINVAL;
}

static void __net_exit raft_proc_exit_net(struct net *net)
{
	raft_config_proc_exit(net);
}

static struct pernet_operations raft_net_ops = {
	.init = raft_proc_init_net,
	.exit = raft_proc_exit_net,
};

int __init raft_proc_init(void)
{
	return register_pernet_subsys(&raft_net_ops);
}
//EXPORT_SYMBOL(raft_proc_init);

void raft_proc_exit(void)
{
	unregister_pernet_subsys(&raft_net_ops);
}
//EXPORT_SYMBOL(raft_proc_exit);
#else /* CONFIG_PROC_FS */
int __init raft_proc_init(void)
{
	return 0;
}

void raft_proc_exit(void)
{
	return;
}
#endif /* CONFIG_PROC_FS */

