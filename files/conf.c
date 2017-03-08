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

#include "raft.h"

static struct raft_net *rnet_static_ptr;

static int raft_config_cluster_add(struct raft_net *rnet, uint32_t cluster_id, struct raft_cluster **new)
{
	struct raft_cluster *cluster = NULL;
	struct raft_cluster *c_safe;
	int err;

	if (!new)
		return -EINVAL;

//	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			return -EEXIST;

		if (cluster->cluster_id > cluster_id)
			break;

		if (list_is_last(&cluster->cluster_list, &rnet->clusters))
			break;
	}
//	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	*new = kmalloc(sizeof(**new), GFP_ATOMIC);
	if (!(*new)) {
		err = -ENOMEM;
		goto err_nomem;
	}

	INIT_LIST_HEAD(&(*new)->domains);
	(*new)->cluster_id = cluster_id;
//	printk("New Cluster ID %u\n", (*new)->cluster_id);

	if ((struct list_head *)cluster == &rnet->clusters) {
//		printk("Beginning: New Cluster ID %u\n", (*new)->cluster_id);
		list_add(&(*new)->cluster_list, &rnet->clusters);
	} else if (cluster->cluster_id > cluster_id) {
//		printk("Middle: New Cluster ID %u <= %u\n", (*new)->cluster_id, cluster->cluster_id);
		list_add_tail(&(*new)->cluster_list, &cluster->cluster_list);
	} else {
//		printk("End: New Cluster ID %u\n", (*new)->cluster_id);
		list_add(&(*new)->cluster_list, &cluster->cluster_list);
	}

	return 0;

err_nomem:
	return err;
}

int raft_nl_cluster_add(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t cluster_id;
	struct nlattr *attrs[RAFT_NLA_CLUSTER_MAX + 1];
	struct raft_cluster *new = NULL;
//	struct raft_net *rnet = raft(genl_info_net(info));

//	pr_info("Netlink RAFT cluster add called!\n");

	if ((info == NULL) || (!info->attrs[RAFT_NLA_CLUSTER])) {
		err = -EINVAL;
		goto input_error;
	}

	err = nla_parse_nested(attrs, RAFT_NLA_CLUSTER_MAX,
				info->attrs[RAFT_NLA_CLUSTER],
				raft_nl_cluster_policy);
	if (err)
		goto input_error;

	if (!attrs[RAFT_NLA_CLUSTER_ID]) {
		err = -EINVAL;
		goto input_error;
	}

	cluster_id = nla_get_u32(attrs[RAFT_NLA_CLUSTER_ID]);
//	printk("Cluster ID %u\n", cluster_id);

	err = raft_config_cluster_add(rnet_static_ptr, cluster_id, &new);
	if (err) {
		printk("raft_config_cluster_add() returns %d\n", err);
		return err;
	}

	return 0;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}

static int raft_config_cluster_del(struct raft_net *rnet, uint32_t cluster_id)
{
	struct raft_cluster *cluster = NULL;
	struct raft_cluster *c_safe;

//	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
//		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
//	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
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
//	struct raft_net *rnet = raft(genl_info_net(info));

//	pr_info("Netlink RAFT cluster delete called!\n");

	if ((info == NULL) || (!info->attrs[RAFT_NLA_CLUSTER])) {
		err = -EINVAL;
		goto input_error;
	}

	err = nla_parse_nested(attrs, RAFT_NLA_CLUSTER_MAX,
				info->attrs[RAFT_NLA_CLUSTER],
				raft_nl_cluster_policy);
	if (err)
		goto input_error;

	if (!attrs[RAFT_NLA_CLUSTER_ID]) {
		err = -EINVAL;
		goto input_error;
	}

	cluster_id = nla_get_u32(attrs[RAFT_NLA_CLUSTER_ID]);
//	printk("Cluster ID %u\n", cluster_id);

	err = raft_config_cluster_del(rnet_static_ptr, cluster_id);

//	printk("raft_nl_cluster_del() returns %d\n", err);
	return err;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}

static struct raft_cluster *raft_config_cluster_get(struct raft_net *rnet, uint32_t cluster_id)
{
	struct raft_cluster *cluster = NULL;
	struct raft_cluster *c_safe;

//	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
//		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
//	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return NULL;

	return cluster;
}

static struct raft_cluster *raft_config_cluster_get_next(struct raft_net *rnet, struct raft_cluster *prev_cluster)
{
	struct raft_cluster *cluster = NULL;

	if (prev_cluster == NULL)
		cluster = list_first_entry_or_null(&rnet->clusters, struct raft_cluster, cluster_list); 
	else
		cluster = list_next_entry(prev_cluster, cluster_list);

//	printk("Cluster list INIT: &rnet->clusters=%p, next: cluster=%p\n", (void *)&rnet->clusters, (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*end of cluster_list reached*/
		return NULL;

	return cluster;
}

int raft_nl_cluster_set(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t cluster_id;
	struct nlattr *attrs[RAFT_NLA_CLUSTER_MAX + 1];
	struct raft_cluster *cluster = NULL;
//	struct raft_net *rnet = raft(genl_info_net(info));

//	pr_info("Netlink RAFT cluster set called!\n");

	if ((info == NULL) || (!info->attrs[RAFT_NLA_CLUSTER])) {
		err = -EINVAL;
		goto input_error;
	}

	err = nla_parse_nested(attrs, RAFT_NLA_CLUSTER_MAX,
				info->attrs[RAFT_NLA_CLUSTER],
				raft_nl_cluster_policy);
	if (err)
		goto input_error;

	if (!attrs[RAFT_NLA_CLUSTER_ID]) {
		err = -EINVAL;
		goto input_error;
	}

	cluster_id = nla_get_u32(attrs[RAFT_NLA_CLUSTER_ID]);
//	printk("Cluster ID %u\n", cluster_id);

	cluster = raft_config_cluster_get(rnet_static_ptr, cluster_id);
	if (!cluster)
		return -EEXIST;

	return 0;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}

int raft_nl_dump_cluster(struct raft_cluster *cluster, struct raft_nl_msg *msg)
{
	struct nlattr *attrs;
	void *hdr;

	hdr = genlmsg_put(msg->skb, msg->portid, msg->seq, &raft_genl_family,
			  NLM_F_MULTI, RAFT_NL_CLUSTER_SHOW);
	if (!hdr)
		return -EMSGSIZE;

	attrs = nla_nest_start(msg->skb, RAFT_NLA_CLUSTER);
	if (!attrs)
		goto msg_full;

	if (nla_put_u32(msg->skb, RAFT_NLA_CLUSTER_ID, cluster->cluster_id))
		goto attr_msg_full;

	nla_nest_end(msg->skb, attrs);
	genlmsg_end(msg->skb, hdr);
	return 0;

attr_msg_full:
	nla_nest_cancel(msg->skb, attrs);
msg_full:
	genlmsg_cancel(msg->skb, hdr);

	return -EMSGSIZE;
}

int raft_nl_cluster_show(struct sk_buff *skb, struct netlink_callback *cb)
{
//	struct raft_net *rnet = raft(sock_net(skb->sk));
	struct nlattr **pattrs;
	struct nlattr *attrs[RAFT_NLA_CLUSTER_MAX + 1];
	struct raft_nl_msg msg;
	struct raft_cluster *cluster = NULL;
	struct raft_cluster *prev_cluster = (struct raft_cluster *)cb->args[1];
	int done = cb->args[0];
	uint32_t cluster_id = 0;
	int err;

//	pr_info("Netlink RAFT cluster show called!\n");

	if (!prev_cluster) {
		err = raft_nlmsg_parse(cb->nlh, &pattrs);
		if (err)
			goto input_error;

		if (!pattrs[RAFT_NLA_CLUSTER]) {
			err = -EINVAL;
			goto input_error;
		}

		err = nla_parse_nested(attrs, RAFT_NLA_CLUSTER_MAX,
					pattrs[RAFT_NLA_CLUSTER],
					raft_nl_cluster_policy);
		if (err)
			goto input_error;

		if (attrs[RAFT_NLA_CLUSTER_ID]) {
			cluster_id = nla_get_u32(attrs[RAFT_NLA_CLUSTER_ID]);
		}
	}

	if (done)
		return 0;

	msg.skb = skb;
	msg.portid = NETLINK_CB(cb->skb).portid;
	msg.seq = cb->nlh->nlmsg_seq;

	rtnl_lock();

//	printk("Cluster ID %u\n", cluster_id);

	if (cluster_id != 0) {
		if ((cluster = raft_config_cluster_get(rnet_static_ptr, cluster_id)) != NULL) {
			raft_nl_dump_cluster(cluster, &msg);
		} else {
			rtnl_unlock();
			return -EEXIST;
		}
		done = 1;
	} else {
		while ((cluster = raft_config_cluster_get_next(rnet_static_ptr, prev_cluster)) != NULL) {
			err = raft_nl_dump_cluster(cluster, &msg);
			if (err) break;
			prev_cluster = cluster;
		}
		if (!err)
			done = 1;
	}
//	printk("Cluster ptr %p\n", (void *)cluster);

	rtnl_unlock();
	cb->args[0] = done;
	cb->args[1] = (long)cluster;

	return skb->len;

input_error:
	printk("Error parsing attributes!\n");
	return err;
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

//	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
//	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return -EEXIST;

//	printk("Domain list before search: &cluster->domains=%p\n", (void *)&cluster->domains);
	list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
//		printk("Domain list in search: domain=%p\n", (void *)domain);
		if (domain->domain_id == domain_id)
			return -EEXIST;

		if (domain->domain_id > domain_id)
			break;

		if (list_is_last(&domain->domain_list, &cluster->domains))
			break;
	}
//	printk("Domain list after search: domain=%p\n", (void *)domain);

	*new = kmalloc(sizeof(**new), GFP_ATOMIC);
	if (!(*new)) {
		err = -ENOMEM;
		goto err_nomem;
	}

	INIT_LIST_HEAD(&(*new)->nodes);
	(*new)->domain_id = domain_id;
	(*new)->clusterid = cluster_id;
//	printk("New Domain ID %u\n", (*new)->domain_id);

	if ((struct list_head *)domain == &cluster->domains) {
//		printk("Beginning: New Domain ID %u\n", (*new)->domain_id);
		list_add(&(*new)->domain_list, &cluster->domains);
	} else if (domain->domain_id > domain_id) {
//		printk("Middle: New Domain ID %u\n", (*new)->domain_id);
		list_add_tail(&(*new)->domain_list, &domain->domain_list);
	} else {
//		printk("End: New Domain ID %u\n", (*new)->domain_id);
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
//	struct raft_net *rnet = raft(genl_info_net(info));

//	pr_info("Netlink RAFT domain add called!\n");

	if ((info == NULL) || (!info->attrs[RAFT_NLA_DOMAIN])) {
		err = -EINVAL;
		goto input_error;
	}

	err = nla_parse_nested(attrs, RAFT_NLA_DOMAIN_MAX,
				info->attrs[RAFT_NLA_DOMAIN],
				raft_nl_domain_policy);
	if (err)
		goto input_error;

	if (!attrs[RAFT_NLA_DOMAIN_CLUSTERID]) {
		err = -EINVAL;
		goto input_error;
	}

	clusterid = nla_get_u32(attrs[RAFT_NLA_DOMAIN_CLUSTERID]);
//	printk("Cluster ID %u\n", clusterid);

	if (!attrs[RAFT_NLA_DOMAIN_ID]) {
		err = -EINVAL;
		goto input_error;
	}

	domain_id = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ID]);
//	printk("Domain ID %u\n", domain_id);

	err = raft_config_domain_add(rnet_static_ptr, clusterid, domain_id, &new);
	if (err) {
		printk("raft_config_domain_add() returns %d\n", err);
		return err;
	}

	if (!attrs[RAFT_NLA_DOMAIN_HEARTBEAT])
		heartbeat = 200;
	else
		heartbeat = nla_get_u32(attrs[RAFT_NLA_DOMAIN_HEARTBEAT]);
//	printk("Heartbeat %u\n", heartbeat);
	new->heartbeat = heartbeat;

	if (!attrs[RAFT_NLA_DOMAIN_ELECTION])
		election = 300;
	else
		election = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ELECTION]);
//	printk("Election %u\n", election);
	new->election = election;

	if (!attrs[RAFT_NLA_DOMAIN_MAXNODES])
		maxnodes = 0;
	else
		maxnodes = nla_get_u32(attrs[RAFT_NLA_DOMAIN_MAXNODES]);
//	printk("Maxnodes %u\n", maxnodes);
	new->maxnodes = maxnodes;

	return 0;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}

static int raft_config_domain_del(struct raft_net *rnet, uint32_t cluster_id, uint32_t domain_id)
{
	struct raft_cluster *cluster = NULL;
	struct raft_cluster *c_safe;
	struct raft_domain *domain = NULL;
	struct raft_domain *d_safe;

//	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
//		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
//	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return -EEXIST;

//	printk("Domain list before search: &cluster->domains=%p\n", (void *)&cluster->domains);
	list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
//		printk("Domain list in search: domain=%p\n", (void *)domain);
		if (domain->domain_id == domain_id)
			break;
	}
//	printk("Domain list after search: domain=%p\n", (void *)domain);

	if ((struct list_head *)domain == &cluster->domains) /*domain not found*/
		return -EEXIST;

	if (!list_empty(&domain->nodes))
		return -EEXIST;

	list_del(&domain->domain_list);

	kfree(domain);

	return 0;
}

int raft_nl_domain_del(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t domain_id;
	uint32_t clusterid;
	struct nlattr *attrs[RAFT_NLA_DOMAIN_MAX + 1];
//	struct raft_net *rnet = raft(genl_info_net(info));

//	pr_info("Netlink RAFT domain delete called!\n");

	if ((info == NULL) || (!info->attrs[RAFT_NLA_DOMAIN])) {
		err = -EINVAL;
		goto input_error;
	}

	err = nla_parse_nested(attrs, RAFT_NLA_DOMAIN_MAX,
				info->attrs[RAFT_NLA_DOMAIN],
				raft_nl_domain_policy);
	if (err)
		goto input_error;

	if (!attrs[RAFT_NLA_DOMAIN_ID]) {
		err = -EINVAL;
		goto input_error;
	}

	domain_id = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ID]);
//	printk("Domain ID %u\n", domain_id);

	if (!attrs[RAFT_NLA_DOMAIN_CLUSTERID]) {
		err = -EINVAL;
		goto input_error;
	}

	clusterid = nla_get_u32(attrs[RAFT_NLA_DOMAIN_CLUSTERID]);
//	printk("Cluster ID %u\n", clusterid);

	err = raft_config_domain_del(rnet_static_ptr, clusterid, domain_id);
	if (err) {
		printk("raft_nl_domain_del() returns %d\n", err);
		return err;
	}

	return 0;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}

static struct raft_domain *raft_config_domain_get(struct raft_net *rnet, uint32_t cluster_id, uint32_t domain_id)
{
	struct raft_cluster *cluster = NULL;
	struct raft_cluster *c_safe;
	struct raft_domain *domain = NULL;
	struct raft_domain *d_safe;

//	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
//		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
//	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return NULL;

//	printk("Domain list before search: &cluster->domains=%p\n", (void *)&cluster->domains);
	list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
//		printk("Domain list in search: domain=%p\n", (void *)domain);
		if (domain->domain_id == domain_id)
			break;
	}
//	printk("Domain list after search: domain=%p\n", (void *)domain);

	if ((struct list_head *)domain == &cluster->domains) /*domain not found*/
		return NULL;

	return domain;
}

static struct raft_domain *raft_config_domain_get_next(struct raft_net *rnet, uint32_t cluster_id, struct raft_domain *prev_domain)
{
	struct raft_cluster *cluster = NULL;
	struct raft_domain *domain = NULL;

	if (cluster_id == 0)
		return NULL;

	if ((cluster = raft_config_cluster_get(rnet, cluster_id)) == NULL)
		return NULL;

	if (prev_domain == NULL)
		domain = list_first_entry_or_null(&cluster->domains, struct raft_domain, domain_list); 
	else
		domain = list_next_entry(prev_domain, domain_list);

//	printk("Domain list INIT: &cluster->domains=%p, next: domain=%p\n", (void *)&cluster->domains, (void *)domain);

	if ((struct list_head *)domain == &cluster->domains) /*end of domain_list reached*/
		return NULL;

	return domain;
}

int raft_nl_domain_set(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t domain_id;
	uint32_t clusterid;
	struct nlattr *attrs[RAFT_NLA_DOMAIN_MAX + 1];
	struct raft_domain *domain = NULL;
//	struct raft_net *rnet = raft(genl_info_net(info));

//	pr_info("Netlink RAFT domain set called!\n");

	if ((info == NULL) || (!info->attrs[RAFT_NLA_DOMAIN])) {
		err = -EINVAL;
		goto input_error;
	}

	err = nla_parse_nested(attrs, RAFT_NLA_DOMAIN_MAX,
				info->attrs[RAFT_NLA_DOMAIN],
				raft_nl_domain_policy);
	if (err)
		goto input_error;

	if (!attrs[RAFT_NLA_DOMAIN_ID]) {
		err = -EINVAL;
		goto input_error;
	}

	domain_id = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ID]);
//	printk("Domain ID %u\n", domain_id);

	if (!attrs[RAFT_NLA_DOMAIN_CLUSTERID]) {
		err = -EINVAL;
		goto input_error;
	}

	clusterid = nla_get_u32(attrs[RAFT_NLA_DOMAIN_CLUSTERID]);
//	printk("Cluster ID %u\n", clusterid);

	domain = raft_config_domain_get(rnet_static_ptr, clusterid, domain_id);
	if (!domain)
		return -EEXIST;

	if (attrs[RAFT_NLA_DOMAIN_HEARTBEAT])
		domain->heartbeat = nla_get_u32(attrs[RAFT_NLA_DOMAIN_HEARTBEAT]);
//	printk("Heartbeat %u\n", domain->heartbeat);

	if (attrs[RAFT_NLA_DOMAIN_ELECTION])
		domain->election = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ELECTION]);
//	printk("Election %u\n", domain->election);

	if (attrs[RAFT_NLA_DOMAIN_MAXNODES])
		domain->maxnodes = nla_get_u32(attrs[RAFT_NLA_DOMAIN_MAXNODES]);
//	printk("Maxnodes %u\n", domain->maxnodes);

	return 0;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}

int raft_nl_dump_domain(struct raft_domain *domain, struct raft_nl_msg *msg)
{
	struct nlattr *attrs;
	void *hdr;

	hdr = genlmsg_put(msg->skb, msg->portid, msg->seq, &raft_genl_family,
			  NLM_F_MULTI, RAFT_NL_DOMAIN_SHOW);
	if (!hdr)
		return -EMSGSIZE;

	attrs = nla_nest_start(msg->skb, RAFT_NLA_DOMAIN);
	if (!attrs)
		goto msg_full;

	if (nla_put_u32(msg->skb, RAFT_NLA_DOMAIN_ID, domain->domain_id))
		goto attr_msg_full;

	if (nla_put_u32(msg->skb, RAFT_NLA_DOMAIN_HEARTBEAT, domain->heartbeat))
		goto attr_msg_full;

	if (nla_put_u32(msg->skb, RAFT_NLA_DOMAIN_ELECTION, domain->election))
		goto attr_msg_full;

	if (nla_put_u32(msg->skb, RAFT_NLA_DOMAIN_MAXNODES, domain->maxnodes))
		goto attr_msg_full;

	if (nla_put_u32(msg->skb, RAFT_NLA_DOMAIN_CLUSTERID, domain->clusterid))
		goto attr_msg_full;

	nla_nest_end(msg->skb, attrs);
	genlmsg_end(msg->skb, hdr);
	return 0;

attr_msg_full:
	nla_nest_cancel(msg->skb, attrs);
msg_full:
	genlmsg_cancel(msg->skb, hdr);

	return -EMSGSIZE;
}

int raft_nl_domain_show(struct sk_buff *skb, struct netlink_callback *cb)
{
//	struct raft_net *rnet = raft(sock_net(skb->sk));
	struct nlattr **pattrs;
	struct nlattr *attrs[RAFT_NLA_DOMAIN_MAX + 1];
	struct raft_nl_msg msg;
	struct raft_domain *domain = NULL;
	struct raft_domain *prev_domain = (struct raft_domain *)cb->args[1];
	int done = cb->args[0];
	uint32_t domain_id = 0;
	uint32_t clusterid = 0;
	int err;

//	pr_info("Netlink RAFT domain show called!\n");

	if (!prev_domain) {
		err = raft_nlmsg_parse(cb->nlh, &pattrs);
		if (err)
			goto input_error;

		if (!pattrs[RAFT_NLA_DOMAIN]) {
			err = -EINVAL;
			goto input_error;
		}

		err = nla_parse_nested(attrs, RAFT_NLA_DOMAIN_MAX,
					pattrs[RAFT_NLA_DOMAIN],
					raft_nl_cluster_policy);
		if (err)
			goto input_error;

		if (attrs[RAFT_NLA_DOMAIN_ID]) {
			domain_id = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ID]);
		}
		if (attrs[RAFT_NLA_DOMAIN_CLUSTERID]) {
			clusterid = nla_get_u32(attrs[RAFT_NLA_DOMAIN_CLUSTERID]);
		} else {
			err = -EINVAL;
			goto input_error;
		}
	}

	if (done)
		return 0;

	msg.skb = skb;
	msg.portid = NETLINK_CB(cb->skb).portid;
	msg.seq = cb->nlh->nlmsg_seq;

	rtnl_lock();

//	printk("Domain ID %u\n", domain_id);
//	printk("ClusterID %u\n", clusterid);

	if (domain_id != 0) {
		if ((domain = raft_config_domain_get(rnet_static_ptr, clusterid, domain_id)) != NULL) {
			raft_nl_dump_domain(domain, &msg);
		} else {
			rtnl_unlock();
			return -EEXIST;
		}
		done = 1;
	} else {
		while ((domain = raft_config_domain_get_next(rnet_static_ptr, clusterid, prev_domain)) != NULL) {
			err = raft_nl_dump_domain(domain, &msg);
			if (err) break;
			prev_domain = domain;
		}
		if (!err)
			done = 1;
	}
//	printk("Domain ptr %p\n", (void *)domain);

	rtnl_unlock();
	cb->args[0] = done;
	cb->args[1] = (long)domain;

	return skb->len;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}


static int raft_config_node_add(struct raft_net *rnet, uint32_t cluster_id, uint32_t domain_id, uint32_t node_id, struct raft_node **new)
{
	struct raft_cluster *cluster = NULL;
	struct raft_cluster *c_safe;
	struct raft_domain *domain = NULL;
	struct raft_domain *d_safe;
	struct raft_node *node = NULL;
	struct raft_node *n_safe;
	int err;

	if (!new)
		return -EINVAL;

//	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
//	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return -EEXIST;

//	printk("Domain list before search: &cluster->domains=%p\n", (void *)&cluster->domains);
	list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
//		printk("Domain list in search: domain=%p\n", (void *)domain);
		if (domain->domain_id == domain_id)
			break;
	}
//	printk("Domain list after search: domain=%p\n", (void *)domain);

	if ((struct list_head *)domain == &cluster->domains) /*domain not found*/
		return -EEXIST;

//	printk("Node list before search: &domain->nodes=%p\n", (void *)&domain->nodes);
	list_for_each_entry_safe(node, n_safe, &domain->nodes, node_list) {
//		printk("Node list in search: node=%p\n", (void *)node);
		if (node->node_id == node_id)
			return -EEXIST;

		if (node->node_id > node_id)
			break;

		if (list_is_last(&node->node_list, &domain->nodes))
			break;
	}
//	printk("Node list after search: node=%p\n", (void *)node);

	*new = kmalloc(sizeof(**new), GFP_ATOMIC);
	if (!(*new)) {
		err = -ENOMEM;
		goto err_nomem;
	}

	(*new)->node_id = node_id;
	(*new)->clusterid = cluster_id;
	(*new)->domainid = domain_id;
//	printk("New Node ID %u\n", (*new)->node_id);

	if ((struct list_head *)node == &domain->nodes) {
//		printk("Beginning: New Node ID %u\n", (*new)->node_id);
		list_add(&(*new)->node_list, &domain->nodes);
	} else if (node->node_id > node_id) {
//		printk("Middle: New Node ID %u\n", (*new)->node_id);
		list_add_tail(&(*new)->node_list, &node->node_list);
	} else {
//		printk("End: New Node ID %u\n", (*new)->node_id);
		list_add(&(*new)->node_list, &node->node_list);
	}

	return 0;

err_nomem:
	return err;
}

int raft_nl_node_add(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t node_id;
	__be32 contact;
	uint32_t domainid;
	uint32_t clusterid;
	struct nlattr *attrs[RAFT_NLA_NODE_MAX + 1];
	struct raft_node *new = NULL;
	uint8_t *pcontact = (uint8_t *)&contact;
//	struct raft_net *rnet = raft(genl_info_net(info));

//	pr_info("Netlink RAFT node add called!\n");

	if ((info == NULL) || (!info->attrs[RAFT_NLA_NODE])) {
		err = -EINVAL;
		goto input_error;
	}

	err = nla_parse_nested(attrs, RAFT_NLA_NODE_MAX,
				info->attrs[RAFT_NLA_NODE],
				raft_nl_node_policy);
	if (err)
		goto input_error;

	if (!attrs[RAFT_NLA_NODE_ID]) {
		err = -EINVAL;
		goto input_error;
	}

	node_id = nla_get_u32(attrs[RAFT_NLA_NODE_ID]);
//	printk("Node ID %u\n", node_id);

	if (!attrs[RAFT_NLA_NODE_DOMAINID]) {
		err = -EINVAL;
		goto input_error;
	}

	domainid = nla_get_u32(attrs[RAFT_NLA_NODE_DOMAINID]);
//	printk("Domain ID %u\n", domainid);

	if (!attrs[RAFT_NLA_NODE_CLUSTERID]) {
		err = -EINVAL;
		goto input_error;
	}

	clusterid = nla_get_u32(attrs[RAFT_NLA_NODE_CLUSTERID]);
//	printk("Cluster ID %u\n", clusterid);

	err = raft_config_node_add(rnet_static_ptr, clusterid, domainid, node_id, &new);
	if (err) {
		printk("raft_config_node_add() returns %d\n", err);
		return err;
	}

	if (!attrs[RAFT_NLA_NODE_CONTACT]) {
		pcontact[0] = 127;
		pcontact[1] = 0;
		pcontact[2] = 0;
		pcontact[3] = 1;
	} else
		contact = nla_get_u32(attrs[RAFT_NLA_NODE_CONTACT]);
//	printk("Contact 0x%x\n", contact);
	new->contact = contact;

	return 0;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}

static int raft_config_node_del(struct raft_net *rnet, uint32_t cluster_id, uint32_t domain_id, uint32_t node_id)
{
	struct raft_cluster *cluster = NULL;
	struct raft_cluster *c_safe;
	struct raft_domain *domain = NULL;
	struct raft_domain *d_safe;
	struct raft_node *node = NULL;
	struct raft_node *n_safe;

//	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
//		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
//	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return -EEXIST;

//	printk("Domain list before search: &cluster->domains=%p\n", (void *)&cluster->domains);
	list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
//		printk("Domain list in search: domain=%p\n", (void *)domain);
		if (domain->domain_id == domain_id)
			break;
	}
//	printk("Domain list after search: domain=%p\n", (void *)domain);

	if ((struct list_head *)domain == &cluster->domains) /*domain not found*/
		return -EEXIST;

//	printk("Node list before search: &domain->nodes=%p\n", (void *)&domain->nodes);
	list_for_each_entry_safe(node, n_safe, &domain->nodes, node_list) {
//		printk("Node list in search: node=%p\n", (void *)node);
		if (node->node_id == node_id)
			break;
	}
//	printk("Node list after search: node=%p\n", (void *)node);

	if ((struct list_head *)node == &domain->nodes) /*node not found*/
		return -EEXIST;

	list_del(&node->node_list);

	kfree(node);

	return 0;
}

int raft_nl_node_del(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t node_id;
	uint32_t domainid;
	uint32_t clusterid;
	struct nlattr *attrs[RAFT_NLA_NODE_MAX + 1];
//	struct raft_net *rnet = raft(genl_info_net(info));

//	pr_info("Netlink RAFT node delete called!\n");

	if ((info == NULL) || (!info->attrs[RAFT_NLA_NODE])) {
		err = -EINVAL;
		goto input_error;
	}

	err = nla_parse_nested(attrs, RAFT_NLA_NODE_MAX,
				info->attrs[RAFT_NLA_NODE],
				raft_nl_node_policy);
	if (err)
		goto input_error;

	if (!attrs[RAFT_NLA_NODE_ID]) {
		err = -EINVAL;
		goto input_error;
	}

	node_id = nla_get_u32(attrs[RAFT_NLA_NODE_ID]);
//	printk("Node ID %u\n", node_id);

	if (!attrs[RAFT_NLA_NODE_DOMAINID]) {
		err = -EINVAL;
		goto input_error;
	}

	domainid = nla_get_u32(attrs[RAFT_NLA_NODE_DOMAINID]);
//	printk("Domain ID %u\n", domainid);

	if (!attrs[RAFT_NLA_NODE_CLUSTERID]) {
		err = -EINVAL;
		goto input_error;
	}

	clusterid = nla_get_u32(attrs[RAFT_NLA_NODE_CLUSTERID]);
//	printk("Cluster ID %u\n", clusterid);

	err = raft_config_node_del(rnet_static_ptr, clusterid, domainid, node_id);
	if (err) {
		printk("raft_config_node_del() returns %d\n", err);
		return err;
	}

	return 0;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}

static struct raft_node *raft_config_node_get(struct raft_net *rnet, uint32_t cluster_id, uint32_t domain_id, uint32_t node_id)
{
	struct raft_cluster *cluster = NULL;
	struct raft_cluster *c_safe;
	struct raft_domain *domain = NULL;
	struct raft_domain *d_safe;
	struct raft_node *node = NULL;
	struct raft_node *n_safe;

//	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
//		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
//	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return NULL;

//	printk("Domain list before search: &cluster->domains=%p\n", (void *)&cluster->domains);
	list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
//		printk("Domain list in search: domain=%p\n", (void *)domain);
		if (domain->domain_id == domain_id)
			break;
	}
//	printk("Domain list after search: domain=%p\n", (void *)domain);

	if ((struct list_head *)domain == &cluster->domains) /*domain not found*/
		return NULL;

//	printk("Node list before search: &domain->nodes=%p\n", (void *)&domain->nodes);
	list_for_each_entry_safe(node, n_safe, &domain->nodes, node_list) {
//		printk("Node list in search: node=%p\n", (void *)node);
		if (node->node_id == node_id)
			break;
	}
//	printk("Node list after search: node=%p\n", (void *)node);

	if ((struct list_head *)node == &domain->nodes) /*node not found*/
		return NULL;

	return node;
}

static struct raft_node *raft_config_node_get_next(struct raft_net *rnet, uint32_t cluster_id, uint32_t domain_id, struct raft_node *prev_node)
{
	struct raft_domain *domain = NULL;
	struct raft_node *node = NULL;

	if (cluster_id == 0)
		return NULL;

	if (domain_id == 0)
		return NULL;

	if ((domain = raft_config_domain_get(rnet, cluster_id, domain_id)) == NULL)
		return NULL;

	if (prev_node == NULL)
		node = list_first_entry_or_null(&domain->nodes, struct raft_node, node_list); 
	else
		node = list_next_entry(prev_node, node_list);

//	printk("Node list INIT: &domain->nodes=%p, next: node=%p\n", (void *)&domain->nodes, (void *)node);

	if ((struct list_head *)node == &domain->nodes) /*end of node_list reached*/
		return NULL;

	return node;
}

int raft_nl_node_set(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t node_id;
	uint32_t domainid;
	uint32_t clusterid;
	struct nlattr *attrs[RAFT_NLA_NODE_MAX + 1];
	struct raft_node *node = NULL;
//	struct raft_net *rnet = raft(genl_info_net(info));

//	pr_info("Netlink RAFT node set called!\n");

	if ((info == NULL) || (!info->attrs[RAFT_NLA_NODE])) {
		err = -EINVAL;
		goto input_error;
	}

	err = nla_parse_nested(attrs, RAFT_NLA_NODE_MAX,
				info->attrs[RAFT_NLA_NODE],
				raft_nl_node_policy);
	if (err)
		goto input_error;

	if (!attrs[RAFT_NLA_NODE_ID]) {
		err = -EINVAL;
		goto input_error;
	}

	node_id = nla_get_u32(attrs[RAFT_NLA_NODE_ID]);
//	printk("Node ID %u\n", node_id);

	if (!attrs[RAFT_NLA_NODE_DOMAINID]) {
		err = -EINVAL;
		goto input_error;
	}

	domainid = nla_get_u32(attrs[RAFT_NLA_NODE_DOMAINID]);
//	printk("Domain ID %u\n", domainid);

	if (!attrs[RAFT_NLA_NODE_CLUSTERID]) {
		err = -EINVAL;
		goto input_error;
	}

	clusterid = nla_get_u32(attrs[RAFT_NLA_NODE_CLUSTERID]);
//	printk("Cluster ID %u\n", clusterid);

	node = raft_config_node_get(rnet_static_ptr, clusterid, domainid, node_id);
	if (!node)
		return -EEXIST;

	if (attrs[RAFT_NLA_NODE_CONTACT])
		node->contact = nla_get_u32(attrs[RAFT_NLA_NODE_CONTACT]);
//	printk("Contact 0x%x\n", node->contact);

	return 0;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}

int raft_nl_dump_node(struct raft_node *node, struct raft_nl_msg *msg)
{
	struct nlattr *attrs;
	void *hdr;

	hdr = genlmsg_put(msg->skb, msg->portid, msg->seq, &raft_genl_family,
			  NLM_F_MULTI, RAFT_NL_NODE_SHOW);
	if (!hdr)
		return -EMSGSIZE;

	attrs = nla_nest_start(msg->skb, RAFT_NLA_NODE);
	if (!attrs)
		goto msg_full;

	if (nla_put_u32(msg->skb, RAFT_NLA_NODE_ID, node->node_id))
		goto attr_msg_full;

	if (nla_put_u32(msg->skb, RAFT_NLA_NODE_CONTACT, node->contact))
		goto attr_msg_full;

	if (nla_put_u32(msg->skb, RAFT_NLA_NODE_DOMAINID, node->domainid))
		goto attr_msg_full;

	if (nla_put_u32(msg->skb, RAFT_NLA_NODE_CLUSTERID, node->clusterid))
		goto attr_msg_full;

	nla_nest_end(msg->skb, attrs);
	genlmsg_end(msg->skb, hdr);
	return 0;

attr_msg_full:
	nla_nest_cancel(msg->skb, attrs);
msg_full:
	genlmsg_cancel(msg->skb, hdr);

	return -EMSGSIZE;
}

int raft_nl_node_show(struct sk_buff *skb, struct netlink_callback *cb)
{
//	struct raft_net *rnet = raft(sock_net(skb->sk));
	struct nlattr **pattrs;
	struct nlattr *attrs[RAFT_NLA_NODE_MAX + 1];
	struct raft_nl_msg msg;
	struct raft_node *node = NULL;
	struct raft_node *prev_node = (struct raft_node *)cb->args[1];
	int done = cb->args[0];
	uint32_t node_id = 0;
	uint32_t domainid = 0;
	uint32_t clusterid = 0;
	int err;

//	pr_info("Netlink RAFT node show called!\n");

	if (!prev_node) {
		err = raft_nlmsg_parse(cb->nlh, &pattrs);
		if (err)
			goto input_error;

		if (!pattrs[RAFT_NLA_NODE]) {
			err = -EINVAL;
			goto input_error;
		}

		err = nla_parse_nested(attrs, RAFT_NLA_NODE_MAX,
					pattrs[RAFT_NLA_NODE],
					raft_nl_cluster_policy);
		if (err)
			goto input_error;

		if (attrs[RAFT_NLA_NODE_ID]) {
			node_id = nla_get_u32(attrs[RAFT_NLA_NODE_ID]);
		}
		if (attrs[RAFT_NLA_NODE_DOMAINID]) {
			domainid = nla_get_u32(attrs[RAFT_NLA_NODE_DOMAINID]);
		} else {
			err = -EINVAL;
			goto input_error;
		}
		if (attrs[RAFT_NLA_NODE_CLUSTERID]) {
			clusterid = nla_get_u32(attrs[RAFT_NLA_NODE_CLUSTERID]);
		} else {
			err = -EINVAL;
			goto input_error;
		}
	}

	if (done)
		return 0;

	msg.skb = skb;
	msg.portid = NETLINK_CB(cb->skb).portid;
	msg.seq = cb->nlh->nlmsg_seq;

	rtnl_lock();

//	printk("Node ID %u\n", node_id);
//	printk("DomainID %u\n", domainid);
//	printk("ClusterID %u\n", clusterid);

	if (node_id != 0) {
		if ((node = raft_config_node_get(rnet_static_ptr, clusterid, domainid, node_id)) != NULL) {
			raft_nl_dump_node(node, &msg);
		} else {
			rtnl_unlock();
			return -EEXIST;
		}
		done = 1;
	} else {
		while ((node = raft_config_node_get_next(rnet_static_ptr, clusterid, domainid, prev_node)) != NULL) {
			err = raft_nl_dump_node(node, &msg);
			if (err) break;
			prev_node = node;
		}
		if (!err)
			done = 1;
	}
//	printk("Node ptr %p\n", (void *)node);

	rtnl_unlock();
	cb->args[0] = done;
	cb->args[1] = (long)node;

	return skb->len;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}



#ifdef CONFIG_PROC_FS
/* Display raft configuration (/proc/net/raft/config). */
static int raft_config_seq_show(struct seq_file *seq, void *v)
{
	struct raft_net *rnet = seq->private;
	struct raft_cluster *cluster;
	struct raft_cluster *c_safe;

//	seq_printf(seq, "raft_config_seq_show: rnet = %p\n", rnet);

	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		struct raft_domain *domain;
		struct raft_domain *d_safe;

		seq_printf(seq,                 "cluster %u:\n", cluster->cluster_id);
		list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
			struct raft_node *node;
			struct raft_node *n_safe;

			seq_printf(seq,         "    domain %u:\n", domain->domain_id);
			seq_printf(seq,         "        heartbeat %u\n", domain->heartbeat);
			seq_printf(seq,         "        election %u\n", domain->election);
			seq_printf(seq,         "        maxnodes %u\n", domain->maxnodes);
//			seq_printf(seq,         "        clusterid %u\n", domain->clusterid);
			list_for_each_entry_safe(node, n_safe, &domain->nodes, node_list) {
				seq_printf(seq, "        node %u:\n", node->node_id);
				seq_printf(seq, "            contact %pI4\n", &node->contact);
//				seq_printf(seq, "            domainid %u\n", node->domainid);
//				seq_printf(seq, "            clusterid %u\n", node->clusterid);
			}
		}
	}

	return 0;
}

static int raft_config_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int ret = -EINVAL;

	ret = single_open(file, raft_config_seq_show, inode);
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
	.release = single_release,
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

