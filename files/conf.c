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

	if ((struct list_head *)cluster == &rnet->clusters) {
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
	struct sk_buff *rep;
	int rc;
	int err;
	uint32_t cluster_id;
	struct nlattr *attrs[RAFT_NLA_CLUSTER_MAX + 1];
	void *msg_head;
	struct raft_cluster *new = NULL;
	struct net *net = genl_info_net(info);

	pr_info("Netlink RAFT cluster add called!\n");

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
	printk("Cluster ID %u\n", cluster_id);

	err = raft_config_cluster_add(rnet_static_ptr, cluster_id, &new);
	if (err) {
		printk("raft_config_cluster_add() returns %d\n", err);
		return err;
	}

	return 0;

input_error:
	printk("Error parsing attributes!\n");
	return err;

#if 0
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
#endif
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

	pr_info("Netlink RAFT cluster delete called!\n");

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
	printk("Cluster ID %u\n", cluster_id);

	err = raft_config_cluster_del(rnet_static_ptr, cluster_id);

	printk("raft_nl_cluster_del() returns %d\n", err);
	return err;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}

static struct raft_cluster *raft_config_cluster_get(struct raft_net *rnet, uint32_t cluster_id)
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

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return NULL;

	return cluster;
}

int raft_nl_cluster_set(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	uint32_t cluster_id;
	struct nlattr *attrs[RAFT_NLA_CLUSTER_MAX + 1];
	struct raft_cluster *cluster = NULL;

	pr_info("Netlink RAFT cluster set called!\n");

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
	printk("Cluster ID %u\n", cluster_id);

	cluster = raft_config_cluster_get(rnet_static_ptr, cluster_id);
	if (!cluster)
		return -EEXIST;

	return 0;

input_error:
	printk("Error parsing attributes!\n");
	return err;
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

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
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
	(*new)->clusterid = cluster_id;
	printk("New Domain ID %u\n", (*new)->domain_id);

	if ((struct list_head *)domain == &cluster->domains) {
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
	printk("Cluster ID %u\n", clusterid);

	if (!attrs[RAFT_NLA_DOMAIN_ID]) {
		err = -EINVAL;
		goto input_error;
	}

	domain_id = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ID]);
	printk("Domain ID %u\n", domain_id);

	err = raft_config_domain_add(rnet_static_ptr, clusterid, domain_id, &new);
	if (err) {
		printk("raft_config_domain_add() returns %d\n", err);
		return err;
	}

	if (!attrs[RAFT_NLA_DOMAIN_HEARTBEAT])
		heartbeat = 200;
	else
		heartbeat = nla_get_u32(attrs[RAFT_NLA_DOMAIN_HEARTBEAT]);
	printk("Heartbeat %u\n", heartbeat);
	new->heartbeat = heartbeat;

	if (!attrs[RAFT_NLA_DOMAIN_ELECTION])
		election = 300;
	else
		election = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ELECTION]);
	printk("Election %u\n", election);
	new->election = election;

	if (!attrs[RAFT_NLA_DOMAIN_MAXNODES])
		maxnodes = 0;
	else
		maxnodes = nla_get_u32(attrs[RAFT_NLA_DOMAIN_MAXNODES]);
	printk("Maxnodes %u\n", maxnodes);
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

	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return -EEXIST;

	printk("Domain list before search: &cluster->domains=%p\n", (void *)&cluster->domains);
	list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
		printk("Domain list in search: domain=%p\n", (void *)domain);
		if (domain->domain_id == domain_id)
			break;
	}
	printk("Domain list after search: domain=%p\n", (void *)domain);

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

	pr_info("Netlink RAFT domain delete called!\n");

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
	printk("Domain ID %u\n", domain_id);

	if (!attrs[RAFT_NLA_DOMAIN_CLUSTERID]) {
		err = -EINVAL;
		goto input_error;
	}

	clusterid = nla_get_u32(attrs[RAFT_NLA_DOMAIN_CLUSTERID]);
	printk("Cluster ID %u\n", clusterid);

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

	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return NULL;

	printk("Domain list before search: &cluster->domains=%p\n", (void *)&cluster->domains);
	list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
		printk("Domain list in search: domain=%p\n", (void *)domain);
		if (domain->domain_id == domain_id)
			break;
	}
	printk("Domain list after search: domain=%p\n", (void *)domain);

	if ((struct list_head *)domain == &cluster->domains) /*domain not found*/
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

	pr_info("Netlink RAFT domain set called!\n");

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
	printk("Domain ID %u\n", domain_id);

	if (!attrs[RAFT_NLA_DOMAIN_CLUSTERID]) {
		err = -EINVAL;
		goto input_error;
	}

	clusterid = nla_get_u32(attrs[RAFT_NLA_DOMAIN_CLUSTERID]);
	printk("Cluster ID %u\n", clusterid);

	domain = raft_config_domain_get(rnet_static_ptr, clusterid, domain_id);
	if (!domain)
		return -EEXIST;

	if (attrs[RAFT_NLA_DOMAIN_HEARTBEAT])
		domain->heartbeat = nla_get_u32(attrs[RAFT_NLA_DOMAIN_HEARTBEAT]);
	printk("Heartbeat %u\n", domain->heartbeat);

	if (attrs[RAFT_NLA_DOMAIN_ELECTION])
		domain->election = nla_get_u32(attrs[RAFT_NLA_DOMAIN_ELECTION]);
	printk("Election %u\n", domain->election);

	if (attrs[RAFT_NLA_DOMAIN_MAXNODES])
		domain->maxnodes = nla_get_u32(attrs[RAFT_NLA_DOMAIN_MAXNODES]);
	printk("Maxnodes %u\n", domain->maxnodes);

	return 0;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}

int raft_nl_domain_show(struct sk_buff *skb, struct netlink_callback *cb)
{
	pr_info("Netlink RAFT domain show called!\n");
	return 0;
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

	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return -EEXIST;

	printk("Domain list before search: &cluster->domains=%p\n", (void *)&cluster->domains);
	list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
		printk("Domain list in search: domain=%p\n", (void *)domain);
		if (domain->domain_id == domain_id)
			break;
	}
	printk("Domain list after search: domain=%p\n", (void *)domain);

	if ((struct list_head *)domain == &cluster->domains) /*domain not found*/
		return -EEXIST;

	printk("Node list before search: &domain->nodes=%p\n", (void *)&domain->nodes);
	list_for_each_entry_safe(node, n_safe, &domain->nodes, node_list) {
		printk("Node list in search: node=%p\n", (void *)node);
		if (node->node_id == node_id)
			return -EEXIST;

		if (node->node_id > node_id)
			break;

		if (list_is_last(&node->node_list, &domain->nodes))
			break;
	}
	printk("Node list after search: node=%p\n", (void *)node);

	*new = kmalloc(sizeof(**new), GFP_ATOMIC);
	if (!(*new)) {
		err = -ENOMEM;
		goto err_nomem;
	}

	(*new)->node_id = node_id;
	(*new)->clusterid = cluster_id;
	(*new)->domainid = domain_id;
	printk("New Node ID %u\n", (*new)->node_id);

	if ((struct list_head *)node == &domain->nodes) {
		printk("Beginning: New Node ID %u\n", (*new)->node_id);
		list_add(&(*new)->node_list, &domain->nodes);
	} else if (node->node_id > node_id) {
		printk("Middle: New Node ID %u\n", (*new)->node_id);
		list_add_tail(&(*new)->node_list, &node->node_list);
	} else {
		printk("End: New Node ID %u\n", (*new)->node_id);
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

	pr_info("Netlink RAFT node add called!\n");

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
	printk("Node ID %u\n", node_id);

	if (!attrs[RAFT_NLA_NODE_DOMAINID]) {
		err = -EINVAL;
		goto input_error;
	}

	domainid = nla_get_u32(attrs[RAFT_NLA_NODE_DOMAINID]);
	printk("Domain ID %u\n", domainid);

	if (!attrs[RAFT_NLA_NODE_CLUSTERID]) {
		err = -EINVAL;
		goto input_error;
	}

	clusterid = nla_get_u32(attrs[RAFT_NLA_NODE_CLUSTERID]);
	printk("Cluster ID %u\n", clusterid);

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
	printk("Contact 0x%x\n", contact);
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

	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return -EEXIST;

	printk("Domain list before search: &cluster->domains=%p\n", (void *)&cluster->domains);
	list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
		printk("Domain list in search: domain=%p\n", (void *)domain);
		if (domain->domain_id == domain_id)
			break;
	}
	printk("Domain list after search: domain=%p\n", (void *)domain);

	if ((struct list_head *)domain == &cluster->domains) /*domain not found*/
		return -EEXIST;

	printk("Node list before search: &domain->nodes=%p\n", (void *)&domain->nodes);
	list_for_each_entry_safe(node, n_safe, &domain->nodes, node_list) {
		printk("Node list in search: node=%p\n", (void *)node);
		if (node->node_id == node_id)
			break;
	}
	printk("Node list after search: node=%p\n", (void *)node);

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

	pr_info("Netlink RAFT node delete called!\n");

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
	printk("Node ID %u\n", node_id);

	if (!attrs[RAFT_NLA_NODE_DOMAINID]) {
		err = -EINVAL;
		goto input_error;
	}

	domainid = nla_get_u32(attrs[RAFT_NLA_NODE_DOMAINID]);
	printk("Domain ID %u\n", domainid);

	if (!attrs[RAFT_NLA_NODE_CLUSTERID]) {
		err = -EINVAL;
		goto input_error;
	}

	clusterid = nla_get_u32(attrs[RAFT_NLA_NODE_CLUSTERID]);
	printk("Cluster ID %u\n", clusterid);

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

	printk("Cluster list before search: &rnet->clusters=%p\n", (void *)&rnet->clusters);
	list_for_each_entry_safe(cluster, c_safe, &rnet->clusters, cluster_list) {
		printk("Cluster list in search: cluster=%p\n", (void *)cluster);
		if (cluster->cluster_id == cluster_id)
			break;
	}
	printk("Cluster list after search: cluster=%p\n", (void *)cluster);

	if ((struct list_head *)cluster == &rnet->clusters) /*cluster not found*/
		return NULL;

	printk("Domain list before search: &cluster->domains=%p\n", (void *)&cluster->domains);
	list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
		printk("Domain list in search: domain=%p\n", (void *)domain);
		if (domain->domain_id == domain_id)
			break;
	}
	printk("Domain list after search: domain=%p\n", (void *)domain);

	if ((struct list_head *)domain == &cluster->domains) /*domain not found*/
		return NULL;

	printk("Node list before search: &domain->nodes=%p\n", (void *)&domain->nodes);
	list_for_each_entry_safe(node, n_safe, &domain->nodes, node_list) {
		printk("Node list in search: node=%p\n", (void *)node);
		if (node->node_id == node_id)
			break;
	}
	printk("Node list after search: node=%p\n", (void *)node);

	if ((struct list_head *)node == &domain->nodes) /*node not found*/
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

	pr_info("Netlink RAFT node set called!\n");

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
	printk("Node ID %u\n", node_id);

	if (!attrs[RAFT_NLA_NODE_DOMAINID]) {
		err = -EINVAL;
		goto input_error;
	}

	domainid = nla_get_u32(attrs[RAFT_NLA_NODE_DOMAINID]);
	printk("Domain ID %u\n", domainid);

	if (!attrs[RAFT_NLA_NODE_CLUSTERID]) {
		err = -EINVAL;
		goto input_error;
	}

	clusterid = nla_get_u32(attrs[RAFT_NLA_NODE_CLUSTERID]);
	printk("Cluster ID %u\n", clusterid);

	node = raft_config_node_get(rnet_static_ptr, clusterid, domainid, node_id);
	if (!node)
		return -EEXIST;

	if (attrs[RAFT_NLA_NODE_CONTACT])
		node->contact = nla_get_u32(attrs[RAFT_NLA_NODE_CONTACT]);
	printk("Contact 0x%x\n", node->contact);

	return 0;

input_error:
	printk("Error parsing attributes!\n");
	return err;
}

int raft_nl_node_show(struct sk_buff *skb, struct netlink_callback *cb)
{
	pr_info("Netlink RAFT node show called!\n");
	return 0;
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

		seq_printf(seq,                 "Cluster: ID %u\n", cluster->cluster_id);
		list_for_each_entry_safe(domain, d_safe, &cluster->domains, domain_list) {
			struct raft_node *node;
			struct raft_node *n_safe;

			seq_printf(seq,         "    Domain: ID %u\n", domain->domain_id);
			seq_printf(seq,         "        HeartBeat %u\n", domain->heartbeat);
			seq_printf(seq,         "        Election %u\n", domain->election);
			seq_printf(seq,         "        MaxNodes %u\n", domain->maxnodes);
//			seq_printf(seq,         "        clusterid %u\n", domain->clusterid);
			list_for_each_entry_safe(node, n_safe, &domain->nodes, node_list) {
				seq_printf(seq, "        Node: ID %u\n", node->node_id);
				seq_printf(seq, "            Contact %pI4\n", &node->contact);
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

