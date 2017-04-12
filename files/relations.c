/*
 * relations.c - The RAFT kernel module
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

static __be32 raft_get_source_addr(struct net *net, __be32 dest_addr, int local)
{
	struct net_device *dev;
	 __be32 newsrc = 0;

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
		if (local != 0) {
			newsrc = inet_select_addr(dev, dest_addr, RT_SCOPE_LINK);
		} else {
			newsrc = inet_select_addr(dev, dest_addr, RT_SCOPE_UNIVERSE);
		}
//		printk("source IP (%pI4) for destiantion %pI4\n", &newsrc, &dest_addr);
		if (newsrc != 0)
			break;
	}
	rcu_read_unlock();

	return newsrc;
}

int raft_relations_add_node(struct net *net, struct raft_node *new_node)
{
	struct raft_domain *domain;
	struct raft_node *node, *n_safe;
	struct raft_relation *relation, *r_safe, *new;
	__be32 srcip;
	int err;

	if (!new_node)
		return -EINVAL;

	domain = new_node->domain;
	if (!domain)
		return -EINVAL;

	/* this is a new node, so there may not exist any relations with this node_id */
	printk("Go through all domain relations\n");
	list_for_each_entry_safe(relation, r_safe, &domain->relations, relation_list) {
		if (relation->local_node->node_id == new_node->node_id)
			return -EEXIST;
		if (relation->peer_node->node_id == new_node->node_id)
			return -EEXIST;
	}

	printk("Go through all domain nodes\n");
	list_for_each_entry_safe(node, n_safe, &domain->nodes, node_list) {
		if (node != new_node) {
			if (new_node->local) {
				srcip = raft_get_source_addr(net, node->contact_addr.v4.sin_addr.s_addr, node->local);
				if (srcip != 0) {
					new = kmalloc(sizeof(*new), GFP_ATOMIC);
					if (!new) {
						err = -ENOMEM;
						goto err_nomem;
					}
					new->src_addr.v4.sin_family = AF_INET;
					new->src_addr.v4.sin_port = 0;
					new->src_addr.v4.sin_addr.s_addr = srcip;
					new->dst_addr.v4.sin_family = AF_INET;
					new->dst_addr.v4.sin_port = 0;
					new->dst_addr.v4.sin_addr.s_addr = node->contact_addr.v4.sin_addr.s_addr;
					new->local_node = new_node;
					new->peer_node = node;
					new->relation_state = RAFT_REL_ST_UNSPEC;
					printk("Inserting New Relation: Local Node ID %u@%pI4, Peer Node ID %u@%pI4\n", new->local_node->node_id, &new->src_addr.v4.sin_addr.s_addr, new->peer_node->node_id, &new->dst_addr.v4.sin_addr.s_addr);
					list_add(&new->relation_list, &domain->relations);
				} else
					printk("Inserting New Relation failed - no route to contact address: %pI4\n", &node->contact_addr.v4.sin_addr.s_addr);
			}

			if (node->local) {
				srcip = raft_get_source_addr(net, new_node->contact_addr.v4.sin_addr.s_addr, new_node->local);
				if (srcip != 0) {
					new = kmalloc(sizeof(*new), GFP_ATOMIC);
					if (!new) {
						err = -ENOMEM;
						goto err_nomem;
					}
					new->src_addr.v4.sin_family = AF_INET;
					new->src_addr.v4.sin_port = 0;
					new->src_addr.v4.sin_addr.s_addr = srcip;
					new->dst_addr.v4.sin_family = AF_INET;
					new->dst_addr.v4.sin_port = 0;
					new->dst_addr.v4.sin_addr.s_addr = new_node->contact_addr.v4.sin_addr.s_addr;
					new->local_node = node;
					new->peer_node = new_node;
					new->relation_state = RAFT_REL_ST_UNSPEC;
					printk("Inserting New Relation: Local Node ID %u@%pI4, Peer Node ID %u@%pI4\n", new->local_node->node_id, &new->src_addr.v4.sin_addr.s_addr, new->peer_node->node_id, &new->dst_addr.v4.sin_addr.s_addr);
					list_add(&new->relation_list, &domain->relations);
				} else
					printk("Inserting New Relation failed - no route to contact address: %pI4\n", &node->contact_addr.v4.sin_addr.s_addr);
			}
		}
	}

	return 0;

err_nomem:
	return err;
}

int raft_relations_del_node(struct raft_node *node)
{
	struct raft_domain *domain;
	struct raft_relation *relation, *r_safe;

	if (!node)
		return -EINVAL;

	domain = node->domain;
	if (!domain)
		return -EINVAL;

	/* this is an existing node, so there are existing relations to be deleted */
	printk("Go through all domain relations\n");
	list_for_each_entry_safe(relation, r_safe, &domain->relations, relation_list) {
		if (
			(relation->local_node == node) ||
			(relation->peer_node == node)
		) {
			printk("Deleting Relation: Local Node ID %u, Peer Node ID %u\n", relation->local_node->node_id, relation->peer_node->node_id);
			list_del(&relation->relation_list);
			kfree(relation);
		}
	}

	return 0;
}

int raft_relations_change_node(struct net *net, struct raft_node *node, union raft_addr *new_addr, int local)
{
	struct raft_domain *domain;
	struct raft_relation *relation, *r_safe;
	__be32 srcip;

	if (!node)
		return -EINVAL;

	domain = node->domain;
	if (!domain)
		return -EINVAL;

	/* this is a old node, so there are existing relations to be changed */
	if (node->local == local) {
		/* local stays local, peer stays peer */
		/* just reset state of the relation and change node's contact_addr */
		printk("Go through all domain relations\n");
		list_for_each_entry_safe(relation, r_safe, &domain->relations, relation_list) {
			if (relation->local_node == node) {
				relation->src_addr.v4.sin_family = new_addr->v4.sin_family;
				relation->src_addr.v4.sin_port = new_addr->v4.sin_port;
				relation->src_addr.v4.sin_addr.s_addr = new_addr->v4.sin_addr.s_addr;
				printk("Reseting Relation: Local Node ID %u@%pI4, Peer Node ID %u@%pI4\n", relation->local_node->node_id, &relation->src_addr.v4.sin_addr.s_addr, relation->peer_node->node_id, &relation->dst_addr.v4.sin_addr.s_addr);
				relation->relation_state = RAFT_REL_ST_UNSPEC;
			} else if (relation->peer_node == node) {
				srcip = raft_get_source_addr(net, new_addr->v4.sin_addr.s_addr, node->local);
				if (srcip != 0) {
					relation->src_addr.v4.sin_addr.s_addr = srcip;
					relation->dst_addr.v4.sin_family = new_addr->v4.sin_family;
					relation->dst_addr.v4.sin_port = new_addr->v4.sin_port;
					relation->dst_addr.v4.sin_addr.s_addr = new_addr->v4.sin_addr.s_addr;
					printk("Reseting Relation: Local Node ID %u@%pI4, Peer Node ID %u@%pI4\n", relation->local_node->node_id, &relation->src_addr.v4.sin_addr.s_addr, relation->peer_node->node_id, &relation->dst_addr.v4.sin_addr.s_addr);
					relation->relation_state = RAFT_REL_ST_UNSPEC;
				} else {
					printk("Reseting Relation failed - no route to contact address: %pI4\n", &node->contact_addr.v4.sin_addr.s_addr);
					printk("Deleting Relation: Local Node ID %u, Peer Node ID %u\n", relation->local_node->node_id, relation->peer_node->node_id);
					list_del(&relation->relation_list);
					kfree(relation);
				}
			}
			node->contact_addr.v4.sin_family = new_addr->v4.sin_family;
			node->contact_addr.v4.sin_port = new_addr->v4.sin_port;
			node->contact_addr.v4.sin_addr.s_addr = new_addr->v4.sin_addr.s_addr;
		}
	} else {
		/* local becomes peer or peer becomes local */
		/* first delete old node relations, change its contact_addr and local and create new relations */
		printk("delete changed relations\n");
		if (raft_relations_del_node(node) != 0)
			printk("Error deleting node relations\n");

		node->contact_addr.v4.sin_family = new_addr->v4.sin_family;
		node->contact_addr.v4.sin_port = new_addr->v4.sin_port;
		node->contact_addr.v4.sin_addr.s_addr = new_addr->v4.sin_addr.s_addr;
		node->local = local;

		printk("create changed relations\n");
		return raft_relations_add_node(net, node);
	}

	return 0;
}

#ifdef CONFIG_PROC_FS
/* Display raft relations (/proc/net/raft/relations). */
static int raft_relations_seq_show(struct seq_file *seq, void *v)
{
#if 0
	struct raft_net *rnet = seq->private;
	struct raft_cluster *cluster;
	struct raft_cluster *c_safe;
#endif

	seq_printf(seq, "raft_relations_seq_show: rnet_static_ptr = %p\n", rnet_static_ptr);

#if 0
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
//			seq_printf(seq,         "        clusterid %u\n", domain->cluster->cluster_id);
			list_for_each_entry_safe(node, n_safe, &domain->nodes, node_list) {
				seq_printf(seq, "        node %u:\n", node->node_id);
				seq_printf(seq, "            contact %pI4\n", &node->contact_addr.v4.sin_addr.s_addr);
				seq_printf(seq, "            local %d\n", node->local);
//				seq_printf(seq, "            domainid %u\n", node->domain->domain_id);
//				seq_printf(seq, "            clusterid %u\n", node->domain->cluster->cluster_id);
			}
		}
	}
#endif

	return 0;
}

static int raft_relations_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int ret = -EINVAL;

	ret = single_open(file, raft_relations_seq_show, inode);
	if (ret)
		goto err;

	seq = file->private_data;
	seq->private = rnet_static_ptr;

	return 0;
err:
	return ret;
}

static const struct file_operations raft_relations_seq_fops = {
	.open = raft_relations_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* Cleanup the proc fs entry for 'remaddr' object. */
void raft_relations_proc_exit(struct net *net)
{
	remove_proc_entry("relations", raft_net(net)->proc_net_raft);
}

int __net_init raft_relations_proc_init(struct net *net)
{
	struct proc_dir_entry *p;

	rnet_static_ptr = raft_net(net);
	printk("raft_relations_proc_init: rnet_static_ptr = %p\n", (void *)rnet_static_ptr);
	p = proc_create("relations", S_IRUGO, raft_net(net)->proc_net_raft,
			&raft_relations_seq_fops);
	if (!p)
		return -ENOMEM;
	return 0;
}
//EXPORT_SYMBOL(raft_relations_proc_init);
#endif /* CONFIG_PROC_FS */

