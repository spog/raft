/*
 * raft.h - The RAFT kernel module
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

#ifndef __raft_h__
#define __raft_h__

#include <linux/ktime.h>
#include <linux/rhashtable.h>
#include <linux/socket.h>	/* linux/in.h needs this!!    */
#include <linux/in.h>		/* We get struct sockaddr_in. */
#include <linux/in6.h>		/* We get struct in6_addr     */
#include <linux/ipv6.h>
#include <asm/param.h>		/* We get MAXHOSTNAMELEN.     */
#include <linux/atomic.h>	/* This gets us atomic counters.  */
#include <linux/skbuff.h>	/* We need sk_buff_head. */
#include <linux/workqueue.h>	/* We need tq_struct.	 */
#include <net/ip.h>		/* For inet_skb_parm */
#include <net/netns/generic.h>
#include <net/genetlink.h>

#include "structs.h"		/* We need raft* header structs.  */
#include "netlink.h"

#define RAFT_MOD_VER "0.0.2"

#define RAFT_PROTOSW_FLAG 0

int raft_asconf_mgmt(struct raft_sock *, struct raft_sockaddr_entry *);

/* External references. */

extern struct proto raft_prot;
extern int raft_net_id __read_mostly;

/* Raft Node States */
enum {
	RAFT_NODE_ST_UNSPEC,

	RAFT_NODE_ST_INIT_10,
	RAFT_NODE_ST_INIT_20,
	RAFT_NODE_ST_INIT_30,

	RAFT_NODE_ST_CONNECT_10,
	RAFT_NODE_ST_CONNECT_20,
	RAFT_NODE_ST_CONNECT_30,

	__RAFT_NODE_ST_MAX,
	RAFT_NODE_ST_MAX = __RAFT_NODE_ST_MAX - 1
};

/* Raft Relation States */
enum {
	RAFT_REL_ST_UNSPEC,

	RAFT_REL_ST_INIT,

	__RAFT_REL_ST_MAX,
	RAFT_REL_ST_MAX = __RAFT_REL_ST_MAX - 1
};

struct raft_domain;
struct raft_node {
	struct list_head node_list;
	uint32_t node_id;
	union raft_addr contact_addr;
	struct raft_domain *domain;
};

struct raft_relation {
	struct list_head relation_list;
	struct raft_node *local_node;
	struct raft_node *peer_node;
	uint32_t relation_state;
};

struct raft_cluster;
struct raft_domain {
	struct list_head domain_list;
	struct list_head nodes;
	uint32_t domain_id;
	uint32_t heartbeat;
	uint32_t election;
	uint32_t maxnodes;
	struct raft_cluster *cluster;

	/* Entry into the local nodes and their relation data */
	struct list_head relations;
};

struct raft_cluster {
	struct list_head cluster_list;
	struct list_head domains;
	uint32_t cluster_id;
};

struct raft_net {
#ifdef CONFIG_PROC_FS
        struct proc_dir_entry *proc_net_raft;
#endif

	/* This is the global local address list.
	 * We actively maintain this complete list of addresses on
	 * the system by catching address add/delete events.
	 *
	 * It is a list of raft_sockaddr_entry.
	 */
	struct list_head local_addr_list;
	struct list_head addr_waitq;
	struct timer_list addr_wq_timer;
	struct list_head auto_asconf_splist;

	/* Lock that protects both addr_waitq and auto_asconf_splist */
	spinlock_t addr_wq_lock;

	/* Lock that protects the local_addr_list writers */
	spinlock_t local_addr_lock;

	/* Entry into the raft configuration data */
	struct list_head clusters;

	/* Entry into the raft nodes list */
	struct list_head locals;
};

struct raft_local_node {
	struct list_head local_node_list;
	struct raft_cluster *cluster;
	struct raft_domain *domain;
	struct raft_node *node;
};

static inline struct raft_net *raft_net(struct net *net)
{
	return net_generic(net, raft_net_id);
}

enum {
  IPPROTO_RAFT = 254,		/* RAFT in IP		*/
#define IPPROTO_RAFT		IPPROTO_RAFT
};

int raft_nl_cluster_add(struct sk_buff *skb, struct genl_info *info);
int raft_nl_cluster_del(struct sk_buff *skb, struct genl_info *info);
int raft_nl_cluster_set(struct sk_buff *skb, struct genl_info *info);
int raft_nl_cluster_show(struct sk_buff *skb, struct netlink_callback *cb);
int raft_nl_domain_add(struct sk_buff *skb, struct genl_info *info);
int raft_nl_domain_del(struct sk_buff *skb, struct genl_info *info);
int raft_nl_domain_set(struct sk_buff *skb, struct genl_info *info);
int raft_nl_domain_show(struct sk_buff *skb, struct netlink_callback *cb);
int raft_nl_node_add(struct sk_buff *skb, struct genl_info *info);
int raft_nl_node_del(struct sk_buff *skb, struct genl_info *info);
int raft_nl_node_set(struct sk_buff *skb, struct genl_info *info);
int raft_nl_node_show(struct sk_buff *skb, struct netlink_callback *cb);

/* /proc */
int raft_seq_open(struct inode *inode, struct file *file);

struct raft_seq_afinfo {
	char *name;
	sa_family_t family;
	struct raft_table *raft_table;
	const struct file_operations *seq_fops;
	struct seq_operations seq_ops;
};

struct raft_iter_state {
	struct seq_net_private p;
	sa_family_t family;
	int bucket;
	struct raft_table *raft_table;
};

#ifdef CONFIG_PROC_FS
int raft_proc_register(struct net *net, struct raft_seq_afinfo *afinfo);
void raft_proc_unregister(struct net *net, struct raft_seq_afinfo *afinfo);

int raft_proc_init(void);
void raft_proc_exit(void);
#endif

static inline u32 raft_hashfn(const struct net *net, u32 num, u32 mask)
{
	return (num + net_hash_mix(net)) & mask;
}

/**
 *	struct raft_hslot - RAFT hash slot
 *
 *	@head:	head of list of sockets
 *	@count:	number of sockets in 'head' list
 *	@lock:	spinlock protecting changes to head/count
 */
struct raft_hslot {
	struct hlist_head	head;
	int			count;
	spinlock_t		lock;
} __attribute__((aligned(2 * sizeof(long))));

/**
 *	struct raft_table - RAFT table
 *
 *	@hash:	hash table, sockets are hashed on (local port)
 *	@hash2:	hash table, sockets are hashed on (local port, local address)
 *	@mask:	number of slots in hash tables, minus 1
 *	@log:	log2(number of slots in hash table)
 */
struct raft_table {
	struct raft_hslot *hash;
	struct raft_hslot *hash2;
	unsigned int mask;
	unsigned int log;
};
//extern struct raft_table raft_table;
void raft_table_init(struct raft_table *, const char *);
static inline struct raft_hslot *raft_hashslot(struct raft_table *table,
					     struct net *net, unsigned int num)
{
	return &table->hash[raft_hashfn(net, num, table->mask)];
}
/*
 * For secondary hash, net_hash_mix() is performed before calling
 * raft_hashslot2(), this explains difference with raft_hashslot()
 */
static inline struct raft_hslot *raft_hashslot2(struct raft_table *table,
					      unsigned int hash)
{
	return &table->hash2[hash & table->mask];
}

#endif /* __raft_h__ */
