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

#ifdef CONFIG_PROC_FS
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
int raft_proc_register(struct net *net, struct raft_seq_afinfo *afinfo)
{
	struct proc_dir_entry *p;
	int rc = 0;

	afinfo->seq_ops.start = raft_seq_start;
	afinfo->seq_ops.next = raft_seq_next;
	afinfo->seq_ops.stop = raft_seq_stop;

	p = proc_create_data(afinfo->name, S_IRUGO, net->proc_net,
			     afinfo->seq_fops, afinfo);
	if (!p)
		rc = -ENOMEM;
	return rc;
}
//EXPORT_SYMBOL(raft_proc_register);

void raft_proc_unregister(struct net *net, struct raft_seq_afinfo *afinfo)
{
	remove_proc_entry(afinfo->name, net->proc_net);
}
//EXPORT_SYMBOL(raft_proc_unregister);

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
	return raft_proc_register(net, &raft_seq_afinfo);
}

static void __net_exit raft_proc_exit_net(struct net *net)
{
	raft_proc_unregister(net, &raft_seq_afinfo);
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

