/*
 * init.c - The RAFT kernel module
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

/*
 * This is the routine which IP calls when receiving an RAFT packet.
 */
int raft_rcv(struct sk_buff *skb)
{
	struct sock *sk;
	return 0;
}

#if 0
static int raft6_rcv(struct sk_buff *skb)
{
	return raft_rcv(skb) ? -1 : 0;
}

static const struct inet6_protocol raftv6_protocol = {
	.handler      = raft6_rcv,
	.flags        = INET6_PROTO_NOPOLICY | INET6_PROTO_FINAL,
};

/* Event handler for inet6 address addition/deletion events.
 * The raft_local_addr_list needs to be protocted by a spin lock since
 * multiple notifiers (say IPv4 and IPv6) may be running at the same
 * time and thus corrupt the list.
 * The reader side is protected with RCU.
 */
static int raft_inet6addr_event(struct notifier_block *this, unsigned long ev,
				void *ptr)
{
	struct inet6_ifaddr *ifa = (struct inet6_ifaddr *)ptr;
	struct raft_sockaddr_entry *addr = NULL;
	struct raft_sockaddr_entry *temp;
	struct raft_net *rn = raft_net(dev_net(ifa->idev->dev));
//	struct net *net = dev_net(ifa->idev->dev);
	int found = 0;

	switch (ev) {
	case NETDEV_UP:
		addr = kmalloc(sizeof(struct raft_sockaddr_entry), GFP_ATOMIC);
		if (addr) {
			addr->a.v6.sin6_family = AF_INET6;
			addr->a.v6.sin6_port = 0;
			addr->a.v6.sin6_addr = ifa->addr;
			addr->a.v6.sin6_scope_id = ifa->idev->dev->ifindex;
			addr->valid = 1;
			spin_lock_bh(&rn->local_addr_lock);
//			list_add_tail_rcu(&addr->list, &net->raft.local_addr_list);
//			raft_addr_wq_mgmt(net, addr, RAFT_ADDR_NEW);
			spin_unlock_bh(&rn->local_addr_lock);
		}
		break;
	case NETDEV_DOWN:
		spin_lock_bh(&rn->local_addr_lock);
//		list_for_each_entry_safe(addr, temp,
//					&net->raft.local_addr_list, list) {
//			if (addr->a.sa.sa_family == AF_INET6 &&
//					ipv6_addr_equal(&addr->a.v6.sin6_addr,
//						&ifa->addr)) {
//				raft_addr_wq_mgmt(net, addr, RAFT_ADDR_DEL);
//				found = 1;
//				addr->valid = 0;
//				list_del_rcu(&addr->list);
//				break;
//			}
//		}
		spin_unlock_bh(&rn->local_addr_lock);
//		if (found)
//			kfree_rcu(addr, rcu);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block raft_inet6addr_notifier = {
	.notifier_call = raft_inet6addr_event,
};

/* Register with inet6 layer. */
int raft_v6_add_protocol(void)
{
	/* Register notifier for inet6 address additions/deletions. */
	register_inet6addr_notifier(&raft_inet6addr_notifier);

	if (inet6_add_protocol(&raftv6_protocol, IPPROTO_RAFT) < 0)
		return -EAGAIN;

	return 0;
}

/* Unregister with inet6 layer. */
void raft_v6_del_protocol(void)
{
	inet6_del_protocol(&raftv6_protocol, IPPROTO_RAFT);
	unregister_inet6addr_notifier(&raft_inet6addr_notifier);
}
#endif

/* Socket operations.  */
static const struct proto_ops inet_seqpacket_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,	/* Needs to be wrapped... */
	.bind		   = inet_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = inet_getname,	/* Semantics are different.  */
//	.poll		   = raft_poll,
	.ioctl		   = inet_ioctl,
//	.listen		   = raft_inet_listen,
	.shutdown	   = inet_shutdown,	/* Looks harmless.  */
	.setsockopt	   = sock_common_setsockopt, /* IP_SOL IP_OPTION is a problem */
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = sock_no_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
};

/* Registration with AF_INET family.  */
static struct inet_protosw raft_seqpacket_protosw = {
	.type       = SOCK_SEQPACKET,
	.protocol   = IPPROTO_RAFT,
	.prot       = &raft_prot,
	.ops        = &inet_seqpacket_ops,
	.flags      = RAFT_PROTOSW_FLAG
};

/* Register with IP layer.  */
static const struct net_protocol raft_protocol = {
	.handler     = raft_rcv,
	.no_policy   = 1,
	.netns_ok    = 1,
	.icmp_strict_tag_validation = 1,
};

/* Event handler for inet address addition/deletion events.
 * The raft_local_addr_list needs to be protocted by a spin lock since
 * multiple notifiers (say IPv4 and IPv6) may be running at the same
 * time and thus corrupt the list.
 * The reader side is protected with RCU.
 */
static int raft_inetaddr_event(struct notifier_block *this, unsigned long ev,
			       void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct raft_sockaddr_entry *addr = NULL;
	struct raft_sockaddr_entry *temp;
	struct raft_net *rn = raft_net(dev_net(ifa->ifa_dev->dev));
//	struct net *net = dev_net(ifa->ifa_dev->dev);
	int found = 0;

	switch (ev) {
	case NETDEV_UP:
		addr = kmalloc(sizeof(struct raft_sockaddr_entry), GFP_ATOMIC);
		if (addr) {
			addr->a.v4.sin_family = AF_INET;
			addr->a.v4.sin_port = 0;
			addr->a.v4.sin_addr.s_addr = ifa->ifa_local;
			addr->valid = 1;
			spin_lock_bh(&rn->local_addr_lock);
//			list_add_tail_rcu(&addr->list, &net->raft.local_addr_list);
//			raft_addr_wq_mgmt(net, addr, RAFT_ADDR_NEW);
			spin_unlock_bh(&rn->local_addr_lock);
		}
		break;
	case NETDEV_DOWN:
		spin_lock_bh(&rn->local_addr_lock);
//		list_for_each_entry_safe(addr, temp,
//					&net->raft.local_addr_list, list) {
//			if (addr->a.sa.sa_family == AF_INET &&
//					addr->a.v4.sin_addr.s_addr ==
//					ifa->ifa_local) {
//				raft_addr_wq_mgmt(net, addr, RAFT_ADDR_DEL);
//				found = 1;
//				addr->valid = 0;
//				list_del_rcu(&addr->list);
//				break;
//			}
//		}
		spin_unlock_bh(&rn->local_addr_lock);
//		if (found)
//			kfree_rcu(addr, rcu);
		break;
	}

	return NOTIFY_DONE;
}

/* Notifier for inetaddr addition/deletion events.  */
static struct notifier_block raft_inetaddr_notifier = {
	.notifier_call = raft_inetaddr_event,
};

/* Register with inet4 layer. */
static int raft_v4_protosw_init(void)
{
	int rc;

	rc = proto_register(&raft_prot, 1);
	if (rc)
		return rc;

	/* Register RAFT(UDP style) with socket layer.  */
	inet_register_protosw(&raft_seqpacket_protosw);

	return 0;
}

static void raft_v4_protosw_exit(void)
{
	inet_unregister_protosw(&raft_seqpacket_protosw);
	proto_unregister(&raft_prot);
}

static int raft_v4_add_protocol(void)
{
	/* Register notifier for inet address additions/deletions. */
	register_inetaddr_notifier(&raft_inetaddr_notifier);

	/* Register RAFT with inet layer.  */
	if (inet_add_protocol(&raft_protocol, IPPROTO_RAFT) < 0)
		return -EAGAIN;

	return 0;
}

/* Unregister with inet4 layer. */
static void raft_v4_del_protocol(void)
{
	inet_del_protocol(&raft_protocol, IPPROTO_RAFT);
	unregister_inetaddr_notifier(&raft_inetaddr_notifier);
}

int raft_net_id __read_mostly;

static int __net_init raft_init_net(struct net *net)
{
	struct raft_net *rn = net_generic(net, raft_net_id);

	return 0;
}

static void __net_exit raft_exit_net(struct net *net)
{
	return;
}

static struct pernet_operations raft_net_ops = {
	.init = raft_init_net,
	.exit = raft_exit_net,
	.id   = &raft_net_id,
	.size = sizeof(struct raft_net),
};

/* Initialize the RAFT module.  */
static __init int raft_init(void)
{
	int status = -EINVAL;

	pr_info("Activated RAFT (version " RAFT_MOD_VER ")\n");

	status = raft_netlink_start();
	if (status)
		goto err_netlink_start;

	status = raft_v4_protosw_init();
	if (status)
		goto err_protosw_init;

	status = raft_v4_add_protocol();
	if (status)
		goto err_add_protocol;

#if 0
	/* Register RAFT with inet6 layer.  */
	status = raft_v6_add_protocol();
	if (status)
		goto err_v6_add_protocol;
#endif
  
	status = register_pernet_subsys(&raft_net_ops);
	if (status)
		goto err_pernet;

	status = raft_proc_init();
	if (status)
		goto err_pernet;

out:
	return status;

err_add_protocol:
//err_v6_add_protocol:
	raft_v4_protosw_exit();
err_pernet:
err_protosw_init:
	raft_netlink_stop();
err_netlink_start:
	goto out;
}

/* RAFT module cleanup.  */
static __exit void raft_exit(void)
{
	pr_info("Goodbye world from the Raft\n");

	raft_proc_exit();

	unregister_pernet_subsys(&raft_net_ops);

	/* Unregister with inet6/inet layers. */
//	raft_v6_del_protocol();
	raft_v4_del_protocol();

	raft_netlink_stop();
}

module_init(raft_init);
module_exit(raft_exit);

MODULE_DESCRIPTION("Kernel support for the Raft Consensus Algrithm");
MODULE_LICENSE("GPL");
