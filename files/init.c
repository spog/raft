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

/* Global data structures. */
struct raft_globals raft_globals __read_mostly;

static struct raft_pf *raft_pf_inet6_specific;
static struct raft_pf *raft_pf_inet_specific;
static struct raft_af *raft_af_v4_specific;
static struct raft_af *raft_af_v6_specific;

/*
 * This is the routine which IP calls when receiving an RAFT packet.
 */
int raft_rcv(struct sk_buff *skb)
{
//	struct sock *sk;
	return 0;
}

/* Private helper to extract ipv4 address and stash them in
 * the protocol structure.
 */
static void raft_v4_copy_addrlist(struct list_head *addrlist,
				  struct net_device *dev)
{
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	struct raft_sockaddr_entry *addr;

	rcu_read_lock();
	if ((in_dev = __in_dev_get_rcu(dev)) == NULL) {
		rcu_read_unlock();
		return;
	}

	for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
		/* Add the address to the local list.  */
		addr = kzalloc(sizeof(*addr), GFP_ATOMIC);
		if (addr) {
			addr->a.v4.sin_family = AF_INET;
			addr->a.v4.sin_port = 0;
			addr->a.v4.sin_addr.s_addr = ifa->ifa_local;
			printk("raft_v4_copy_addrlist: IP local = %pI4\n", &addr->a.v4.sin_addr.s_addr);
			addr->valid = 1;
			INIT_LIST_HEAD(&addr->list);
			list_add_tail(&addr->list, addrlist);
		}
	}

	rcu_read_unlock();
}

/* Extract our IP addresses from the system and stash them in the
 * protocol structure.
 */
static void raft_get_local_addr_list(struct net *net)
{
	struct raft_net *rn = raft_net(net);
	struct net_device *dev;
	struct list_head *pos;
	struct raft_af *af;

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
		list_for_each(pos, &raft_address_families) {
			af = list_entry(pos, struct raft_af, list);
			af->copy_addrlist(&rn->local_addr_list, dev);
		}
	}
	rcu_read_unlock();
}

/* Free the existing local addresses.  */
static void raft_free_local_addr_list(struct net *net)
{
	struct raft_net *rn = raft_net(net);
	struct raft_sockaddr_entry *addr;
	struct list_head *pos, *temp;

	list_for_each_safe(pos, temp, &rn->local_addr_list) {
		addr = list_entry(pos, struct raft_sockaddr_entry, list);
		list_del(pos);
		kfree(addr);
	}
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

/* IPv4 address related functions.  */
static struct raft_af raft_af_inet = {
	.sa_family	   = AF_INET,
//	.sctp_xmit	   = sctp_v4_xmit,
	.setsockopt	   = ip_setsockopt,
	.getsockopt	   = ip_getsockopt,
//	.get_dst	   = sctp_v4_get_dst,
//	.get_saddr	   = sctp_v4_get_saddr,
	.copy_addrlist	   = raft_v4_copy_addrlist,
//	.from_skb	   = sctp_v4_from_skb,
//	.from_sk	   = sctp_v4_from_sk,
//	.from_addr_param   = sctp_v4_from_addr_param,
//	.to_addr_param	   = sctp_v4_to_addr_param,
//	.cmp_addr	   = sctp_v4_cmp_addr,
//	.addr_valid	   = sctp_v4_addr_valid,
//	.inaddr_any	   = sctp_v4_inaddr_any,
//	.is_any		   = sctp_v4_is_any,
//	.available	   = sctp_v4_available,
//	.scope		   = sctp_v4_scope,
//	.skb_iif	   = sctp_v4_skb_iif,
//	.is_ce		   = sctp_v4_is_ce,
//	.seq_dump_addr	   = sctp_v4_seq_dump_addr,
//	.ecn_capable	   = sctp_v4_ecn_capable,
	.net_header_len	   = sizeof(struct iphdr),
	.sockaddr_len	   = sizeof(struct sockaddr_in),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ip_setsockopt,
	.compat_getsockopt = compat_ip_getsockopt,
#endif
};

struct raft_pf *raft_get_pf_specific(sa_family_t family)
{
	switch (family) {
	case PF_INET:
		return raft_pf_inet_specific;
	case PF_INET6:
		return raft_pf_inet6_specific;
	default:
		return NULL;
	}
}

/* Register the PF specific function table.  */
int raft_register_pf(struct raft_pf *pf, sa_family_t family)
{
	switch (family) {
	case PF_INET:
		if (raft_pf_inet_specific)
			return 0;
		raft_pf_inet_specific = pf;
		break;
	case PF_INET6:
		if (raft_pf_inet6_specific)
			return 0;
		raft_pf_inet6_specific = pf;
		break;
	default:
		return 0;
	}
	return 1;
}

static void raft_addr_wq_timeout_handler(unsigned long arg)
{
	struct net *net = (struct net *)arg;
	struct raft_net *rn = raft_net(net);
	struct raft_sockaddr_entry *addrw, *temp;
	struct raft_sock *sp;

	printk("raft_addr_wq_timeout_handler:\n");
	spin_lock_bh(&rn->addr_wq_lock);

	list_for_each_entry_safe(addrw, temp, &rn->addr_waitq, list) {
		pr_debug("%s: the first ent in wq:%p is addr:%pISc for cmd:%d at "
			 "entry:%p\n", __func__, &rn->addr_waitq, &addrw->a.sa,
			 addrw->state, addrw);

#if 0
#if IS_ENABLED(CONFIG_IPV6)
		/* Now we send an ASCONF for each association */
		/* Note. we currently don't handle link local IPv6 addressees */
		if (addrw->a.sa.sa_family == AF_INET6) {
			struct in6_addr *in6;

			if (ipv6_addr_type(&addrw->a.v6.sin6_addr) &
			    IPV6_ADDR_LINKLOCAL)
				goto free_next;

			in6 = (struct in6_addr *)&addrw->a.v6.sin6_addr;
			if (ipv6_chk_addr(net, in6, NULL, 0) == 0 &&
			    addrw->state == SCTP_ADDR_NEW) {
				unsigned long timeo_val;

				pr_debug("%s: this is on DAD, trying %d sec "
					 "later\n", __func__,
					 RAFT_ADDRESS_TICK_DELAY);

				timeo_val = jiffies;
				timeo_val += msecs_to_jiffies(RAFT_ADDRESS_TICK_DELAY);
				mod_timer(&rn->addr_wq_timer, timeo_val);
				break;
			}
		}
#endif
#endif
		list_for_each_entry(sp, &rn->auto_asconf_splist, auto_asconf_list) {
			struct sock *sk;

			sk = raft_opt2sk(sp);
			/* ignore bound-specific endpoints */
//			if (!sctp_is_ep_boundall(sk))
//				continue;
			bh_lock_sock(sk);
			if (raft_asconf_mgmt(sp, addrw) < 0)
				pr_debug("%s: raft_asconf_mgmt failed\n", __func__);
			bh_unlock_sock(sk);
		}
#if 0
#if IS_ENABLED(CONFIG_IPV6)
free_next:
#endif
#endif
		list_del(&addrw->list);
		kfree(addrw);
	}
	spin_unlock_bh(&rn->addr_wq_lock);
}

static void raft_free_addr_wq(struct net *net)
{
	struct raft_net *rn = raft_net(net);
#if 1
	struct raft_sockaddr_entry *addrw;
	struct raft_sockaddr_entry *temp;

	spin_lock_bh(&rn->addr_wq_lock);
	del_timer(&rn->addr_wq_timer);
	list_for_each_entry_safe(addrw, temp, &rn->addr_waitq, list) {
		list_del(&addrw->list);
		kfree(addrw);
	}
	spin_unlock_bh(&rn->addr_wq_lock);
#endif
}

/* lookup the entry for the same address in the addr_waitq
 * sctp_addr_wq MUST be locked
 */
#if 1
static struct raft_sockaddr_entry *raft_addr_wq_lookup(struct net *net,
					struct raft_sockaddr_entry *addr)
{
	struct raft_net *rn = raft_net(net);
	struct raft_sockaddr_entry *addrw;

	list_for_each_entry(addrw, &rn->addr_waitq, list) {
		if (addrw->a.sa.sa_family != addr->a.sa.sa_family)
			continue;
		if (addrw->a.sa.sa_family == AF_INET) {
			if (addrw->a.v4.sin_addr.s_addr ==
			    addr->a.v4.sin_addr.s_addr)
				return addrw;
		} else if (addrw->a.sa.sa_family == AF_INET6) {
			if (ipv6_addr_equal(&addrw->a.v6.sin6_addr,
			    &addr->a.v6.sin6_addr))
				return addrw;
		}
	}
	return NULL;
}
#endif

void raft_addr_wq_mgmt(struct net *net, struct raft_sockaddr_entry *addr, int cmd)
{
	struct raft_net *rn = raft_net(net);
#if 1
	struct raft_sockaddr_entry *addrw;
	unsigned long timeo_val;

	/* first, we check if an opposite message already exist in the queue.
	 * If we found such message, it is removed.
	 * This operation is a bit stupid, but the DHCP client attaches the
	 * new address after a couple of addition and deletion of that address
	 */

	spin_lock_bh(&rn->addr_wq_lock);
	/* Offsets existing events in addr_wq */
	addrw = raft_addr_wq_lookup(net, addr);
	if (addrw) {
		if (addrw->state != cmd) {
			pr_debug("%s: offsets existing entry for %d, addr:%pISc "
				 "in wq:%p\n", __func__, addrw->state, &addrw->a.sa,
				 &rn->addr_waitq);

			list_del(&addrw->list);
			kfree(addrw);
		}
		spin_unlock_bh(&rn->addr_wq_lock);
		return;
	}

	/* OK, we have to add the new address to the wait queue */
	addrw = kmemdup(addr, sizeof(struct raft_sockaddr_entry), GFP_ATOMIC);
	if (addrw == NULL) {
		spin_unlock_bh(&rn->addr_wq_lock);
		return;
	}
	addrw->state = cmd;
	list_add_tail(&addrw->list, &rn->addr_waitq);

	pr_debug("%s: add new entry for cmd:%d, addr:%pISc in wq:%p\n",
		 __func__, addrw->state, &addrw->a.sa, &rn->addr_waitq);

	if (!timer_pending(&rn->addr_wq_timer)) {
		timeo_val = jiffies;
		timeo_val += msecs_to_jiffies(RAFT_ADDRESS_TICK_DELAY);
		mod_timer(&rn->addr_wq_timer, timeo_val);
	}
	spin_unlock_bh(&rn->addr_wq_lock);
#endif
}

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
	struct net *net = dev_net(ifa->ifa_dev->dev);
	struct raft_net *rn = raft_net(net);
	int found = 0;

	printk("raft_inetaddr_event:\n");
	switch (ev) {
	case NETDEV_UP:
		addr = kmalloc(sizeof(struct raft_sockaddr_entry), GFP_ATOMIC);
		if (addr) {
			addr->a.v4.sin_family = AF_INET;
			addr->a.v4.sin_port = 0;
			addr->a.v4.sin_addr.s_addr = ifa->ifa_local;
			addr->valid = 1;
			spin_lock_bh(&rn->local_addr_lock);
			list_add_tail_rcu(&addr->list, &rn->local_addr_list);
			raft_addr_wq_mgmt(net, addr, RAFT_ADDR_NEW);
			spin_unlock_bh(&rn->local_addr_lock);
		}
		break;
	case NETDEV_DOWN:
		spin_lock_bh(&rn->local_addr_lock);
		list_for_each_entry_safe(addr, temp,
					&rn->local_addr_list, list) {
			if (addr->a.sa.sa_family == AF_INET &&
					addr->a.v4.sin_addr.s_addr ==
					ifa->ifa_local) {
				raft_addr_wq_mgmt(net, addr, RAFT_ADDR_DEL);
				found = 1;
				addr->valid = 0;
				list_del_rcu(&addr->list);
				break;
			}
		}
		spin_unlock_bh(&rn->local_addr_lock);
		if (found)
			kfree_rcu(addr, rcu);
		break;
	}

	return NOTIFY_DONE;
}

static struct raft_af raft_af_inet;

static struct raft_pf raft_pf_inet = {
//	.event_msgname = sctp_inet_event_msgname,
//	.skb_msgname   = sctp_inet_skb_msgname,
//	.af_supported  = sctp_inet_af_supported,
//	.cmp_addr      = sctp_inet_cmp_addr,
//	.bind_verify   = sctp_inet_bind_verify,
//	.send_verify   = sctp_inet_send_verify,
//	.supported_addrs = sctp_inet_supported_addrs,
//	.create_accept_sk = sctp_v4_create_accept_sk,
//	.addr_to_user  = sctp_v4_addr_to_user,
//	.to_sk_saddr   = sctp_v4_to_sk_saddr,
//	.to_sk_daddr   = sctp_v4_to_sk_daddr,
	.af            = &raft_af_inet
};

/* Notifier for inetaddr addition/deletion events.  */
static struct notifier_block raft_inetaddr_notifier = {
	.notifier_call = raft_inetaddr_event,
};

/* Register address family specific functions. */
int raft_register_af(struct raft_af *af)
{
	switch (af->sa_family) {
	case AF_INET:
		if (raft_af_v4_specific)
			return 0;
		raft_af_v4_specific = af;
		break;
	case AF_INET6:
		if (raft_af_v6_specific)
			return 0;
		raft_af_v6_specific = af;
		break;
	default:
		return 0;
	}

	INIT_LIST_HEAD(&af->list);
	list_add_tail(&af->list, &raft_address_families);
	return 1;
}

/* Get the table of functions for manipulating a particular address
 * family.
 */
struct raft_af *raft_get_af_specific(sa_family_t family)
{
	switch (family) {
	case AF_INET:
		return raft_af_v4_specific;
	case AF_INET6:
		return raft_af_v6_specific;
	default:
		return NULL;
	}
}

static void raft_v4_pf_init(void)
{
	/* Initialize the SCTP specific PF functions. */
	raft_register_pf(&raft_pf_inet, PF_INET);
	raft_register_af(&raft_af_inet);
}

static void raft_v4_pf_exit(void)
{
	list_del(&raft_af_inet.list);
}

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
	struct raft_net *rn = raft_net(net);

	printk("raft_init_net: rn = %p\n", (void *)rn);
	INIT_LIST_HEAD(&rn->clusters);

	/* Initialize the local address list. */
	INIT_LIST_HEAD(&rn->local_addr_list);
	spin_lock_init(&rn->local_addr_lock);
	raft_get_local_addr_list(net);

	/* Initialize the address event list */
	INIT_LIST_HEAD(&rn->addr_waitq);
	INIT_LIST_HEAD(&rn->auto_asconf_splist);
	spin_lock_init(&rn->addr_wq_lock);
	rn->addr_wq_timer.expires = 0;
	setup_timer(&rn->addr_wq_timer, raft_addr_wq_timeout_handler,
		    (unsigned long)net);

	return 0;
}

static void __net_exit raft_exit_net(struct net *net)
{
	/* Free the local address list */
	raft_free_addr_wq(net);
	raft_free_local_addr_list(net);

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

	INIT_LIST_HEAD(&raft_address_families);
	raft_v4_pf_init();
//	raft_v6_pf_init();

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
//err_register_defaults:
	raft_v4_pf_exit();
//	sctp_v6_pf_exit();
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

	/* Free protosw registrations */
//	raft_v6_protosw_exit();
	raft_v4_protosw_exit();

	raft_netlink_stop();

	/* Unregister with socket layer. */
//	raft_v6_pf_exit();
	raft_v4_pf_exit();
}

module_init(raft_init);
module_exit(raft_exit);

MODULE_DESCRIPTION("Kernel support for the Raft Consensus Algrithm");
MODULE_LICENSE("GPL");
