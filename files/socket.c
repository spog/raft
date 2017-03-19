/*
 * socket.c - The RAFT kernel module
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/hash.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <linux/time.h>
#include <linux/ip.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/compat.h>

#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/ipv6.h>
#include <net/inet_common.h>
#include <net/busy_poll.h>

#include <linux/socket.h> /* for sa_family_t */
#include <linux/export.h>
#include <net/sock.h>

#include "raft.h"

struct proto raft_prot = {
	.name		= "RAFT",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct raft_sock),
//	.sysctl_rmem	= sysctl_raft_rmem
};

/* Verify that this is a valid address. */
static inline int raft_verify_addr(struct sock *sk, union raft_addr *addr,
				   int len)
{
	struct raft_af *af;

#if 0
	/* Verify basic sockaddr. */
	af = raft_sockaddr_af(raft_sk(sk), addr, len);
	if (!af)
		return -EINVAL;

	/* Is this a valid SCTP address?  */
	if (!af->addr_valid(addr, sctp_sk(sk), NULL))
		return -EINVAL;

	if (!sctp_sk(sk)->pf->send_verify(sctp_sk(sk), (addr)))
		return -EINVAL;
#endif

	return 0;
}

/* set addr events to assocs in the endpoint.  ep and addr_wq must be locked */
int raft_asconf_mgmt(struct raft_sock *sp, struct raft_sockaddr_entry *addrw)
{
	struct sock *sk = raft_opt2sk(sp);
	union raft_addr *addr;
	struct raft_af *af;

	/* It is safe to write port space in caller. */
	addr = &addrw->a;
//	addr->v4.sin_port = htons(sp->ep->base.bind_addr.port);
	af = raft_get_af_specific(addr->sa.sa_family);
	if (!af)
		return -EINVAL;
	if (raft_verify_addr(sk, addr, af->sockaddr_len))
		return -EINVAL;

#if 0
	if (addrw->state == SCTP_ADDR_NEW)
		return sctp_send_asconf_add_ip(sk, (struct sockaddr *)addr, 1);
	else
		return sctp_send_asconf_del_ip(sk, (struct sockaddr *)addr, 1);
#else
	return 0;
#endif
}


