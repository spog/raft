/*
 * netlink.h - The RAFT kernel module
 * Copyright (c) 2017 Samo Pogacnik
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

#ifndef __raft_netlink_h__
#define __raft_netlink_h__

#include <net/netlink.h>

#include "raft_netlink.h"

extern struct genl_family raft_genl_family;
int raft_nlmsg_parse(const struct nlmsghdr *nlh, struct nlattr ***buf);

struct raft_nl_msg {
	struct sk_buff *skb;
	u32 portid;
	u32 seq;
};

extern const struct nla_policy raft_nl_cluster_policy[];
extern const struct nla_policy raft_nl_domain_policy[];
extern const struct nla_policy raft_nl_node_policy[];

int raft_netlink_start(void);
void raft_netlink_stop(void);

#endif /* __raft_netlink_h__ */
