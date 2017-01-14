/*
 * raft_netlink.h - The RAFT kernel module
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

#ifndef __raft_raft_netlink_h__
#define __raft_raft_netlink_h__

#define RAFT_GENL_V2_NAME      "RAFTv2"
#define RAFT_GENL_V2_VERSION   0x1

/* Netlink commands */
enum {
	RAFT_NL_UNSPEC,
	RAFT_NL_CLUSTER_ADD,
	RAFT_NL_CLUSTER_DEL,
	RAFT_NL_DOMAIN_ADD,
	RAFT_NL_DOMAIN_DEL,
	RAFT_NL_NODE_ADD,
	RAFT_NL_NODE_DEL,

	__RAFT_NL_CMD_MAX,
	RAFT_NL_CMD_MAX = __RAFT_NL_CMD_MAX - 1
};

/* Top level netlink attributes */
enum {
	RAFT_NLA_UNSPEC,
	RAFT_NLA_CLUSTER,		/* nest */
	RAFT_NLA_DOMAIN,		/* nest */
	RAFT_NLA_NODE,			/* nest */

	__RAFT_NLA_MAX,
	RAFT_NLA_MAX = __RAFT_NLA_MAX - 1
};

/* Cluster info */
enum {
	RAFT_NLA_CLUSTER_UNSPEC,
	RAFT_NLA_CLUSTER_ID,		/* u32 */

	__RAFT_NLA_CLUSTER_MAX,
	RAFT_NLA_CLUSTER_MAX = __RAFT_NLA_CLUSTER_MAX - 1
};

/* Domain info */
enum {
	RAFT_NLA_DOMAIN_UNSPEC,
	RAFT_NLA_DOMAIN_ID,		/* u32 */
	RAFT_NLA_DOMAIN_HEARTBEAT,	/* u32 */
	RAFT_NLA_DOMAIN_ELECTION,	/* u32 */
	RAFT_NLA_DOMAIN_MAXNODES,	/* u32 */

	__RAFT_NLA_DOMAIN_MAX,
	RAFT_NLA_DOMAIN_MAX = __RAFT_NLA_DOMAIN_MAX - 1
};

/* Node info */
enum {
	RAFT_NLA_NODE_UNSPEC,
	RAFT_NLA_NODE_ID,		/* u32 */
	RAFT_NLA_NODE_CONTACT,		/* sockaddr_storage */
	RAFT_NLA_NODE_UP,		/* flag */

	__RAFT_NLA_NODE_MAX,
	RAFT_NLA_NODE_MAX = __RAFT_NLA_NODE_MAX - 1
};

#endif /* __raft_raft_netlink_h__ */

