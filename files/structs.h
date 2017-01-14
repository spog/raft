/*
 * structs.h - The RAFT kernel module
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

#ifndef __raft_structs_h__
#define __raft_structs_h__

/* The RAFT globals structure. */
extern struct raft_globals {
	/* Flag to indicate whether computing and verifying checksum
	 * is disabled. */
        bool checksum_disable;
} raft_globals;

#define raft_checksum_disable		(raft_globals.checksum_disable)

/* Per socket RAFT information. */
struct raft_sock {
	/* inet_sock has to be the first member of raft_sock */
	struct inet_sock inet;

	/* What is our base endpointer? */
	struct raft_endpoint *ep;

	/* Heartbeat interval: The endpoint sends out a Heartbeat chunk to
	 * the destination address every heartbeat interval. This value
	 * will be inherited by all new associations.
	 */
	__u32 hbinterval;

	/* Flags controlling Heartbeat, SACK delay, and Path MTU Discovery. */
	__u32 param_flags;
};

struct raft_endpoint {
	/* This is really a list of struct raft_association entries. */
	struct list_head asocs;
};

#endif /* __raft_structs_h__ */
