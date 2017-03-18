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

/* A convenience structure for handling sockaddr structures.
 * We should wean ourselves off this.
 */
union raft_addr {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
	struct sockaddr sa;
};

/* Forward declarations for data structures. */
struct raft_globals;

/* The RAFT globals structure. */
extern struct raft_globals {
	/* This is a list of groups of functions for each address
	 * family that we support.
	 */
	struct list_head address_families;

	/* Flag to indicate whether computing and verifying checksum
	 * is disabled. */
        bool checksum_disable;
} raft_globals;

#define raft_checksum_disable		(raft_globals.checksum_disable)
#define raft_address_families		(raft_globals.address_families)

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

/*
 * Pointers to address related RAFT functions.
 * (i.e. things that depend on the address family.)
 */
struct raft_af {
//	int		(*raft_xmit)	(struct sk_buff *skb,
//					 struct raft_transport *);
	int		(*setsockopt)	(struct sock *sk,
					 int level,
					 int optname,
					 char __user *optval,
					 unsigned int optlen);
	int		(*getsockopt)	(struct sock *sk,
					 int level,
					 int optname,
					 char __user *optval,
					 int __user *optlen);
	int		(*compat_setsockopt)	(struct sock *sk,
					 int level,
					 int optname,
					 char __user *optval,
					 unsigned int optlen);
	int		(*compat_getsockopt)	(struct sock *sk,
					 int level,
					 int optname,
					 char __user *optval,
					 int __user *optlen);
//	void		(*get_dst)	(struct raft_transport *t,
//					 union raft_addr *saddr,
//					 struct flowi *fl,
//					 struct sock *sk);
//	void		(*get_saddr)	(struct raft_sock *sk,
//					 struct raft_transport *t,
//					 struct flowi *fl);
	void		(*copy_addrlist) (struct list_head *,
					  struct net_device *);
	int		(*cmp_addr)	(const union raft_addr *addr1,
					 const union raft_addr *addr2);
	void		(*addr_copy)	(union raft_addr *dst,
					 union raft_addr *src);
	void		(*from_skb)	(union raft_addr *,
					 struct sk_buff *skb,
					 int saddr);
	void		(*from_sk)	(union raft_addr *,
					 struct sock *sk);
//	void		(*from_addr_param) (union raft_addr *,
//					    union raft_addr_param *,
//					    __be16 port, int iif);
//	int		(*to_addr_param) (const union raft_addr *,
//					  union raft_addr_param *); 
	int		(*addr_valid)	(union raft_addr *,
					 struct raft_sock *,
					 const struct sk_buff *);
//	raft_scope_t	(*scope) (union raft_addr *);
	void		(*inaddr_any)	(union raft_addr *, __be16);
	int		(*is_any)	(const union raft_addr *);
	int		(*available)	(union raft_addr *,
					 struct raft_sock *);
	int		(*skb_iif)	(const struct sk_buff *sk);
	int		(*is_ce)	(const struct sk_buff *sk);
	void		(*seq_dump_addr)(struct seq_file *seq,
					 union raft_addr *addr);
	void		(*ecn_capable)(struct sock *sk);
	__u16		net_header_len;
	int		sockaddr_len;
	sa_family_t	sa_family;
	struct list_head list;
};

struct raft_af *raft_get_af_specific(sa_family_t);
int raft_register_af(struct raft_af *);

/* Protocol family functions. */
struct raft_pf {
//	void (*event_msgname)(struct sctp_ulpevent *, char *, int *);
//	void (*skb_msgname)  (struct sk_buff *, char *, int *);
//	int  (*af_supported) (sa_family_t, struct sctp_sock *);
//	int  (*cmp_addr) (const union sctp_addr *,
//			  const union sctp_addr *,
//			  struct sctp_sock *);
//	int  (*bind_verify) (struct sctp_sock *, union sctp_addr *);
//	int  (*send_verify) (struct sctp_sock *, union sctp_addr *);
//	int  (*supported_addrs)(const struct sctp_sock *, __be16 *);
//	struct sock *(*create_accept_sk) (struct sock *sk,
//					  struct sctp_association *asoc);
//	int (*addr_to_user)(struct sctp_sock *sk, union sctp_addr *addr);
//	void (*to_sk_saddr)(union sctp_addr *, struct sock *sk);
//	void (*to_sk_daddr)(union sctp_addr *, struct sock *sk);
	struct raft_af *af;
};

enum {
	RAFT_ADDR_NEW,		/* new address added to assoc/ep */
	RAFT_ADDR_SRC,		/* address can be used as source */
	RAFT_ADDR_DEL,		/* address about to be deleted */
};


/* This is a structure for holding either an IPv6 or an IPv4 address.  */
struct raft_sockaddr_entry {
	struct list_head list;
	struct rcu_head	rcu;
	union raft_addr a;
	__u8 state;
	__u8 valid;
};

#define RAFT_ADDRESS_TICK_DELAY	500

#endif /* __raft_structs_h__ */
