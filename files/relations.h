/*
 * relations.h - The RAFT kernel module
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

#ifndef __raft_relations_h__
#define __raft_relations_h__

int raft_relations_add_node(struct net *net, struct raft_node *new_node);
int raft_relations_del_node(struct raft_node *node);
int raft_relations_change_node(struct net *net, struct raft_node *node, union raft_addr *new_addr, int local);

#endif /* __raft_relations_h__ */
