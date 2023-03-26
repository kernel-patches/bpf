/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_ID_NS_H
#define _LINUX_BPF_ID_NS_H
#include <linux/types.h>
#include <linux/idr.h>
#include <linux/ns_common.h>
#include <linux/user_namespace.h>

struct ubpf_obj_id {
	int nr;
	struct bpf_namespace *ns;
};

struct bpf_obj_id {
	refcount_t count;
	unsigned int level;
	struct rcu_head rcu;
	struct ubpf_obj_id numbers[1];
};

enum {
	MAP_OBJ_ID = 0,
	PROG_OBJ_ID,
	LINK_OBJ_ID,
	OBJ_ID_NUM,
};

struct bpf_namespace {
	struct idr idr[OBJ_ID_NUM];
	struct rcu_head rcu;
	int level;
	struct ns_common ns;
	struct user_namespace *user_ns;
	struct kmem_cache *obj_id_cachep;
	struct bpf_namespace *parent;
	struct ucounts *ucounts;
};

extern struct bpf_namespace init_bpf_ns;
extern struct proc_ns_operations bpfns_operations;

struct bpf_namespace *copy_bpfns(unsigned long flags,
								struct user_namespace *user_ns,
								struct bpf_namespace *old_ns);
void put_bpfns(struct bpf_namespace *ns);
#endif /* _LINUX_BPF_ID_NS_H */
