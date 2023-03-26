/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_ID_NS_H
#define _LINUX_BPF_ID_NS_H
#include <linux/types.h>
#include <linux/idr.h>
#include <linux/ns_common.h>
#include <linux/user_namespace.h>
#include <linux/capability.h>

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
extern spinlock_t map_idr_lock;
extern spinlock_t prog_idr_lock;
extern spinlock_t link_idr_lock;

struct bpf_namespace *copy_bpfns(unsigned long flags,
								struct user_namespace *user_ns,
								struct bpf_namespace *old_ns);
void put_bpfns(struct bpf_namespace *ns);
struct bpf_obj_id *bpf_alloc_obj_id(struct bpf_namespace *ns,
									void *obj, int type);
void bpf_free_obj_id(struct bpf_obj_id *obj_id, int type);

/*
 * The helpers to get the bpf_id's id seen from different namespaces
 *
 * bpf_id_nr()    : global id, i.e. the id seen from the init namespace;
 * bpf_id_vnr()   : virtual id, i.e. the id seen from the pid namespace of
 *                  current.
 * bpf_id_nr_ns() : id seen from the ns specified.
 *
 * see also task_xid_nr() etc in include/linux/sched.h
 */
static inline int bpf_obj_id_nr(struct bpf_obj_id *obj_id)
{
	if (obj_id)
		return obj_id->numbers[0].nr;
	return 0;
}

static inline int bpf_obj_id_nr_ns(struct bpf_obj_id *obj_id,
								   struct bpf_namespace *ns)
{
	if (obj_id && ns->level <= obj_id->level)
		return obj_id->numbers[ns->level].nr;
	return 0;
}

static inline int bpf_obj_id_vnr(struct bpf_obj_id *obj_id)
{
	return bpf_obj_id_nr_ns(obj_id, current->nsproxy->bpf_ns);
}

static inline bool bpfns_capable(void)
{
	if (current->nsproxy->bpf_ns != &init_bpf_ns && capable(CAP_BPF))
		return true;
	return false;
}
#endif /* _LINUX_BPF_ID_NS_H */
