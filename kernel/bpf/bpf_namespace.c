// SPDX-License-Identifier: GPL-2.0-only
#include <linux/ns_common.h>
#include <linux/syscalls.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/proc_ns.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/idr.h>
#include <linux/user_namespace.h>
#include <linux/bpf_namespace.h>

#define MAX_BPF_NS_LEVEL 32
static struct kmem_cache *bpfns_cachep;
static struct kmem_cache *obj_id_cache[MAX_PID_NS_LEVEL];
static struct ns_common *bpfns_get(struct task_struct *task);
static void bpfns_put(struct ns_common *ns);
static struct kmem_cache *create_bpf_cachep(unsigned int level);
static DEFINE_MUTEX(obj_id_caches_mutex);

static int bpfns_install(struct nsset *nsset, struct ns_common *ns)
{
	pr_info("setns not supported for bpf namespace");
	return -EOPNOTSUPP;
}

struct proc_ns_operations bpfns_operations = {
	.name = "bpf",
	.type = CLONE_NEWBPF,
	.get  = bpfns_get,
	.put  = bpfns_put,
	.install = bpfns_install,
};

struct bpf_namespace init_bpf_ns = {
	.level = 0,
	.user_ns = &init_user_ns,
	.ns.ops = &bpfns_operations,
	.ns.inum = PROC_BPF_INIT_INO,
};

static struct bpf_namespace *get_bpfns(struct bpf_namespace *ns)
{
	if (ns != &init_bpf_ns)
		refcount_inc(&ns->ns.count);
	return ns;
}

static struct ns_common *bpfns_get(struct task_struct *task)
{
	struct ns_common *ns = NULL;
	struct nsproxy *nsproxy;

	rcu_read_lock();
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = &nsproxy->bpf_ns->ns;
		get_bpfns(container_of(ns, struct bpf_namespace, ns));
	}
	rcu_read_unlock();
	return ns;
}

static struct ucounts *inc_bpf_namespaces(struct user_namespace *ns)
{
	return inc_ucount(ns, current_euid(), UCOUNT_BPF_NAMESPACES);
}

static void dec_bpf_namespaces(struct ucounts *ucounts)
{
	dec_ucount(ucounts, UCOUNT_BPF_NAMESPACES);
}

static void delayed_free_bpfns(struct rcu_head *p)
{
	struct bpf_namespace *ns = container_of(p, struct bpf_namespace, rcu);

	dec_bpf_namespaces(ns->ucounts);
	put_user_ns(ns->user_ns);
	kmem_cache_free(bpfns_cachep, ns);
}

static void destroy_bpf_namespace(struct bpf_namespace *ns)
{
	int i;

	ns_free_inum(&ns->ns);
	for (i = 0; i < OBJ_ID_NUM; i++)
		idr_destroy(&ns->idr[i]);
	call_rcu(&ns->rcu, delayed_free_bpfns);
}

void put_bpfns(struct bpf_namespace *ns)
{
	struct bpf_namespace *parent;

	while (ns != &init_bpf_ns) {
		parent = ns->parent;
		if (!refcount_dec_and_test(&ns->ns.count))
			break;
		destroy_bpf_namespace(ns);
		ns = parent;
	}
}

static void bpfns_put(struct ns_common *ns)
{
	struct bpf_namespace *bpf_ns;

	bpf_ns = container_of(ns, struct bpf_namespace, ns);
	put_bpfns(bpf_ns);
}

static struct bpf_namespace *
create_bpf_namespace(struct user_namespace *user_ns,
						struct bpf_namespace *parent_bpfns)
{
	struct bpf_namespace *ns;
	unsigned int level = parent_bpfns->level + 1;
	struct ucounts *ucounts;
	int err;
	int i;

	err = -EINVAL;
	if (!in_userns(parent_bpfns->user_ns, user_ns))
		goto out;

	err = -ENOSPC;
	if (level > MAX_BPF_NS_LEVEL)
		goto out;
	ucounts = inc_bpf_namespaces(user_ns);
	if (!ucounts)
		goto out;

	err = -ENOMEM;
	ns = kmem_cache_zalloc(bpfns_cachep, GFP_KERNEL);
	if (!ns)
		goto out_dec;

	for (i = 0; i < OBJ_ID_NUM; i++)
		idr_init(&ns->idr[i]);

	ns->obj_id_cachep = create_bpf_cachep(level);
	if (!ns->obj_id_cachep)
		goto out_free_idr;

	err = ns_alloc_inum(&ns->ns);
	if (err)
		goto out_free_idr;
	ns->ns.ops = &bpfns_operations;

	refcount_set(&ns->ns.count, 1);
	ns->level = level;
	ns->parent = get_bpfns(parent_bpfns);
	ns->user_ns = get_user_ns(user_ns);
	ns->ucounts = ucounts;
	return ns;

out_free_idr:
	for (i = 0; i < OBJ_ID_NUM; i++)
		idr_destroy(&ns->idr[i]);
	kmem_cache_free(bpfns_cachep, ns);
out_dec:
	dec_bpf_namespaces(ucounts);
out:
	return ERR_PTR(err);
}

struct bpf_namespace *copy_bpfns(unsigned long flags,
								 struct user_namespace *user_ns,
								 struct bpf_namespace *old_ns)
{
	if (!(flags & CLONE_NEWBPF))
		return get_bpfns(old_ns);
	return create_bpf_namespace(user_ns, old_ns);
}

static struct kmem_cache *create_bpf_cachep(unsigned int level)
{
	/* Level 0 is init_bpf_ns.obj_id_cachep */
	struct kmem_cache **pkc = &obj_id_cache[level - 1];
	struct kmem_cache *kc;
	char name[4 + 10 + 1];
	unsigned int len;

	kc = READ_ONCE(*pkc);
	if (kc)
		return kc;

	snprintf(name, sizeof(name), "bpf_%u", level + 1);
	len = sizeof(struct bpf_obj_id) + level * sizeof(struct ubpf_obj_id);
	mutex_lock(&obj_id_caches_mutex);
	/* Name collision forces to do allocation under mutex. */
	if (!*pkc)
		*pkc = kmem_cache_create(name, len, 0,
					 SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT, NULL);
	mutex_unlock(&obj_id_caches_mutex);
	/* current can fail, but someone else can succeed. */
	return READ_ONCE(*pkc);
}

static void __init bpfns_idr_init(void)
{
	int i;

	init_bpf_ns.obj_id_cachep =
		KMEM_CACHE(pid, SLAB_HWCACHE_ALIGN | SLAB_PANIC | SLAB_ACCOUNT);
	for (i = 0; i < OBJ_ID_NUM; i++)
		idr_init(&init_bpf_ns.idr[i]);
}

static __init int bpf_namespaces_init(void)
{
	bpfns_cachep = KMEM_CACHE(bpf_namespace, SLAB_PANIC | SLAB_ACCOUNT);
	bpfns_idr_init();
	return 0;
}

late_initcall(bpf_namespaces_init);
