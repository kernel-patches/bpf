// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */

#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/rcupdate.h>
#include <linux/ftrace.h>
#include <linux/rhashtable.h>
#include <linux/kfunc_md.h>

#include <uapi/linux/bpf.h>

#define MIN_KFUNC_MD_ARRAY_BITS 4
struct kfunc_md_array default_mds = {
	.used = ATOMIC_INIT(0),
	.hash_bits = MIN_KFUNC_MD_ARRAY_BITS,
	.mds = {
		[0 ... ((1 << MIN_KFUNC_MD_ARRAY_BITS) - 1)] = HLIST_HEAD_INIT,
	},
};
struct kfunc_md_array __rcu *kfunc_mds = &default_mds;
EXPORT_SYMBOL_GPL(kfunc_mds);

static DEFINE_MUTEX(kfunc_md_mutex);

static int kfunc_md_array_inc(void);

static void kfunc_md_release_rcu(struct rcu_head *rcu)
{
	struct kfunc_md *md;

	md = container_of(rcu, struct kfunc_md, rcu);
	/* Step 4, free the md */
	kfree(md);
}

static void kfunc_md_release_rcu_tasks(struct rcu_head *rcu)
{
	struct kfunc_md *md;

	md = container_of(rcu, struct kfunc_md, rcu);
	/* Step 3, wait for the nornal progs and bfp_global_caller to finish */
	call_rcu_tasks(&md->rcu, kfunc_md_release_rcu);
}

static void kfunc_md_release(struct percpu_ref *pcref)
{
	struct kfunc_md *md;

	md = container_of(pcref, struct kfunc_md, pcref);
	percpu_ref_exit(&md->pcref);

	/* Step 2, wait for sleepable progs to finish. */
	call_rcu_tasks_trace(&md->rcu, kfunc_md_release_rcu_tasks);
}

struct kfunc_md *kfunc_md_get(unsigned long ip)
{
	struct kfunc_md_array *mds;
	struct kfunc_md *md;

	rcu_read_lock();
	mds = rcu_dereference(kfunc_mds);
	md = __kfunc_md_get(mds, ip);
	rcu_read_unlock();

	return md;
}
EXPORT_SYMBOL_GPL(kfunc_md_get);

static struct kfunc_md *__kfunc_md_create(struct kfunc_md_array *mds, unsigned long ip,
					  int nr_args)
{
	struct kfunc_md *md = __kfunc_md_get(mds, ip);
	int err;

	if (md) {
		md->users++;
		return md;
	}

	md = kzalloc(sizeof(*md), GFP_KERNEL);
	if (!md)
		return NULL;

	md->users = 1;
	md->func = ip;
	md->nr_args = nr_args;

	err = percpu_ref_init(&md->pcref, kfunc_md_release, 0, GFP_KERNEL);
	if (err) {
		kfree(md);
		return NULL;
	}

	hlist_add_head_rcu(&md->hash, kfunc_md_hash_head(mds, ip));
	atomic_inc(&mds->used);

	return md;
}

struct kfunc_md *kfunc_md_create(unsigned long ip, int nr_args)
{
	struct kfunc_md *md = NULL;

	mutex_lock(&kfunc_md_mutex);

	if (kfunc_md_array_inc())
		goto out;

	md = __kfunc_md_create(kfunc_mds, ip, nr_args);
out:
	mutex_unlock(&kfunc_md_mutex);

	return md;
}
EXPORT_SYMBOL_GPL(kfunc_md_create);

static int kfunc_md_array_adjust(bool inc)
{
	struct kfunc_md_array *new_mds, *old_mds;
	struct kfunc_md *md, *new_md;
	struct hlist_node *n;
	int size, hash_bits, i;

	hash_bits = kfunc_mds->hash_bits;
	hash_bits += inc ? 1 : -1;

	size = sizeof(*new_mds) + sizeof(struct hlist_head) * (1 << hash_bits);
	new_mds = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
	if (!new_mds)
		return -ENOMEM;

	new_mds->hash_bits = hash_bits;
	for (i = 0; i < (1 << new_mds->hash_bits); i++)
		INIT_HLIST_HEAD(&new_mds->mds[i]);

	/* copy all the mds from kfunc_mds to new_mds */
	for (i = 0; i < (1 << kfunc_mds->hash_bits); i++) {
		hlist_for_each_entry(md, &kfunc_mds->mds[i], hash) {
			new_md = __kfunc_md_create(new_mds, md->func, md->nr_args);
			if (!new_md)
				goto err_out;

			new_md->bpf_prog_cnt = md->bpf_prog_cnt;
			new_md->bpf_origin_call = md->bpf_origin_call;
			new_md->users = md->users;

			memcpy(new_md->bpf_progs, md->bpf_progs, sizeof(md->bpf_progs));
		}
	}

	old_mds = kfunc_mds;
	rcu_assign_pointer(kfunc_mds, new_mds);
	synchronize_rcu();

	/* free all the mds in the old_mds. See kfunc_md_put() for the
	 * complete release process.
	 */
	for (i = 0; i < (1 << old_mds->hash_bits); i++) {
		hlist_for_each_entry_safe(md, n, &old_mds->mds[i], hash) {
			percpu_ref_kill(&md->pcref);
			hlist_del(&md->hash);
		}
	}

	if (old_mds != &default_mds)
		kfree_rcu(old_mds, rcu);

	return 0;

err_out:
	for (i = 0; i < (1 << new_mds->hash_bits); i++) {
		hlist_for_each_entry_safe(md, n, &new_mds->mds[i], hash) {
			percpu_ref_exit(&md->pcref);
			hlist_del(&md->hash);
			kfree(md);
		}
	}
	return -ENOMEM;
}

static int kfunc_md_array_inc(void)
{
	/* increase the hash table if greater than 90% */
	if (atomic_read(&kfunc_mds->used) * 10 < (1 << (kfunc_mds->hash_bits)) * 9)
		return 0;
	return kfunc_md_array_adjust(true);
}

static int kfunc_md_array_dec(void)
{
	/* decrease the hash table if less than 30%. */
	if (atomic_read(&kfunc_mds->used) * 10 > (1 << (kfunc_mds->hash_bits)) * 3)
		return 0;

	if (kfunc_mds->hash_bits <= MIN_KFUNC_MD_ARRAY_BITS)
		return 0;

	return kfunc_md_array_adjust(false);
}

void kfunc_md_put(struct kfunc_md *md)
{
	if (!md || WARN_ON_ONCE(md->users <= 0))
		return;

	mutex_lock(&kfunc_md_mutex);
	md->users--;
	if (md->users > 0)
		goto out_unlock;

	hlist_del_rcu(&md->hash);
	atomic_dec(&kfunc_mds->used);
	/* Step 1, use percpu_ref_kill to wait for the origin function to
	 * finish. See kfunc_md_release for step 2.
	 */
	percpu_ref_kill(&md->pcref);
	kfunc_md_array_dec();

out_unlock:
	mutex_unlock(&kfunc_md_mutex);
}
EXPORT_SYMBOL_GPL(kfunc_md_put);

static bool kfunc_md_bpf_check(struct kfunc_md *md, int nr_args)
{
	return md->bpf_prog_cnt && md->nr_args == nr_args;
}

int kfunc_md_bpf_ips(void ***ips_ptr, int nr_args)
{
	struct kfunc_md *md;
	int count, res = 0;
	void **ips;

	mutex_lock(&kfunc_md_mutex);
	count = atomic_read(&kfunc_mds->used);
	if (count <= 0)
		goto out_unlock;

	ips = kmalloc_array(count, sizeof(*ips), GFP_KERNEL);
	if (!ips) {
		res = -ENOMEM;
		goto out_unlock;
	}

	for (int j = 0; j < (1 << kfunc_mds->hash_bits); j++) {
		hlist_for_each_entry(md, &kfunc_mds->mds[j], hash) {
			if (kfunc_md_bpf_check(md, nr_args))
				ips[res++] = (void *)md->func;
		}
	}
	*ips_ptr = ips;

out_unlock:
	mutex_unlock(&kfunc_md_mutex);

	return res;
}

int kfunc_md_bpf_link(struct kfunc_md *md, struct bpf_prog *prog, int type,
		      u64 cookie)
{
	struct kfunc_md_tramp_prog *tramp_prog, **last;
	int err = 0;

	mutex_lock(&kfunc_md_mutex);
	tramp_prog = md->bpf_progs[type];
	/* check if the prog is already linked */
	while (tramp_prog) {
		if (tramp_prog->prog == prog) {
			err = -EEXIST;
			goto out_unlock;
		}
		tramp_prog = tramp_prog->next;
	}

	tramp_prog = kmalloc(sizeof(*tramp_prog), GFP_KERNEL);
	if (!tramp_prog) {
		err = -ENOMEM;
		goto out_unlock;
	}

	WRITE_ONCE(tramp_prog->prog, prog);
	WRITE_ONCE(tramp_prog->cookie, cookie);
	WRITE_ONCE(tramp_prog->next, NULL);

	/* add the new prog to the list tail */
	last = &md->bpf_progs[type];
	while (*last)
		last = &(*last)->next;

	WRITE_ONCE(*last, tramp_prog);

	md->bpf_prog_cnt++;
	if (type == BPF_TRAMP_FEXIT || type == BPF_TRAMP_MODIFY_RETURN)
		md->bpf_origin_call = true;

out_unlock:
	mutex_unlock(&kfunc_md_mutex);
	return err;
}

static void link_free_rcu(struct rcu_head *rcu)
{
	struct kfunc_md_tramp_prog *tramp_prog;

	tramp_prog = container_of(rcu, struct kfunc_md_tramp_prog, rcu);
	/* Step 3, free the tramp_prog */
	kfree(tramp_prog);
}

static void link_free_rcu_tasks(struct rcu_head *rcu)
{
	struct kfunc_md_tramp_prog *tramp_prog;

	tramp_prog = container_of(rcu, struct kfunc_md_tramp_prog, rcu);
	/* Step 2, wait for normal progs finish, which means all the progs
	 * in the list finished.
	 */
	call_rcu_tasks(&tramp_prog->rcu, link_free_rcu);
}

int kfunc_md_bpf_unlink(struct kfunc_md *md, struct bpf_prog *prog, int type)
{
	struct kfunc_md_tramp_prog *cur, **prev, **progs;

	mutex_lock(&kfunc_md_mutex);
	progs = md->bpf_progs;
	prev = progs + type;
	while (*prev && (*prev)->prog != prog)
		prev = &(*prev)->next;

	cur = *prev;
	if (!cur) {
		mutex_unlock(&kfunc_md_mutex);
		return -EINVAL;
	}

	WRITE_ONCE(*prev, cur->next);
	WRITE_ONCE(md->bpf_origin_call, progs[BPF_TRAMP_MODIFY_RETURN] ||
					progs[BPF_TRAMP_FEXIT]);

	md->bpf_prog_cnt--;

	/* Step 1, wait for sleepable progs to finish. */
	call_rcu_tasks_trace(&cur->rcu, link_free_rcu_tasks);
	mutex_unlock(&kfunc_md_mutex);

	return 0;
}
