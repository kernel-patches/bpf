/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KFUNC_MD_H
#define _LINUX_KFUNC_MD_H

#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/rhashtable.h>

struct kfunc_md_tramp_prog {
	struct kfunc_md_tramp_prog *next;
	struct bpf_prog *prog;
	u64 cookie;
	struct rcu_head rcu;
};

struct kfunc_md {
	struct hlist_node hash;
	struct rcu_head rcu;
	unsigned long func;
	struct kfunc_md_tramp_prog *bpf_progs[BPF_TRAMP_MAX];
	struct percpu_ref pcref;
	u16 users;
	bool bpf_origin_call;
	u8 bpf_prog_cnt;
	u8 nr_args;
};

struct kfunc_md_array {
	atomic_t used;
	struct rcu_head rcu;
	int hash_bits;
	struct hlist_head mds[];
};

extern struct kfunc_md_array __rcu *kfunc_mds;

struct kfunc_md *kfunc_md_create(unsigned long ip, int nr_args);
struct kfunc_md *kfunc_md_get(unsigned long ip);
void kfunc_md_put(struct kfunc_md *meta);
bool kfunc_md_arch_support(int *insn, int *data);

int kfunc_md_bpf_ips(void ***ips, int nr_args);
int kfunc_md_bpf_unlink(struct kfunc_md *md, struct bpf_prog *prog, int type);
int kfunc_md_bpf_link(struct kfunc_md *md, struct bpf_prog *prog, int type,
		      u64 cookie);

static __always_inline notrace struct hlist_head *
kfunc_md_hash_head(struct kfunc_md_array *mds, unsigned long ip)
{
	return &mds->mds[hash_ptr((void *)ip, mds->hash_bits)];
}

static __always_inline notrace struct kfunc_md *
__kfunc_md_get(struct kfunc_md_array *mds, unsigned long ip)
{
	struct hlist_head *head;
	struct kfunc_md *md;

	head = kfunc_md_hash_head(mds, ip);
	hlist_for_each_entry_rcu_notrace(md, head, hash) {
		if (md->func == ip)
			return md;
	}

	return NULL;
}

/* This function will be called in the bpf global trampoline, so it can't
 * be traced, and the "notrace" is necessary.
 */
static __always_inline notrace struct kfunc_md *kfunc_md_get_rcu(unsigned long ip)
{
	return __kfunc_md_get(rcu_dereference_raw(kfunc_mds), ip);
}

static __always_inline notrace void kfunc_md_enter(struct kfunc_md *md)
{
	percpu_ref_get(&md->pcref);
}

static __always_inline notrace void kfunc_md_exit(struct kfunc_md *md)
{
	percpu_ref_put(&md->pcref);
}

static inline void kfunc_md_put_ip(unsigned long ip)
{
	kfunc_md_put(kfunc_md_get(ip));
}

#endif
