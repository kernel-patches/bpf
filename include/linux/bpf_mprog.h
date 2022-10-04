/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 Isovalent */
#ifndef __BPF_MPROG_H
#define __BPF_MPROG_H

#include <linux/bpf.h>

#define BPF_MPROG_MAX	64
#define BPF_MPROG_SWAP	1
#define BPF_MPROG_FREE	2

struct bpf_mprog_fp {
	struct bpf_prog *prog;
};

struct bpf_mprog_cp {
	struct bpf_link *link;
	u32 flags;
};

struct bpf_mprog_entry {
	struct bpf_mprog_fp fp_items[BPF_MPROG_MAX] ____cacheline_aligned;
	struct bpf_mprog_cp cp_items[BPF_MPROG_MAX] ____cacheline_aligned;
	struct bpf_mprog_bundle *parent;
};

struct bpf_mprog_bundle {
	struct bpf_mprog_entry a;
	struct bpf_mprog_entry b;
	struct rcu_head rcu;
	struct bpf_prog *ref;
	atomic_t revision;
};

struct bpf_tuple {
	struct bpf_prog *prog;
	struct bpf_link *link;
};

static inline struct bpf_mprog_entry *
bpf_mprog_peer(const struct bpf_mprog_entry *entry)
{
	if (entry == &entry->parent->a)
		return &entry->parent->b;
	else
		return &entry->parent->a;
}

#define bpf_mprog_foreach_tuple(entry, fp, cp, t)			\
	for (fp = &entry->fp_items[0], cp = &entry->cp_items[0];	\
	     ({								\
		t.prog = READ_ONCE(fp->prog);				\
		t.link = cp->link;					\
		t.prog;							\
	      });							\
	     fp++, cp++)

#define bpf_mprog_foreach_prog(entry, fp, p)				\
	for (fp = &entry->fp_items[0];					\
	     (p = READ_ONCE(fp->prog));					\
	     fp++)

static inline struct bpf_mprog_entry *bpf_mprog_create(size_t extra_size)
{
	struct bpf_mprog_bundle *bundle;

	/* Fast-path items are not extensible, must only contain prog pointer! */
	BUILD_BUG_ON(sizeof(bundle->a.fp_items[0]) > sizeof(u64));
	/* Control-path items can be extended w/o affecting fast-path. */
	BUILD_BUG_ON(ARRAY_SIZE(bundle->a.fp_items) != ARRAY_SIZE(bundle->a.cp_items));

	bundle = kzalloc(sizeof(*bundle) + extra_size, GFP_KERNEL);
	if (bundle) {
		atomic_set(&bundle->revision, 1);
		bundle->a.parent = bundle;
		bundle->b.parent = bundle;
		return &bundle->a;
	}
	return NULL;
}

static inline void bpf_mprog_free(struct bpf_mprog_entry *entry)
{
	kfree_rcu(entry->parent, rcu);
}

static inline void bpf_mprog_mark_ref(struct bpf_mprog_entry *entry,
				      struct bpf_prog *prog)
{
	WARN_ON_ONCE(entry->parent->ref);
	entry->parent->ref = prog;
}

static inline u32 bpf_mprog_flags(u32 cur_flags, u32 req_flags, u32 flag)
{
	if (req_flags & flag)
		cur_flags |= flag;
	else
		cur_flags &= ~flag;
	return cur_flags;
}

static inline u32 bpf_mprog_max(void)
{
	return ARRAY_SIZE(((struct bpf_mprog_entry *)NULL)->fp_items) - 1;
}

static inline struct bpf_prog *bpf_mprog_first(struct bpf_mprog_entry *entry)
{
	return READ_ONCE(entry->fp_items[0].prog);
}

static inline struct bpf_prog *bpf_mprog_last(struct bpf_mprog_entry *entry)
{
	struct bpf_prog *tmp, *prog = NULL;
	struct bpf_mprog_fp *fp;

	bpf_mprog_foreach_prog(entry, fp, tmp)
		prog = tmp;
	return prog;
}

static inline bool bpf_mprog_exists(struct bpf_mprog_entry *entry,
				    struct bpf_prog *prog)
{
	const struct bpf_mprog_fp *fp;
	const struct bpf_prog *tmp;

	bpf_mprog_foreach_prog(entry, fp, tmp) {
		if (tmp == prog)
			return true;
	}
	return false;
}

static inline struct bpf_prog *bpf_mprog_first_reg(struct bpf_mprog_entry *entry)
{
	struct bpf_tuple tuple = {};
	struct bpf_mprog_fp *fp;
	struct bpf_mprog_cp *cp;

	bpf_mprog_foreach_tuple(entry, fp, cp, tuple) {
		if (cp->flags & BPF_F_FIRST)
			continue;
		return tuple.prog;
	}
	return NULL;
}

static inline struct bpf_prog *bpf_mprog_last_reg(struct bpf_mprog_entry *entry)
{
	struct bpf_tuple tuple = {};
	struct bpf_prog *prog = NULL;
	struct bpf_mprog_fp *fp;
	struct bpf_mprog_cp *cp;

	bpf_mprog_foreach_tuple(entry, fp, cp, tuple) {
		if (cp->flags & BPF_F_LAST)
			break;
		prog = tuple.prog;
	}
	return prog;
}

static inline void bpf_mprog_commit(struct bpf_mprog_entry *entry)
{
	do {
		atomic_inc(&entry->parent->revision);
	} while (atomic_read(&entry->parent->revision) == 0);
	synchronize_rcu();
	if (entry->parent->ref) {
		bpf_prog_put(entry->parent->ref);
		entry->parent->ref = NULL;
	}
}

static inline void bpf_mprog_entry_clear(struct bpf_mprog_entry *entry)
{
	memset(entry->fp_items, 0, sizeof(entry->fp_items));
	memset(entry->cp_items, 0, sizeof(entry->cp_items));
}

static inline u64 bpf_mprog_revision(struct bpf_mprog_entry *entry)
{
	return atomic_read(&entry->parent->revision);
}

static inline void bpf_mprog_read(struct bpf_mprog_entry *entry, u32 which,
				  struct bpf_mprog_fp **fp_dst,
				  struct bpf_mprog_cp **cp_dst)
{
	*fp_dst = &entry->fp_items[which];
	*cp_dst = &entry->cp_items[which];
}

static inline void bpf_mprog_write(struct bpf_mprog_fp *fp_dst,
				   struct bpf_mprog_cp *cp_dst,
				   struct bpf_tuple *tuple, u32 flags)
{
	WRITE_ONCE(fp_dst->prog, tuple->prog);
	cp_dst->link  = tuple->link;
	cp_dst->flags = flags;
}

static inline void bpf_mprog_copy(struct bpf_mprog_fp *fp_dst,
				  struct bpf_mprog_cp *cp_dst,
				  struct bpf_mprog_fp *fp_src,
				  struct bpf_mprog_cp *cp_src)
{
	WRITE_ONCE(fp_dst->prog, READ_ONCE(fp_src->prog));
	memcpy(cp_dst, cp_src, sizeof(*cp_src));
}

static inline void bpf_mprog_copy_range(struct bpf_mprog_entry *peer,
					struct bpf_mprog_entry *entry,
					u32 idx_peer, u32 idx_entry, u32 num)
{
	memcpy(&peer->fp_items[idx_peer], &entry->fp_items[idx_entry],
	       num * sizeof(peer->fp_items[0]));
	memcpy(&peer->cp_items[idx_peer], &entry->cp_items[idx_entry],
	       num * sizeof(peer->cp_items[0]));
}

static inline u32 bpf_mprog_total(struct bpf_mprog_entry *entry)
{
	const struct bpf_mprog_fp *fp;
	const struct bpf_prog *tmp;
	u32 num = 0;

	bpf_mprog_foreach_prog(entry, fp, tmp)
		num++;
	return num;
}

int bpf_mprog_attach(struct bpf_mprog_entry *entry, struct bpf_prog *prog,
		     struct bpf_link *link, u32 flags, u32 object,
		     u32 expected_revision);
int bpf_mprog_detach(struct bpf_mprog_entry *entry, struct bpf_prog *prog,
		     struct bpf_link *link, u32 flags, u32 object,
		     u32 expected_revision);

int bpf_mprog_query(const union bpf_attr *attr, union bpf_attr __user *uattr,
		    struct bpf_mprog_entry *entry);

#endif /* __BPF_MPROG_H */
