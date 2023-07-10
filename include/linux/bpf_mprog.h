/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 Isovalent */
#ifndef __BPF_MPROG_H
#define __BPF_MPROG_H

#include <linux/bpf.h>

/* bpf_mprog framework:
 * ~~~~~~~~~~~~~~~~~~~~
 *
 * bpf_mprog is a generic layer for multi-program attachment. In-kernel users
 * of the bpf_mprog don't need to care about the dependency resolution
 * internals, they can just consume it with few API calls. Currently available
 * dependency directives are BPF_F_{BEFORE,AFTER} which enable insertion of
 * a BPF program or BPF link relative to an existing BPF program or BPF link
 * inside the multi-program array as well as prepend and append behavior if
 * no relative object was specified, see corresponding selftests for concrete
 * examples (e.g. tc_links and tc_opts test cases of test_progs).
 *
 * Usage of bpf_mprog_{attach,detach,query}() core APIs with pseudo code:
 *
 *  Attach case:
 *
 *   struct bpf_mprog_entry *entry, *peer;
 *   int ret;
 *
 *   // bpf_mprog user-side lock
 *   // fetch active @entry from attach location
 *   [...]
 *   ret = bpf_mprog_attach(entry, [...]);
 *   if (ret >= 0) {
 *       peer = bpf_mprog_peer(entry);
 *       if (bpf_mprog_swap_entries(ret))
 *           // swap @entry to @peer at attach location
 *       bpf_mprog_commit(entry);
 *       ret = 0;
 *   } else {
 *       // error path, bail out, propagate @ret
 *   }
 *   // bpf_mprog user-side unlock
 *
 *  Detach case:
 *
 *   struct bpf_mprog_entry *entry, *peer;
 *   bool release;
 *   int ret;
 *
 *   // bpf_mprog user-side lock
 *   // fetch active @entry from attach location
 *   [...]
 *   ret = bpf_mprog_detach(entry, [...]);
 *   if (ret >= 0) {
 *       release = ret == BPF_MPROG_FREE;
 *       peer = release ? NULL : bpf_mprog_peer(entry);
 *       if (bpf_mprog_swap_entries(ret))
 *           // swap @entry to @peer at attach location
 *       bpf_mprog_commit(entry);
 *       if (release)
 *           // free bpf_mprog_bundle
 *       ret = 0;
 *   } else {
 *       // error path, bail out, propagate @ret
 *   }
 *   // bpf_mprog user-side unlock
 *
 *  Query case:
 *
 *   struct bpf_mprog_entry *entry;
 *   int ret;
 *
 *   // bpf_mprog user-side lock
 *   // fetch active @entry from attach location
 *   [...]
 *   ret = bpf_mprog_query(attr, uattr, entry);
 *   // bpf_mprog user-side unlock
 *
 *  Data/fast path:
 *
 *   struct bpf_mprog_entry *entry;
 *   struct bpf_mprog_fp *fp;
 *   struct bpf_prog *prog;
 *   int ret = [...];
 *
 *   rcu_read_lock();
 *   // fetch active @entry from attach location
 *   [...]
 *   bpf_mprog_foreach_prog(entry, fp, prog) {
 *       ret = bpf_prog_run(prog, [...]);
 *       // process @ret from program
 *   }
 *   [...]
 *   rcu_read_unlock();
 *
 * bpf_mprog_{attach,detach}() return codes:
 *
 * Negative return code means that an error occurred and the bpf_mprog_entry
 * has not been changed. The error should be propagated to the user. A non-
 * negative return code can be one of the following:
 *
 * BPF_MPROG_KEEP:
 *   The bpf_mprog_entry does not need a/b swap, the bpf_mprog_fp item has
 *   been replaced in the current active bpf_mprog_entry.
 *
 * BPF_MPROG_SWAP:
 *   The bpf_mprog_entry does need an a/b swap and must be updated to its
 *   peer entry (peer = bpf_mprog_peer(entry)) which has been populated to
 *   the new bpf_mprog_fp item configuration.
 *
 * BPF_MPROG_FREE:
 *   The bpf_mprog_entry now does not hold any non-NULL bpf_mprog_fp items
 *   anymore. The bpf_mprog_entry should be swapped with NULL and the
 *   corresponding bpf_mprog_bundle can be freed.
 *
 * bpf_mprog locking considerations:
 *
 * bpf_mprog_{attach,detach,query}() must be protected by an external lock
 * (like RTNL in case of tcx).
 *
 * bpf_mprog_entry pointer can be an __rcu annotated pointer (in case of tcx
 * the netdevice has tcx_ingress and tcx_egress __rcu pointer) which gets
 * updated via rcu_assign_pointer() pointing to the active bpf_mprog_entry of
 * the bpf_mprog_bundle.
 *
 * Fast path accesses the active bpf_mprog_entry within RCU critical section
 * (in case of tcx it runs in NAPI which provides RCU protection there,
 * other users might need explicit rcu_read_lock()). The bpf_mprog_commit()
 * assumes that RCU protection.
 *
 * The READ_ONCE()/WRITE_ONCE() pairing for bpf_mprog_fp's prog access is for
 * the replacement case where we don't swap the bpf_mprog_entry.
 */

#define BPF_MPROG_KEEP	0
#define BPF_MPROG_SWAP	1
#define BPF_MPROG_FREE	2

#define BPF_MPROG_MAX	64

#define bpf_mprog_foreach_tuple(entry, fp, cp, t)			\
	for (fp = &entry->fp_items[0], cp = &entry->parent->cp_items[0];\
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

struct bpf_mprog_fp {
	struct bpf_prog *prog;
};

struct bpf_mprog_cp {
	struct bpf_link *link;
};

struct bpf_mprog_entry {
	struct bpf_mprog_fp fp_items[BPF_MPROG_MAX];
	struct bpf_mprog_bundle *parent;
};

struct bpf_mprog_bundle {
	struct bpf_mprog_entry a;
	struct bpf_mprog_entry b;
	struct bpf_mprog_cp cp_items[BPF_MPROG_MAX];
	struct bpf_prog *ref;
	atomic64_t revision;
	u32 count;
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

static inline void bpf_mprog_bundle_init(struct bpf_mprog_bundle *bundle)
{
	BUILD_BUG_ON(sizeof(bundle->a.fp_items[0]) > sizeof(u64));
	BUILD_BUG_ON(ARRAY_SIZE(bundle->a.fp_items) !=
		     ARRAY_SIZE(bundle->cp_items));

	memset(bundle, 0, sizeof(*bundle));
	atomic64_set(&bundle->revision, 1);
	bundle->a.parent = bundle;
	bundle->b.parent = bundle;
}

static inline void bpf_mprog_inc(struct bpf_mprog_entry *entry)
{
	entry->parent->count++;
}

static inline void bpf_mprog_dec(struct bpf_mprog_entry *entry)
{
	entry->parent->count--;
}

static inline int bpf_mprog_max(void)
{
	return ARRAY_SIZE(((struct bpf_mprog_entry *)NULL)->fp_items) - 1;
}

static inline int bpf_mprog_total(struct bpf_mprog_entry *entry)
{
	int total = entry->parent->count;

	WARN_ON_ONCE(total > bpf_mprog_max());
	return total;
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

static inline bool bpf_mprog_swap_entries(const int code)
{
	return code == BPF_MPROG_SWAP ||
	       code == BPF_MPROG_FREE;
}

static inline void bpf_mprog_mark_ref(struct bpf_mprog_entry *entry,
				      struct bpf_tuple *tuple)
{
	WARN_ON_ONCE(entry->parent->ref);
	if (!tuple->link)
		entry->parent->ref = tuple->prog;
}

static inline void bpf_mprog_commit(struct bpf_mprog_entry *entry)
{
	atomic64_inc(&entry->parent->revision);
	/* bpf_mprog_entry got a/b swapped or prog replacement occurred
	 * on the active bpf_mprog_entry. Ensure there are no inflight
	 * users.
	 */
	synchronize_rcu();
	/* bpf_mprog_delete() marked plain prog via bpf_mprog_mark_ref()
	 * where its reference needs to be dropped after the RCU sync.
	 */
	if (entry->parent->ref) {
		bpf_prog_put(entry->parent->ref);
		entry->parent->ref = NULL;
	}
}

static inline u64 bpf_mprog_revision(struct bpf_mprog_entry *entry)
{
	return atomic64_read(&entry->parent->revision);
}

static inline void bpf_mprog_entry_clear(struct bpf_mprog_entry *entry)
{
	memset(entry->fp_items, 0, sizeof(entry->fp_items));
}

static inline void bpf_mprog_commit_cp(struct bpf_mprog_entry *entry,
				       struct bpf_mprog_cp *cp_items)
{
	memcpy(entry->parent->cp_items, cp_items,
	       sizeof(entry->parent->cp_items));
}

static inline void bpf_mprog_read_fp(struct bpf_mprog_entry *entry, u32 idx,
				     struct bpf_mprog_fp **fp)
{
	*fp = &entry->fp_items[idx];
}

static inline void bpf_mprog_read_cp(struct bpf_mprog_entry *entry, u32 idx,
				     struct bpf_mprog_cp **cp)
{
	*cp = &entry->parent->cp_items[idx];
}

static inline void bpf_mprog_read(struct bpf_mprog_entry *entry, u32 idx,
				  struct bpf_mprog_fp **fp,
				  struct bpf_mprog_cp **cp)
{
	bpf_mprog_read_fp(entry, idx, fp);
	bpf_mprog_read_cp(entry, idx, cp);
}

static inline void bpf_mprog_write_fp(struct bpf_mprog_fp *fp,
				      struct bpf_tuple *tuple)
{
	WRITE_ONCE(fp->prog, tuple->prog);
}

static inline void bpf_mprog_write_cp(struct bpf_mprog_cp *cp,
				      struct bpf_tuple *tuple)
{
	cp->link = tuple->link;
}

static inline void bpf_mprog_write(struct bpf_mprog_fp *fp,
				   struct bpf_mprog_cp *cp,
				   struct bpf_tuple *tuple)
{
	bpf_mprog_write_fp(fp, tuple);
	bpf_mprog_write_cp(cp, tuple);
}

static inline void bpf_mprog_copy(struct bpf_mprog_fp *fp_dst,
				  struct bpf_mprog_cp *cp_dst,
				  struct bpf_mprog_fp *fp_src,
				  struct bpf_mprog_cp *cp_src)
{
	WRITE_ONCE(fp_dst->prog, READ_ONCE(fp_src->prog));
	memcpy(cp_dst, cp_src, sizeof(*cp_src));
}

int bpf_mprog_attach(struct bpf_mprog_entry *entry, struct bpf_prog *prog_new,
		     struct bpf_link *link, struct bpf_prog *prog_old,
		     u32 flags, u32 object, u64 revision);
int bpf_mprog_detach(struct bpf_mprog_entry *entry, struct bpf_prog *prog,
		     struct bpf_link *link, u32 flags, u32 object, u64 revision);

int bpf_mprog_query(const union bpf_attr *attr, union bpf_attr __user *uattr,
		    struct bpf_mprog_entry *entry);

#endif /* __BPF_MPROG_H */
