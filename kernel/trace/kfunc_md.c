// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */

#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/rcupdate.h>
#include <linux/ftrace.h>
#include <linux/kfunc_md.h>

#include <uapi/linux/bpf.h>

#ifndef CONFIG_FUNCTION_METADATA_PADDING

DEFINE_STATIC_KEY_TRUE(kfunc_md_use_padding);
static int __insn_offset, __data_offset;
#define insn_offset	__insn_offset
#define data_offset	__data_offset

#define KFUNC_MD_HASH_BITS	10
static struct hlist_head kfunc_md_table[1 << KFUNC_MD_HASH_BITS];

#else
#define insn_offset	KFUNC_MD_INSN_OFFSET
#define data_offset	KFUNC_MD_DATA_OFFSET
#endif

#define insn_size	KFUNC_MD_INSN_SIZE

#define ENTRIES_PER_PAGE (PAGE_SIZE / sizeof(struct kfunc_md))

#define KFUNC_MD_ARRAY_FL_DEAD 0

struct kfunc_md_array {
	struct kfunc_md *mds;
	u32 kfunc_md_count;
	unsigned long flags;
	atomic_t kfunc_md_used;
	union {
		struct work_struct work;
		struct rcu_head rcu;
	};
};

static struct kfunc_md_array empty_array = {
	.mds = NULL,
	.kfunc_md_count = 0,
};
/* used for the padding-based function metadata */
static struct kfunc_md_array __rcu *kfunc_mds = &empty_array;

/* any function metadata write should hold this lock */
static DEFINE_MUTEX(kfunc_md_mutex);


#ifndef CONFIG_FUNCTION_METADATA_PADDING

static struct hlist_head *kfunc_md_hash_head(unsigned long ip)
{
	return &kfunc_md_table[hash_ptr((void *)ip, KFUNC_MD_HASH_BITS)];
}

static struct kfunc_md *kfunc_md_hash_get(unsigned long ip)
{
	struct hlist_head *head;
	struct kfunc_md *md;

	head = kfunc_md_hash_head(ip);
	hlist_for_each_entry_rcu_notrace(md, head, hash) {
		if (md->func == ip)
			return md;
	}

	return NULL;
}

static void kfunc_md_hash_release(struct percpu_ref *pcref)
{
	struct kfunc_md *md;

	md = container_of(pcref, struct kfunc_md, pcref);
	kfree_rcu(md, rcu);
}

static struct kfunc_md *kfunc_md_hash_create(unsigned long ip, int nr_args)
{
	struct kfunc_md *md = kfunc_md_hash_get(ip);
	struct hlist_head *head;
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

	err = percpu_ref_init(&md->pcref, kfunc_md_hash_release, 0, GFP_KERNEL);
	if (err) {
		kfree(md);
		return NULL;
	}

	head = kfunc_md_hash_head(ip);
	hlist_add_tail_rcu(&md->hash, head);
	atomic_inc(&kfunc_mds->kfunc_md_used);

	return md;
}

static void kfunc_md_hash_put(struct kfunc_md *md)
{
	if (WARN_ON_ONCE(md->users <= 0))
		return;

	md->users--;
	if (md->users > 0)
		return;

	hlist_del_rcu(&md->hash);
	percpu_ref_kill(&md->pcref);
	atomic_dec(&kfunc_mds->kfunc_md_used);
}

static bool kfunc_md_fast(void)
{
	return static_branch_likely(&kfunc_md_use_padding);
}

static int kfunc_md_hash_bpf_ips(void **ips)
{
	struct hlist_head *head;
	struct kfunc_md *md;
	int c = 0, i;

	for (i = 0; i < (1 << KFUNC_MD_HASH_BITS); i++) {
		head = &kfunc_md_table[i];
		hlist_for_each_entry(md, head, hash) {
			if (md->bpf_prog_cnt > !!(md->flags & KFUNC_MD_FL_BPF_REMOVING) &&
			    !md->tramp)
				ips[c++] = (void *)md->func;
		}
	}

	return c;
}
#else

static void kfunc_md_hash_put(struct kfunc_md *md)
{
}

static struct kfunc_md *kfunc_md_hash_get(unsigned long ip)
{
	return NULL;
}

static struct kfunc_md *kfunc_md_hash_create(unsigned long ip, int nr_args)
{
	return NULL;
}

#define kfunc_md_fast() 1

static int kfunc_md_hash_bpf_ips(void **ips)
{
	return 0;
}
#endif /* CONFIG_FUNCTION_METADATA_PADDING */

#ifdef CONFIG_FUNCTION_METADATA
static void kfunc_md_release(struct percpu_ref *pcref);

static __always_inline u32 kfunc_md_get_index(unsigned long ip)
{
	return *(u32 *)(ip - data_offset);
}

static struct kfunc_md_array *kfunc_md_array_alloc(struct kfunc_md_array *old)
{
	struct kfunc_md_array *new_mds;
	int len = old->kfunc_md_count;
	struct kfunc_md *md;
	int err, i;

	new_mds = kmalloc(sizeof(*new_mds), __GFP_ZERO | GFP_KERNEL);
	if (!new_mds)
		return NULL;

	/* if the length of old kfunc md array is zero, we make ENTRIES_PER_PAGE
	 * as the default size of the new kfunc md array.
	 */
	new_mds->kfunc_md_count = (len * 2) ?: ENTRIES_PER_PAGE;
	new_mds->mds = kvmalloc_array(new_mds->kfunc_md_count, sizeof(*new_mds->mds),
				      __GFP_ZERO | GFP_KERNEL);
	if (!new_mds->mds) {
		kfree(new_mds);
		return NULL;
	}

	if (len) {
		memcpy(new_mds->mds, old->mds, sizeof(*new_mds->mds) * len);
		new_mds->kfunc_md_used = old->kfunc_md_used;
	}

	for (i = 0; i < new_mds->kfunc_md_count; i++) {
		md = &new_mds->mds[i];

		if (md->users) {
			err = percpu_ref_init(&md->pcref, kfunc_md_release,
					      0, GFP_KERNEL);
			if (err)
				goto pcref_fail;
			md->array = new_mds;
		}
	}

	return new_mds;

pcref_fail:
	for (int j = 0; j < i; j++) {
		md = &new_mds->mds[j];
		if (md->users)
			percpu_ref_exit(&md->pcref);
	}
	kvfree(new_mds->mds);
	kfree(new_mds);
	return NULL;
}

static void kfunc_md_array_release_deferred(struct work_struct *work)
{
	struct kfunc_md_array *mds;

	mds = container_of(work, struct kfunc_md_array, work);
	/* the kfunc metadata array is not used anywhere, we can free it
	 * directly.
	 */
	if (atomic_read(&mds->kfunc_md_used) == 0) {
		for (int i = 0; i < mds->kfunc_md_count; i++) {
			if (mds->mds[i].users)
				percpu_ref_exit(&mds->mds[i].pcref);
		}

		kvfree(mds->mds);
		kfree_rcu(mds, rcu);
		return;
	}

	for (int i = 0; i < mds->kfunc_md_count; i++) {
		if (mds->mds[i].users)
			percpu_ref_kill(&mds->mds[i].pcref);
	}
}

static void kfunc_md_array_release(struct rcu_head *rcu)
{
	struct kfunc_md_array *mds;

	mds = container_of(rcu, struct kfunc_md_array, rcu);
	if (mds == &empty_array)
		return;

	INIT_WORK(&mds->work, kfunc_md_array_release_deferred);
	schedule_work(&mds->work);
}

static void kfunc_md_release(struct percpu_ref *pcref)
{
	struct kfunc_md *md;

	md = container_of(pcref, struct kfunc_md, pcref);
	if (test_bit(KFUNC_MD_ARRAY_FL_DEAD, &md->array->flags)) {
		if (atomic_dec_and_test(&md->array->kfunc_md_used)) {
			call_rcu_tasks(&md->array->rcu, kfunc_md_array_release);
			return;
		}
	}
	percpu_ref_exit(&md->pcref);
	/* clear the flags, so it can be reused */
	md->flags = 0;
}

static int kfunc_md_text_poke(unsigned long ip, void *insn, void *nop)
{
	void *target;
	int ret = 0;
	u8 *prog;

	target = (void *)(ip - insn_offset);
	mutex_lock(&text_mutex);
	if (insn) {
		if (!memcmp(target, insn, insn_size))
			goto out;

		if (memcmp(target, nop, insn_size)) {
			ret = -EBUSY;
			goto out;
		}
		prog = insn;
	} else {
		if (!memcmp(target, nop, insn_size))
			goto out;
		prog = nop;
	}

	ret = kfunc_md_arch_poke(target, prog, insn_offset);
out:
	mutex_unlock(&text_mutex);
	return ret;
}

/* Get next usable function metadata. On success, return the usable
 * kfunc_md and store the index of it to *index. If no usable kfunc_md is
 * found in kfunc_mds, a larger array will be allocated.
 */
static struct kfunc_md *kfunc_md_fast_next(u32 *index)
{
	struct kfunc_md_array *mds, *new_mds;
	struct kfunc_md *md;
	u32 i;

	mds = kfunc_mds;
do_retry:
	if (likely(atomic_read(&mds->kfunc_md_used) < mds->kfunc_md_count)) {
		/* maybe we can manage the used function metadata entry
		 * with a bit map ?
		 */
		for (i = 0; i < mds->kfunc_md_count; i++) {
			md = &mds->mds[i];
			if (!md->users && !(md->flags & KFUNC_MD_FL_DEAD)) {
				atomic_inc(&mds->kfunc_md_used);
				*index = i;
				return md;
			}
		}
	}

	/* no available function metadata, so allocate a bigger function
	 * metadata array.
	 *
	 * TODO: we increase the array length here, and we also need to
	 * shrink it somewhere.
	 */
	new_mds = kfunc_md_array_alloc(mds);
	if (!new_mds)
		return NULL;

	rcu_assign_pointer(kfunc_mds, new_mds);
	/* release of the old kfunc metadata array.
	 *
	 * First step, set KFUNC_MD_ARRAY_FL_DEAD on it. The old mds will
	 * not be accessed by anyone anymore from now on.
	 *
	 * Second step, call rcu to wakeup the work queue to call
	 * kfunc_md_array_release_deferred() in kfunc_md_array_release.
	 *
	 * Third step, kill all the percpu ref of the mds in
	 * kfunc_md_array_release_deferred().
	 *
	 * Fourth step, decrease the mds->kfunc_md_used in the callback of
	 * the percpu ref. And the callback is kfunc_md_release().
	 *
	 * Fifth step, wakeup the work queue to call
	 * kfunc_md_array_release_deferred() if old->kfunc_md_used is decreased
	 * to 0, and the old mds will be freed.
	 */
	set_bit(KFUNC_MD_ARRAY_FL_DEAD, &mds->flags);
	call_rcu_tasks(&mds->rcu, kfunc_md_array_release);
	mds = new_mds;

	goto do_retry;
}

static void kfunc_md_fast_put(struct kfunc_md *md)
{
	u8 nop_insn[insn_size];

	if (WARN_ON_ONCE(md->users <= 0))
		return;

	md->users--;
	if (md->users > 0)
		return;

	if (WARN_ON_ONCE(!kfunc_md_arch_exist(md->func, insn_offset)))
		return;

	atomic_dec(&md->array->kfunc_md_used);
	kfunc_md_arch_nops(nop_insn);
	/* release the metadata by recovering the function padding to NOPS */
	kfunc_md_text_poke(md->func, NULL, nop_insn);
	/* mark it as dead, so it will not be reused before we release it
	 * fully in kfunc_md_release().
	 */
	md->flags |= KFUNC_MD_FL_DEAD;
	percpu_ref_kill(&md->pcref);
}

/* Get a exist metadata by the function address, and NULL will be returned
 * if not exist.
 *
 * NOTE: rcu lock or kfunc_md_lock should be held during reading the metadata,
 * and kfunc_md_lock should be held if writing happens.
 */
static struct kfunc_md *kfunc_md_fast_get(unsigned long ip)
{
	struct kfunc_md *md;
	u32 index;

	if (kfunc_md_arch_exist(ip, insn_offset)) {
		index = kfunc_md_get_index(ip);
		md = READ_ONCE(kfunc_mds->mds) + index;
		return md;
	}
	return NULL;
}

/* Get a exist metadata by the function address, and create one if not
 * exist. Reference of the metadata will increase 1.
 *
 * NOTE: always call this function with kfunc_md_lock held, and all
 * updating to metadata should also hold the kfunc_md_lock.
 */
static struct kfunc_md *kfunc_md_fast_create(unsigned long ip, int nr_args)
{
	u8 nop_insn[insn_size], insn[insn_size];
	struct kfunc_md *md;
	u32 index;
	int err;

	md = kfunc_md_fast_get(ip);
	if (md) {
		md->users++;
		return md;
	}

	md = kfunc_md_fast_next(&index);
	if (!md)
		return NULL;

	memset(md, 0, sizeof(*md));
	err = percpu_ref_init(&md->pcref, kfunc_md_release, 0, GFP_KERNEL);
	if (err)
		return NULL;

	kfunc_md_arch_pretend(insn, index);
	kfunc_md_arch_nops(nop_insn);

	if (kfunc_md_text_poke(ip, insn, nop_insn)) {
		atomic_dec(&kfunc_mds->kfunc_md_used);
		percpu_ref_exit(&md->pcref);
		return NULL;
	}

	md->users = 1;
	md->func = ip;
	md->array = kfunc_mds;
	md->nr_args = nr_args;

	return md;
}

static int kfunc_md_fast_bpf_ips(void **ips)
{
	struct kfunc_md *md;
	int i, c = 0;

	for (i = 0; i < kfunc_mds->kfunc_md_count; i++) {
		md = &kfunc_mds->mds[i];
		if (md->users && md->bpf_prog_cnt > !!(md->flags & KFUNC_MD_FL_BPF_REMOVING) &&
		    !md->tramp)
			ips[c++] = (void *)md->func;
	}
	return c;
}
#else

static void kfunc_md_fast_put(struct kfunc_md *md)
{
}

static struct kfunc_md *kfunc_md_fast_get(unsigned long ip)
{
	return NULL;
}

static struct kfunc_md *kfunc_md_fast_create(unsigned long ip, int nr_args)
{
	return NULL;
}

static int kfunc_md_fast_bpf_ips(void **ips)
{
	return 0;
}
#endif /* !CONFIG_FUNCTION_METADATA */

void kfunc_md_enter(struct kfunc_md *md)
{
	percpu_ref_get(&md->pcref);
}
EXPORT_SYMBOL_GPL(kfunc_md_enter);

void kfunc_md_exit(struct kfunc_md *md)
{
	percpu_ref_put(&md->pcref);
}
EXPORT_SYMBOL_GPL(kfunc_md_exit);

void kfunc_md_unlock(void)
{
	mutex_unlock(&kfunc_md_mutex);
}
EXPORT_SYMBOL_GPL(kfunc_md_unlock);

void kfunc_md_lock(void)
{
	mutex_lock(&kfunc_md_mutex);
}
EXPORT_SYMBOL_GPL(kfunc_md_lock);

#undef CALL
#define CALL(fast, slow, type, ...) ({			\
	type ___ret;					\
	if (kfunc_md_fast())				\
		___ret = fast(__VA_ARGS__);		\
	else						\
		___ret = slow(__VA_ARGS__);		\
	___ret;						\
})

#undef CALL_VOID
#define CALL_VOID(fast, slow, ...) do {			\
	if (kfunc_md_fast())				\
		fast(__VA_ARGS__);			\
	else						\
		slow(__VA_ARGS__);			\
} while (0)

struct kfunc_md *kfunc_md_get_noref(unsigned long ip)
{
	return CALL(kfunc_md_fast_get, kfunc_md_hash_get, struct kfunc_md *,
		    ip);
}
EXPORT_SYMBOL_GPL(kfunc_md_get_noref);

struct kfunc_md *kfunc_md_get(unsigned long ip)
{
	struct kfunc_md *md;

	md = CALL(kfunc_md_fast_get, kfunc_md_hash_get, struct kfunc_md *,
		  ip);
	if (md)
		md->users++;
	return md;
}
EXPORT_SYMBOL_GPL(kfunc_md_get);

void kfunc_md_put(unsigned long ip)
{
	struct kfunc_md *md = kfunc_md_get_noref(ip);

	if (md)
		CALL_VOID(kfunc_md_fast_put, kfunc_md_hash_put, md);
}
EXPORT_SYMBOL_GPL(kfunc_md_put);

/* Decrease the reference of the md, release it if "md->users <= 0" */
void kfunc_md_put_entry(struct kfunc_md *md)
{
	if (!md)
		return;

	CALL_VOID(kfunc_md_fast_put, kfunc_md_hash_put, md);
}
EXPORT_SYMBOL_GPL(kfunc_md_put_entry);

struct kfunc_md *kfunc_md_create(unsigned long ip, int nr_args)
{
	return CALL(kfunc_md_fast_create, kfunc_md_hash_create,
		    struct kfunc_md *, ip, nr_args);
}
EXPORT_SYMBOL_GPL(kfunc_md_create);

int kfunc_md_bpf_ips(void ***ips)
{
	void **tmp;
	int c;

	c = atomic_read(&kfunc_mds->kfunc_md_used);
	if (!c)
		return 0;

	tmp = kmalloc_array(c, sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	rcu_read_lock();
	c = CALL(kfunc_md_fast_bpf_ips, kfunc_md_hash_bpf_ips, int, tmp);
	rcu_read_unlock();

	*ips = tmp;

	return c;
}

int kfunc_md_bpf_link(struct kfunc_md *md, struct bpf_prog *prog, int type,
		      u64 cookie)
{
	struct kfunc_md_tramp_prog *tramp_prog, **last;

	tramp_prog = md->bpf_progs[type];
	/* check if the prog is already linked */
	while (tramp_prog) {
		if (tramp_prog->prog == prog)
			return -EEXIST;
		tramp_prog = tramp_prog->next;
	}

	tramp_prog = kmalloc(sizeof(*tramp_prog), GFP_KERNEL);
	if (!tramp_prog)
		return -ENOMEM;

	tramp_prog->prog = prog;
	tramp_prog->cookie = cookie;
	tramp_prog->next = NULL;

	/* add the new prog to the list tail */
	last = &md->bpf_progs[type];
	while (*last)
		last = &(*last)->next;
	*last = tramp_prog;

	md->bpf_prog_cnt++;
	if (type == BPF_TRAMP_FEXIT || type == BPF_TRAMP_MODIFY_RETURN)
		md->flags |= KFUNC_MD_FL_TRACING_ORIGIN;

	return 0;
}

int kfunc_md_bpf_unlink(struct kfunc_md *md, struct bpf_prog *prog, int type)
{
	struct kfunc_md_tramp_prog *cur, **prev;

	prev = &md->bpf_progs[type];
	while (*prev && (*prev)->prog != prog)
		prev = &(*prev)->next;

	cur = *prev;
	if (!cur)
		return -EINVAL;

	*prev = cur->next;
	kfree_rcu(cur, rcu);
	md->bpf_prog_cnt--;

	if (!md->bpf_progs[BPF_TRAMP_FEXIT] &&
	    !md->bpf_progs[BPF_TRAMP_MODIFY_RETURN])
		md->flags &= ~KFUNC_MD_FL_TRACING_ORIGIN;

	if (!md->bpf_prog_cnt)
		md->tramp = NULL;

	return 0;
}

bool __weak kfunc_md_arch_support(int *insn, int *data)
{
	return false;
}

static int __init kfunc_md_init_test(void)
{
#ifndef CONFIG_FUNCTION_METADATA_PADDING
	/* When the CONFIG_FUNCTION_METADATA_PADDING is not available, try
	 * to probe the usable function padding dynamically.
	 */
	if (!kfunc_md_arch_support(&__insn_offset, &__data_offset))
		static_branch_disable(&kfunc_md_use_padding);
#endif
	return 0;
}
late_initcall(kfunc_md_init_test);
