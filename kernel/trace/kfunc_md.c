// SPDX-License-Identifier: GPL-2.0

#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/rcupdate.h>
#include <linux/ftrace.h>
#include <linux/kfunc_md.h>

#define ENTRIES_PER_PAGE (PAGE_SIZE / sizeof(struct kfunc_md))

static u32 kfunc_md_count = ENTRIES_PER_PAGE, kfunc_md_used;
struct kfunc_md __rcu *kfunc_mds;
EXPORT_SYMBOL_GPL(kfunc_mds);

static DEFINE_MUTEX(kfunc_md_mutex);


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

static u32 kfunc_md_get_index(void *ip)
{
	return *(u32 *)(ip - KFUNC_MD_DATA_OFFSET);
}

static void kfunc_md_init(struct kfunc_md *mds, u32 start, u32 end)
{
	u32 i;

	for (i = start; i < end; i++)
		mds[i].users = 0;
}

static int kfunc_md_page_order(void)
{
	return fls(DIV_ROUND_UP(kfunc_md_count, ENTRIES_PER_PAGE)) - 1;
}

/* Get next usable function metadata. On success, return the usable
 * kfunc_md and store the index of it to *index. If no usable kfunc_md is
 * found in kfunc_mds, a larger array will be allocated.
 */
static struct kfunc_md *kfunc_md_get_next(u32 *index)
{
	struct kfunc_md *new_mds, *mds;
	u32 i, order;

	mds = rcu_dereference(kfunc_mds);
	if (mds == NULL) {
		order = kfunc_md_page_order();
		new_mds = (void *)__get_free_pages(GFP_KERNEL, order);
		if (!new_mds)
			return NULL;
		kfunc_md_init(new_mds, 0, kfunc_md_count);
		/* The first time to initialize kfunc_mds, so it is not
		 * used anywhere yet, and we can update it directly.
		 */
		rcu_assign_pointer(kfunc_mds, new_mds);
		mds = new_mds;
	}

	if (likely(kfunc_md_used < kfunc_md_count)) {
		/* maybe we can manage the used function metadata entry
		 * with a bit map ?
		 */
		for (i = 0; i < kfunc_md_count; i++) {
			if (!mds[i].users) {
				kfunc_md_used++;
				*index = i;
				mds[i].users++;
				return mds + i;
			}
		}
	}

	order = kfunc_md_page_order();
	/* no available function metadata, so allocate a bigger function
	 * metadata array.
	 */
	new_mds = (void *)__get_free_pages(GFP_KERNEL, order + 1);
	if (!new_mds)
		return NULL;

	memcpy(new_mds, mds, kfunc_md_count * sizeof(*new_mds));
	kfunc_md_init(new_mds, kfunc_md_count, kfunc_md_count * 2);

	rcu_assign_pointer(kfunc_mds, new_mds);
	synchronize_rcu();
	free_pages((u64)mds, order);

	mds = new_mds + kfunc_md_count;
	*index = kfunc_md_count;
	kfunc_md_count <<= 1;
	kfunc_md_used++;
	mds->users++;

	return mds;
}

static int kfunc_md_text_poke(void *ip, void *insn, void *nop)
{
	void *target;
	int ret = 0;
	u8 *prog;

	target = ip - KFUNC_MD_INSN_OFFSET;
	mutex_lock(&text_mutex);
	if (insn) {
		if (!memcmp(target, insn, KFUNC_MD_INSN_SIZE))
			goto out;

		if (memcmp(target, nop, KFUNC_MD_INSN_SIZE)) {
			ret = -EBUSY;
			goto out;
		}
		prog = insn;
	} else {
		if (!memcmp(target, nop, KFUNC_MD_INSN_SIZE))
			goto out;
		prog = nop;
	}

	ret = kfunc_md_arch_poke(target, prog);
out:
	mutex_unlock(&text_mutex);
	return ret;
}

static bool __kfunc_md_put(struct kfunc_md *md)
{
	u8 nop_insn[KFUNC_MD_INSN_SIZE];

	if (WARN_ON_ONCE(md->users <= 0))
		return false;

	md->users--;
	if (md->users > 0)
		return false;

	if (!kfunc_md_arch_exist(md->func))
		return false;

	kfunc_md_arch_nops(nop_insn);
	/* release the metadata by recovering the function padding to NOPS */
	kfunc_md_text_poke(md->func, NULL, nop_insn);
	/* TODO: we need a way to shrink the array "kfunc_mds" */
	kfunc_md_used--;

	return true;
}

/* Decrease the reference of the md, release it if "md->users <= 0" */
void kfunc_md_put(struct kfunc_md *md)
{
	mutex_lock(&kfunc_md_mutex);
	__kfunc_md_put(md);
	mutex_unlock(&kfunc_md_mutex);
}
EXPORT_SYMBOL_GPL(kfunc_md_put);

/* Get a exist metadata by the function address, and NULL will be returned
 * if not exist.
 *
 * NOTE: rcu lock should be held during reading the metadata, and
 * kfunc_md_lock should be held if writing happens.
 */
struct kfunc_md *kfunc_md_find(void *ip)
{
	struct kfunc_md *md;
	u32 index;

	if (kfunc_md_arch_exist(ip)) {
		index = kfunc_md_get_index(ip);
		if (WARN_ON_ONCE(index >= kfunc_md_count))
			return NULL;

		md = &kfunc_mds[index];
		return md;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(kfunc_md_find);

void kfunc_md_put_by_ip(void *ip)
{
	struct kfunc_md *md;

	mutex_lock(&kfunc_md_mutex);
	md = kfunc_md_find(ip);
	if (md)
		__kfunc_md_put(md);
	mutex_unlock(&kfunc_md_mutex);
}
EXPORT_SYMBOL_GPL(kfunc_md_put_by_ip);

/* Get a exist metadata by the function address, and create one if not
 * exist. Reference of the metadata will increase 1.
 *
 * NOTE: always call this function with kfunc_md_lock held, and all
 * updating to metadata should also hold the kfunc_md_lock.
 */
struct kfunc_md *kfunc_md_get(void *ip)
{
	u8 nop_insn[KFUNC_MD_INSN_SIZE], insn[KFUNC_MD_INSN_SIZE];
	struct kfunc_md *md;
	u32 index;

	md = kfunc_md_find(ip);
	if (md) {
		md->users++;
		return md;
	}

	md = kfunc_md_get_next(&index);
	if (!md)
		return NULL;

	kfunc_md_arch_pretend(insn, index);
	kfunc_md_arch_nops(nop_insn);

	if (kfunc_md_text_poke(ip, insn, nop_insn)) {
		kfunc_md_used--;
		md->users = 0;
		return NULL;
	}
	md->func = ip;

	return md;
}
EXPORT_SYMBOL_GPL(kfunc_md_get);
