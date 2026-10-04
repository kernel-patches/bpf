// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <kunit/test-bug.h>
#include <kunit/resource.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <linux/perf_event.h>
#include <linux/kprobes.h>
#include "../mm/slab.h"

static struct kunit_resource resource;
static int slab_errors;

/*
 * Wrapper function for kmem_cache_create(), which reduces 2 parameters:
 * 'align' and 'ctor', and sets SLAB_SKIP_KFENCE flag to avoid getting an
 * object from kfence pool, where the operation could be caught by both
 * our test and kfence sanity check.
 */
static struct kmem_cache *test_kmem_cache_create(const char *name,
				unsigned int size, slab_flags_t flags)
{
	struct kmem_cache *s = kmem_cache_create(name, size, 0,
					(flags | SLAB_NO_USER_FLAGS), NULL);
	s->flags |= SLAB_SKIP_KFENCE;
	return s;
}

static void test_clobber_zone(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_RZ_alloc", 64,
							SLAB_RED_ZONE);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);

	kasan_disable_current();
	p[64] = 0x12;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, slab_errors);

	kasan_enable_current();
	kmem_cache_free(s, p);
	kmem_cache_destroy(s);
}

#ifndef CONFIG_KASAN
static void test_next_pointer(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_next_ptr_free",
							64, SLAB_POISON);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);
	unsigned long tmp;
	unsigned long *ptr_addr;

	kmem_cache_free(s, p);

	ptr_addr = (unsigned long *)(p + s->offset);
	tmp = *ptr_addr;
	p[s->offset] = ~p[s->offset];

	/*
	 * Expecting three errors.
	 * One for the corrupted freechain and the other one for the wrong
	 * count of objects in use. The third error is fixing broken cache.
	 */
	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 3, slab_errors);

	/*
	 * Try to repair corrupted freepointer.
	 * Still expecting two errors. The first for the wrong count
	 * of objects in use.
	 * The second error is for fixing broken cache.
	 */
	*ptr_addr = tmp;
	slab_errors = 0;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, slab_errors);

	/*
	 * Previous validation repaired the count of objects in use.
	 * Now expecting no error.
	 */
	slab_errors = 0;
	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 0, slab_errors);

	kmem_cache_destroy(s);
}

static void test_first_word(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_1th_word_free",
							64, SLAB_POISON);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);

	kmem_cache_free(s, p);
	*p = 0x78;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, slab_errors);

	kmem_cache_destroy(s);
}

static void test_clobber_50th_byte(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_50th_word_free",
							64, SLAB_POISON);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);

	kmem_cache_free(s, p);
	p[50] = 0x9a;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, slab_errors);

	kmem_cache_destroy(s);
}
#endif

static void test_clobber_redzone_free(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_RZ_free", 64,
							SLAB_RED_ZONE);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);

	kasan_disable_current();
	kmem_cache_free(s, p);
	p[64] = 0xab;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, slab_errors);

	kasan_enable_current();
	kmem_cache_destroy(s);
}

static void test_kmalloc_redzone_access(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_RZ_kmalloc", 32,
				SLAB_KMALLOC|SLAB_STORE_USER|SLAB_RED_ZONE);
	u8 *p = alloc_hooks(__kmalloc_cache_noprof(s, GFP_KERNEL, 18));

	kasan_disable_current();

	/* Suppress the -Warray-bounds warning */
	OPTIMIZER_HIDE_VAR(p);
	p[18] = 0xab;
	p[19] = 0xab;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, slab_errors);

	kasan_enable_current();
	kmem_cache_free(s, p);
	kmem_cache_destroy(s);
}

struct test_kfree_rcu_struct {
	union {
		struct rcu_head rcu;
		struct kvfree_rcu_head kvrcu;
	};
};

static void test_kfree_rcu(struct kunit *test)
{
	struct kmem_cache *s;
	struct test_kfree_rcu_struct *p;

	if (IS_BUILTIN(CONFIG_SLUB_KUNIT_TEST))
		kunit_skip(test, "can't do kfree_rcu() when test is built-in");

	s = test_kmem_cache_create("TestSlub_kfree_rcu",
				   sizeof(struct test_kfree_rcu_struct),
				   SLAB_NO_MERGE);
	p = kmem_cache_alloc(s, GFP_KERNEL);

	kfree_rcu(p, rcu);
	kmem_cache_destroy(s);

	KUNIT_EXPECT_EQ(test, 0, slab_errors);
}

struct cache_destroy_work {
	struct work_struct work;
	struct kmem_cache *s;
};

static void cache_destroy_workfn(struct work_struct *w)
{
	struct cache_destroy_work *cdw;

	cdw = container_of(w, struct cache_destroy_work, work);
	kmem_cache_destroy(cdw->s);
}

#define KMEM_CACHE_DESTROY_NR 10

static void test_kfree_rcu_wq_destroy(struct kunit *test)
{
	struct test_kfree_rcu_struct *p;
	struct cache_destroy_work cdw;
	struct workqueue_struct *wq;
	struct kmem_cache *s;
	unsigned int delay;
	int i;

	if (IS_BUILTIN(CONFIG_SLUB_KUNIT_TEST))
		kunit_skip(test, "can't do kfree_rcu() when test is built-in");

	INIT_WORK_ONSTACK(&cdw.work, cache_destroy_workfn);
	wq = alloc_workqueue("test_kfree_rcu_destroy_wq",
			WQ_HIGHPRI | WQ_UNBOUND | WQ_MEM_RECLAIM, 0);

	if (!wq)
		kunit_skip(test, "failed to alloc wq");

	for (i = 0; i < KMEM_CACHE_DESTROY_NR; i++) {
		s = test_kmem_cache_create("TestSlub_kfree_rcu_wq_destroy",
				sizeof(struct test_kfree_rcu_struct),
				SLAB_NO_MERGE);

		if (!s)
			kunit_skip(test, "failed to create cache");

		delay = get_random_u8();
		p = kmem_cache_alloc(s, GFP_KERNEL);
		kfree_rcu(p, rcu);

		cdw.s = s;

		msleep(delay);
		queue_work(wq, &cdw.work);
		flush_work(&cdw.work);
	}

	destroy_workqueue(wq);
	KUNIT_EXPECT_EQ(test, 0, slab_errors);
}

static void test_leak_destroy(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_leak_destroy",
							64, SLAB_NO_MERGE);
	kmem_cache_alloc(s, GFP_KERNEL);

	kmem_cache_destroy(s);

	KUNIT_EXPECT_EQ(test, 2, slab_errors);
}

static void test_krealloc_redzone_zeroing(struct kunit *test)
{
	u8 *p;
	int i;
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_krealloc", 64,
				SLAB_KMALLOC|SLAB_STORE_USER|SLAB_RED_ZONE);

	p = alloc_hooks(__kmalloc_cache_noprof(s, GFP_KERNEL, 48));
	memset(p, 0xff, 48);

	kasan_disable_current();
	OPTIMIZER_HIDE_VAR(p);

	/* Test shrink */
	p = krealloc(p, 40, GFP_KERNEL | __GFP_ZERO);
	for (i = 40; i < 64; i++)
		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);

	/* Test grow within the same 64B kmalloc object */
	p = krealloc(p, 56, GFP_KERNEL | __GFP_ZERO);
	for (i = 40; i < 56; i++)
		KUNIT_EXPECT_EQ(test, p[i], 0);
	for (i = 56; i < 64; i++)
		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 0, slab_errors);

	memset(p, 0xff, 56);
	/* Test grow with allocating a bigger 128B object */
	p = krealloc(p, 112, GFP_KERNEL | __GFP_ZERO);
	for (i = 0; i < 56; i++)
		KUNIT_EXPECT_EQ(test, p[i], 0xff);
	for (i = 56; i < 112; i++)
		KUNIT_EXPECT_EQ(test, p[i], 0);

	kfree(p);
	kasan_enable_current();
	kmem_cache_destroy(s);
}

#if defined(CONFIG_PERF_EVENTS) || (defined(CONFIG_KPROBES) && defined(CONFIG_SMP))
#define NR_ITERATIONS 1000
#define NR_OBJECTS 1000
static struct test_kfree_rcu_struct *objects[NR_OBJECTS];

struct test_nolock_context {
	struct kunit *test;
	int callback_count;
	int alloc_ok;
	int alloc_fail;
#ifdef CONFIG_PERF_EVENTS
	struct perf_event *event;
#endif
#if defined(CONFIG_KPROBES) && defined(CONFIG_SMP)
	struct kprobe kprobe;
#endif
};

static void test_kmalloc_and_friends(void)
{
	int i, j;
	bool can_use_kfree_rcu = !IS_BUILTIN(CONFIG_SLUB_KUNIT_TEST);

	for (i = 0; i < NR_ITERATIONS; i++) {
		for (j = 0; j < NR_OBJECTS; j++) {
			gfp_t gfp = (i & 1) ? GFP_KERNEL : GFP_KERNEL_ACCOUNT;

			objects[j] = kmalloc_obj(*objects[j], gfp);
			if (!objects[j]) {
				j--;
				while (j >= 0)
					kfree(objects[j--]);
				return;
			}
		}

		for (j = 0; j < NR_OBJECTS; j++) {
			if (can_use_kfree_rcu && (i & 2))
				kfree_rcu(objects[j], rcu);
			else
				kfree(objects[j]);
		}
	}
}

static void test_nolock(struct test_nolock_context *ctx)
{
	struct test_kfree_rcu_struct *objp;
	gfp_t gfp;
	bool can_use_kfree_rcu = !IS_BUILTIN(CONFIG_SLUB_KUNIT_TEST);

	/* __GFP_ACCOUNT to test kmalloc_nolock() in alloc_slab_obj_exts() */
	gfp = (ctx->callback_count & 1) ? 0 : __GFP_ACCOUNT;
	objp = kmalloc_nolock(sizeof(*objp), gfp, NUMA_NO_NODE);

	if (objp)
		ctx->alloc_ok++;
	else
		ctx->alloc_fail++;

	if (can_use_kfree_rcu && (ctx->callback_count & 2))
		kfree_rcu_nolock(objp, kvrcu);
	else
		kfree_nolock(objp);

	ctx->callback_count++;
}
#endif

#ifdef CONFIG_PERF_EVENTS
static struct perf_event_attr hw_attr = {
	.type = PERF_TYPE_HARDWARE,
	.config = PERF_COUNT_HW_CPU_CYCLES,
	.size = sizeof(struct perf_event_attr),
	.pinned = 1,
	.disabled = 1,
	.freq = 1,
	.sample_freq = 100000,
};

static void overflow_handler_test_nolock(struct perf_event *event,
					 struct perf_sample_data *data,
					 struct pt_regs *regs)
{
	struct test_nolock_context *ctx = event->overflow_handler_context;

	test_nolock(ctx);
}

static bool enable_perf_events(struct test_nolock_context *ctx)
{
	struct perf_event *event;

	event = perf_event_create_kernel_counter(&hw_attr, -1, current,
						 overflow_handler_test_nolock,
						 ctx);

	if (IS_ERR(event))
		return false;

	ctx->event = event;
	perf_event_enable(ctx->event);
	return true;
}

static void disable_perf_events(struct test_nolock_context *ctx)
{
	kunit_info(ctx->test, "HW perf events: callback_count: %d, alloc_ok: %d, alloc_fail: %d\n",
		   ctx->callback_count, ctx->alloc_ok, ctx->alloc_fail);

	perf_event_disable(ctx->event);
	perf_event_release_kernel(ctx->event);
}

static void test_kmalloc_nolock_and_friends_perf(struct kunit *test)
{
	struct test_nolock_context ctx = { .test = test };

	if (!enable_perf_events(&ctx))
		kunit_skip(test, "Failed to enable perf event, skipping");

	test_kmalloc_and_friends();

	disable_perf_events(&ctx);
	KUNIT_EXPECT_EQ(test, 0, slab_errors);
}
#endif

#if defined(CONFIG_KPROBES) && defined(CONFIG_SMP)
static int slab_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct test_nolock_context *ctx;

	ctx = container_of(p, struct test_nolock_context, kprobe);
	test_nolock(ctx);
	return 0;
}

static bool register_slab_kprobes(struct test_nolock_context *ctx)
{
	ctx->kprobe.symbol_name = "slab_attach_kprobe_locked";
	ctx->kprobe.pre_handler = slab_kprobe_pre_handler;

	if (register_kprobe(&ctx->kprobe))
		return false;
	return true;
}

static void unregister_slab_kprobes(struct test_nolock_context *ctx)
{
	kunit_info(ctx->test, "kprobes: callback_count: %d, alloc_ok: %d, alloc_fail: %d\n",
		   ctx->callback_count, ctx->alloc_ok, ctx->alloc_fail);
	unregister_kprobe(&ctx->kprobe);
}

static void test_kmalloc_nolock_and_friends_kprobe(struct kunit *test)
{
	struct test_nolock_context ctx = { .test = test };

	if (!register_slab_kprobes(&ctx))
		kunit_skip(test, "Failed to register kprobe, skipping");

	test_kmalloc_and_friends();

	unregister_slab_kprobes(&ctx);
	KUNIT_EXPECT_EQ(test, 0, slab_errors);
}
#endif

static int test_init(struct kunit *test)
{
	slab_errors = 0;

	kunit_add_named_resource(test, NULL, NULL, &resource,
					"slab_errors", &slab_errors);
	return 0;
}

/* Destroy buckets on test exit so a failed KUNIT_ASSERT_*() doesn't leak. */
KUNIT_DEFINE_ACTION_WRAPPER(destroy_buckets, kmem_buckets_destroy, kmem_buckets *);

#define KUNIT_ASSERT_BUCKETS_CREATED(test, b)					\
	do {									\
		KUNIT_ASSERT_NOT_NULL(test, b);					\
		KUNIT_ASSERT_EQ(test, 0,					\
				kunit_add_action_or_reset(test,			\
							  destroy_buckets, b)); \
	} while (0)

/*
 * The cache an allocation came from, or NULL if it came from no cache at
 * all, e.g. a size too big for any of them is served by the page allocator.
 */
static struct kmem_cache *cache_of(void *p)
{
	struct slab *slab = virt_to_slab(p);

	return slab ? slab->slab_cache : NULL;
}

/*
 * A bucket set exists to keep its allocations out of the caches everything
 * else uses, so check the two things that make that true: they come from a
 * cache of the set's own, and that cache is never merged into another.
 */
static void test_kmem_buckets_isolation(struct kunit *test)
{
	struct kmem_cache *bucket_cache, *general_cache;
	kmem_buckets *b;
	void *p, *q;

	if (!IS_ENABLED(CONFIG_SLAB_BUCKETS))
		kunit_skip(test, "needs CONFIG_SLAB_BUCKETS");

	b = kmem_buckets_create("isolated_buckets", 0, 0, 0, INT_MAX, NULL);
	KUNIT_ASSERT_BUCKETS_CREATED(test, b);

	/*
	 * Free each allocation before asserting on the next one: the cache
	 * outlives its objects, so nothing below needs them, and an assertion
	 * that leaves one behind would make the deferred teardown report a
	 * cache that is still in use.
	 */
	p = kmem_buckets_alloc(b, 128, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, p);
	bucket_cache = cache_of(p);
	kfree(p);
	KUNIT_ASSERT_NOT_NULL(test, bucket_cache);

	KUNIT_EXPECT_TRUE_MSG(test, strstarts(bucket_cache->name, "isolated_buckets-"),
			      "expected a bucket cache, got %s", bucket_cache->name);

	/*
	 * Cache merging is on by default, and a bucket cache merged into a
	 * same-sized general one would quietly undo the whole separation.
	 */
	KUNIT_EXPECT_TRUE(test, bucket_cache->flags & SLAB_NO_MERGE);

	q = kmalloc(128, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, q);
	general_cache = cache_of(q);
	kfree(q);
	KUNIT_ASSERT_NOT_NULL(test, general_cache);

	KUNIT_EXPECT_PTR_NE(test, bucket_cache, general_cache);
}

/*
 * Every size class gets its own cache in the set, including the ones that
 * are not powers of two and are filled in from an aligned index. Sizes past
 * the largest cache are served by the page allocator, bucket set or not.
 */
static void test_kmem_buckets_sizes(struct kunit *test)
{
	static const size_t sizes[] = { 8, 96, 192, 1024, 4096 };
	struct kmem_cache *c;
	kmem_buckets *b;
	void *p;
	int i;

	if (!IS_ENABLED(CONFIG_SLAB_BUCKETS))
		kunit_skip(test, "needs CONFIG_SLAB_BUCKETS");

	b = kmem_buckets_create("sized_buckets", 0, 0, 0, INT_MAX, NULL);
	KUNIT_ASSERT_BUCKETS_CREATED(test, b);

	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		p = kmem_buckets_alloc(b, sizes[i], GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, p);
		c = cache_of(p);
		kfree(p);
		KUNIT_ASSERT_NOT_NULL(test, c);

		KUNIT_EXPECT_TRUE_MSG(test, strstarts(c->name, "sized_buckets-"),
				      "size %zu: expected a bucket cache, got %s",
				      sizes[i], c->name);
		KUNIT_EXPECT_GE(test, c->object_size, sizes[i]);
	}

	/* Too big for any cache: a folio from the page allocator, not a slab. */
	p = kmem_buckets_alloc(b, KMALLOC_MAX_CACHE_SIZE + 1, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, p);
	c = cache_of(p);
	kfree(p);

	KUNIT_EXPECT_NULL(test, c);
}

/*
 * A bucket cache stands in for a kmalloc cache, so it has to be aligned like
 * one. The DMA layer decides whether a buffer needs bouncing from its size,
 * on the grounds that a kmalloc cache of that size is already aligned for
 * the device, so a weaker alignment here is not something a caller can see
 * coming. Without slab debugging the size implies the alignment and this
 * holds either way; with it, only the cache's own alignment does.
 */
static void test_kmem_buckets_alignment(struct kunit *test)
{
	static const size_t sizes[] = { 128, 512, 2048 };
	struct kmem_cache *bucket_cache, *general_cache;
	kmem_buckets *b;
	void *p;
	int i;

	if (!IS_ENABLED(CONFIG_SLAB_BUCKETS))
		kunit_skip(test, "needs CONFIG_SLAB_BUCKETS");

	b = kmem_buckets_create("aligned_buckets", 0, 0, 0, INT_MAX, NULL);
	KUNIT_ASSERT_BUCKETS_CREATED(test, b);

	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		p = kmem_buckets_alloc(b, sizes[i], GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, p);
		bucket_cache = cache_of(p);
		KUNIT_EXPECT_TRUE_MSG(test,
				      IS_ALIGNED((unsigned long)p, ARCH_DMA_MINALIGN),
				      "size %zu: object %p is not %d byte aligned",
				      sizes[i], p, (int)ARCH_DMA_MINALIGN);
		kfree(p);

		p = kmalloc(sizes[i], GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, p);
		general_cache = cache_of(p);
		kfree(p);

		KUNIT_ASSERT_NOT_NULL(test, bucket_cache);
		KUNIT_ASSERT_NOT_NULL(test, general_cache);
		KUNIT_EXPECT_EQ_MSG(test, bucket_cache->align, general_cache->align,
				    "size %zu: bucket cache aligned to %u, %s to %u",
				    sizes[i], bucket_cache->align,
				    general_cache->name, general_cache->align);
	}
}

/*
 * A set created with an alignment gives every one of its caches that
 * alignment in place of the kmalloc caches' own. 256 is stronger than
 * kmalloc's alignment for the 64 and 128 byte caches and weaker than it
 * for the 512 and 2048 byte ones, so this checks the override both ways.
 */
static void test_kmem_buckets_explicit_alignment(struct kunit *test)
{
	static const size_t sizes[] = { 64, 128, 512, 2048 };
	const unsigned int align = 256;
	struct kmem_cache *c;
	kmem_buckets *b;
	void *p;
	int i;

	if (!IS_ENABLED(CONFIG_SLAB_BUCKETS))
		kunit_skip(test, "needs CONFIG_SLAB_BUCKETS");

	b = kmem_buckets_create("explicit_buckets", align, 0, 0, INT_MAX, NULL);
	KUNIT_ASSERT_BUCKETS_CREATED(test, b);

	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		p = kmem_buckets_alloc(b, sizes[i], GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, p);
		c = cache_of(p);
		KUNIT_EXPECT_TRUE_MSG(test, IS_ALIGNED((unsigned long)p, align),
				      "size %zu: object %p is not %u byte aligned",
				      sizes[i], p, align);
		kfree(p);

		KUNIT_ASSERT_NOT_NULL(test, c);
		KUNIT_EXPECT_EQ_MSG(test, c->align, align,
				    "size %zu: bucket cache aligned to %u, not %u",
				    sizes[i], c->align, align);
	}
}

/*
 * With the feature compiled out, kmem_buckets_create() still returns
 * something non-NULL so that callers only have to check for failure, and
 * allocations through it work (i.e. come from the general caches).
 */
static void test_kmem_buckets_disabled(struct kunit *test)
{
	kmem_buckets *b;
	struct kmem_cache *c;
	void *p;

	if (IS_ENABLED(CONFIG_SLAB_BUCKETS))
		kunit_skip(test, "only meaningful without CONFIG_SLAB_BUCKETS");

	b = kmem_buckets_create("disabled_buckets", 0, 0, 0, INT_MAX, NULL);
	KUNIT_ASSERT_BUCKETS_CREATED(test, b);

	p = kmem_buckets_alloc(b, 128, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, p);
	c = cache_of(p);
	kfree(p);
	KUNIT_ASSERT_NOT_NULL(test, c);

	KUNIT_EXPECT_TRUE_MSG(test, !strstarts(c->name, "disabled_buckets-"),
			      "expected a general cache, got %s", c->name);
}

/* Destroying a set has to take its caches down, not just free the set. */
static void test_kmem_buckets_destroy(struct kunit *test)
{
	kmem_buckets *b;
	void *p;

	if (!IS_ENABLED(CONFIG_SLAB_BUCKETS))
		kunit_skip(test, "needs CONFIG_SLAB_BUCKETS");

	b = kmem_buckets_create("destroyed_buckets", 0, 0, 0, INT_MAX, NULL);
	KUNIT_ASSERT_NOT_NULL(test, b);

	/*
	 * Deliberately leaked, as test_leak_destroy() leaks its own: the
	 * teardown below has to find it. kmem_cache_destroy() unlists the
	 * cache either way, so the name is still released.
	 */
	p = kmem_buckets_alloc(b, 128, GFP_KERNEL);
	KUNIT_EXPECT_NOT_NULL(test, p);

	kmem_buckets_destroy(b);

	KUNIT_EXPECT_EQ(test, 2, slab_errors);
}

/*
 * A bucket set holds only the kmalloc types it was created with, so an
 * allocation that asks for a different one has to come from the general
 * caches. Check that it does, rather than being served a normal cache that
 * does not satisfy what the flags asked for.
 */
static void test_kmem_buckets_type_fallback(struct kunit *test)
{
	struct kmem_cache *c;
	kmem_buckets *b;
	void *p;

	if (!IS_ENABLED(CONFIG_SLAB_BUCKETS))
		kunit_skip(test, "needs CONFIG_SLAB_BUCKETS");

	b = kmem_buckets_create("test_buckets", 0, 0, 0, INT_MAX, NULL);
	KUNIT_ASSERT_BUCKETS_CREATED(test, b);

	/* A plain allocation stays isolated in the bucket set. */
	p = kmem_buckets_alloc(b, 128, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, p);
	c = cache_of(p);
	kfree(p);
	KUNIT_ASSERT_NOT_NULL(test, c);

	KUNIT_EXPECT_TRUE_MSG(test, strstarts(c->name, "test_buckets-"),
			      "expected a bucket cache, got %s", c->name);

	/* One that needs ZONE_DMA cannot, so it falls back. */
	if (IS_ENABLED(CONFIG_ZONE_DMA)) {
		p = kmem_buckets_alloc(b, 128, GFP_KERNEL | GFP_DMA);
		KUNIT_ASSERT_NOT_NULL(test, p);
		c = cache_of(p);
		kfree(p);
		KUNIT_ASSERT_NOT_NULL(test, c);

		KUNIT_EXPECT_TRUE_MSG(test, strstarts(c->name, "dma-kmalloc-"),
				      "expected a DMA cache, got %s", c->name);
	}

	/*
	 * An accounted allocation would fall back too, but a bucket set can
	 * hold that type, so reaching the fallback means the create mask was
	 * wrong and kmalloc_slab() warns. Not exercised here for that reason;
	 * test_kmem_buckets_type_covered() checks the type that is asked for.
	 */
}

/*
 * A bucket set created for a kmalloc type keeps those allocations isolated
 * too, rather than sending them to the general caches. Where nothing creates
 * accounted caches at all, the row aliases the normal one, so this also
 * covers tearing down a set whose rows share their caches.
 */
static void test_kmem_buckets_type_covered(struct kunit *test)
{
	struct kmem_cache *c, *normal_cache;
	kmem_buckets *b;
	void *p;

	if (!IS_ENABLED(CONFIG_SLAB_BUCKETS))
		kunit_skip(test, "needs CONFIG_SLAB_BUCKETS");

	b = kmem_buckets_create_types("covered_buckets", 0, 0, 0, INT_MAX, NULL,
				      BIT(KMEM_BUCKET_NORMAL) |
				      BIT(KMEM_BUCKET_CGROUP));
	KUNIT_ASSERT_BUCKETS_CREATED(test, b);

	p = kmem_buckets_alloc(b, 128, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, p);
	normal_cache = cache_of(p);
	kfree(p);
	KUNIT_ASSERT_NOT_NULL(test, normal_cache);

	KUNIT_EXPECT_TRUE_MSG(test, strstarts(normal_cache->name, "covered_buckets-128"),
			      "expected the normal bucket cache, got %s",
			      normal_cache->name);

	/* Accounted, and still in the bucket set rather than kmalloc-cg-*. */
	p = kmem_buckets_alloc(b, 128, GFP_KERNEL | __GFP_ACCOUNT);
	KUNIT_ASSERT_NOT_NULL(test, p);
	c = cache_of(p);
	kfree(p);
	KUNIT_ASSERT_NOT_NULL(test, c);

	if (IS_ENABLED(CONFIG_MEMCG) && !mem_cgroup_kmem_disabled()) {
		KUNIT_EXPECT_TRUE_MSG(test, strstarts(c->name, "covered_buckets-cg-"),
				      "expected the accounted bucket cache, got %s",
				      c->name);
		KUNIT_EXPECT_TRUE(test, c->flags & SLAB_ACCOUNT);
	} else {
		/*
		 * Nothing is creating accounted caches, so the row aliases
		 * the normal one and the allocation lands there -- isolated
		 * still, just not separately accounted.
		 */
		KUNIT_EXPECT_PTR_EQ(test, c, normal_cache);
	}
}

/*
 * The alignment a set is created with reaches every row it holds, not just
 * the normal one. 256 is stronger than kmalloc's alignment for 128 byte
 * objects, so a row built without it would show here.
 */
static void test_kmem_buckets_type_covered_alignment(struct kunit *test)
{
	static const gfp_t gfps[] = { GFP_KERNEL, GFP_KERNEL | __GFP_ACCOUNT };
	const unsigned int align = 256;
	struct kmem_cache *c;
	kmem_buckets *b;
	void *p;
	int i;

	if (!IS_ENABLED(CONFIG_SLAB_BUCKETS))
		kunit_skip(test, "needs CONFIG_SLAB_BUCKETS");

	b = kmem_buckets_create_types("covered_aligned", align, 0, 0, INT_MAX,
				      NULL, BIT(KMEM_BUCKET_NORMAL) |
				      BIT(KMEM_BUCKET_CGROUP));
	KUNIT_ASSERT_BUCKETS_CREATED(test, b);

	for (i = 0; i < ARRAY_SIZE(gfps); i++) {
		p = kmem_buckets_alloc(b, 128, gfps[i]);
		KUNIT_ASSERT_NOT_NULL(test, p);
		c = cache_of(p);
		KUNIT_EXPECT_TRUE_MSG(test, IS_ALIGNED((unsigned long)p, align),
				      "gfp %pGg: object %p is not %u byte aligned",
				      &gfps[i], p, align);
		kfree(p);

		KUNIT_ASSERT_NOT_NULL(test, c);
		KUNIT_EXPECT_TRUE_MSG(test, strstarts(c->name, "covered_aligned-"),
				      "gfp %pGg: expected a bucket cache, got %s",
				      &gfps[i], c->name);
		KUNIT_EXPECT_EQ_MSG(test, c->align, align,
				    "gfp %pGg: %s aligned to %u, not %u",
				    &gfps[i], c->name, c->align, align);
	}
}

static struct kunit_case test_cases[] = {
	KUNIT_CASE(test_clobber_zone),

#ifndef CONFIG_KASAN
	KUNIT_CASE(test_next_pointer),
	KUNIT_CASE(test_first_word),
	KUNIT_CASE(test_clobber_50th_byte),
#endif

	KUNIT_CASE(test_clobber_redzone_free),
	KUNIT_CASE(test_kmalloc_redzone_access),
	KUNIT_CASE(test_kfree_rcu),
	KUNIT_CASE(test_kfree_rcu_wq_destroy),
	KUNIT_CASE(test_leak_destroy),
	KUNIT_CASE(test_krealloc_redzone_zeroing),
#ifdef CONFIG_PERF_EVENTS
	KUNIT_CASE_SLOW(test_kmalloc_nolock_and_friends_perf),
#endif
#if defined(CONFIG_KPROBES) && defined(CONFIG_SMP)
	KUNIT_CASE_SLOW(test_kmalloc_nolock_and_friends_kprobe),
#endif
	KUNIT_CASE(test_kmem_buckets_isolation),
	KUNIT_CASE(test_kmem_buckets_sizes),
	KUNIT_CASE(test_kmem_buckets_alignment),
	KUNIT_CASE(test_kmem_buckets_explicit_alignment),
	KUNIT_CASE(test_kmem_buckets_disabled),
	KUNIT_CASE(test_kmem_buckets_destroy),
	KUNIT_CASE(test_kmem_buckets_type_fallback),
	KUNIT_CASE(test_kmem_buckets_type_covered),
	KUNIT_CASE(test_kmem_buckets_type_covered_alignment),
	{}
};

static struct kunit_suite test_suite = {
	.name = "slub_test",
	.init = test_init,
	.test_cases = test_cases,
};
kunit_test_suite(test_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_DESCRIPTION("Kunit tests for slub allocator");
MODULE_LICENSE("GPL");
