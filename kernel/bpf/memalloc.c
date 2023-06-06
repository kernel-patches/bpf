// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */
#include <linux/mm.h>
#include <linux/llist.h>
#include <linux/bpf.h>
#include <linux/irq_work.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/memcontrol.h>
#include <asm/local.h>

/* Any context (including NMI) BPF specific memory allocator.
 *
 * Tracing BPF programs can attach to kprobe and fentry. Hence they
 * run in unknown context where calling plain kmalloc() might not be safe.
 *
 * Front-end kmalloc() with per-cpu per-bucket cache of free elements.
 * Refill this cache asynchronously from irq_work.
 *
 * CPU_0 buckets
 * 16 32 64 96 128 196 256 512 1024 2048 4096
 * ...
 * CPU_N buckets
 * 16 32 64 96 128 196 256 512 1024 2048 4096
 *
 * The buckets are prefilled at the start.
 * BPF programs always run with migration disabled.
 * It's safe to allocate from cache of the current cpu with irqs disabled.
 * Free-ing is always done into bucket of the current cpu as well.
 * irq_work trims extra free elements from buckets with kfree
 * and refills them with kmalloc, so global kmalloc logic takes care
 * of freeing objects allocated by one cpu and freed on another.
 *
 * Every allocated objected is padded with extra 8 bytes that contains
 * struct llist_node.
 */
#define LLIST_NODE_SZ sizeof(struct llist_node)

/* similar to kmalloc, but sizeof == 8 bucket is gone */
static u8 size_index[24] __ro_after_init = {
	3,	/* 8 */
	3,	/* 16 */
	4,	/* 24 */
	4,	/* 32 */
	5,	/* 40 */
	5,	/* 48 */
	5,	/* 56 */
	5,	/* 64 */
	1,	/* 72 */
	1,	/* 80 */
	1,	/* 88 */
	1,	/* 96 */
	6,	/* 104 */
	6,	/* 112 */
	6,	/* 120 */
	6,	/* 128 */
	2,	/* 136 */
	2,	/* 144 */
	2,	/* 152 */
	2,	/* 160 */
	2,	/* 168 */
	2,	/* 176 */
	2,	/* 184 */
	2	/* 192 */
};

static int bpf_mem_cache_idx(size_t size)
{
	if (!size || size > 4096)
		return -1;

	if (size <= 192)
		return size_index[(size - 1) / 8] - 1;

	return fls(size - 1) - 2;
}

struct bpf_mem_shared_cache {
	raw_spinlock_t reuse_lock;
	bool percpu;
	bool direct_free;
	struct llist_head reuse_ready_head;
	struct llist_node *reuse_ready_tail;
	struct llist_head wait_for_free;
	atomic_t call_rcu_in_progress;
	struct rcu_head rcu;
};

#define NUM_CACHES 11

struct bpf_mem_cache {
	/* per-cpu list of free objects of size 'unit_size'.
	 * All accesses are done with interrupts disabled and 'active' counter
	 * protection with __llist_add() and __llist_del_first().
	 */
	struct llist_head free_llist;
	local_t active;

	/* Operations on the free_list from unit_alloc/unit_free/bpf_mem_refill
	 * are sequenced by per-cpu 'active' counter. But unit_free() cannot
	 * fail. When 'active' is busy the unit_free() will add an object to
	 * free_llist_extra.
	 */
	struct llist_head free_llist_extra;

	struct irq_work refill_work;
	struct obj_cgroup *objcg;
	int unit_size;
	/* count of objects in free_llist */
	int free_cnt;
	int low_watermark, high_watermark, batch;
	int percpu_size;
	struct llist_head prepare_reuse_head;
	struct llist_node *prepare_reuse_tail;
	unsigned int prepare_reuse_cnt;
	raw_spinlock_t lock;

	struct bpf_mem_shared_cache *sc;
	struct rcu_head rcu;
	struct llist_head free_by_rcu;
	struct llist_node *free_by_rcu_tail;
	struct llist_head waiting_for_gp;
	struct llist_node *waiting_for_gp_tail;
	atomic_t call_rcu_in_progress;
};

struct bpf_mem_caches {
	struct bpf_mem_cache cache[NUM_CACHES];
};

struct bpf_mem_shared_caches {
	struct bpf_mem_shared_cache cache[NUM_CACHES];
};

static struct llist_node notrace *__llist_del_first(struct llist_head *head)
{
	struct llist_node *entry, *next;

	entry = head->first;
	if (!entry)
		return NULL;
	next = entry->next;
	head->first = next;
	return entry;
}

static void *__alloc(struct bpf_mem_cache *c, int node, gfp_t flags)
{
	if (c->percpu_size) {
		void **obj = kmalloc_node(c->percpu_size, flags, node);
		void *pptr = __alloc_percpu_gfp(c->unit_size, 8, flags);

		if (!obj || !pptr) {
			free_percpu(pptr);
			kfree(obj);
			return NULL;
		}
		obj[1] = pptr;
		return obj;
	}

	return kmalloc_node(c->unit_size, flags | __GFP_ZERO, node);
}

static struct mem_cgroup *get_memcg(const struct bpf_mem_cache *c)
{
#ifdef CONFIG_MEMCG_KMEM
	if (c->objcg)
		return get_mem_cgroup_from_objcg(c->objcg);
#endif

#ifdef CONFIG_MEMCG
	return root_mem_cgroup;
#else
	return NULL;
#endif
}

static int bpf_ma_get_reusable_obj(struct bpf_mem_cache *c, int cnt)
{
	struct bpf_mem_shared_cache *sc = c->sc;
	struct llist_node *head, *tail, *obj;
	unsigned long flags;
	int alloc;

	if (llist_empty(&sc->reuse_ready_head) && llist_empty(&sc->wait_for_free))
		return 0;

	alloc = 0;
	head = NULL;
	tail = NULL;
	raw_spin_lock_irqsave(&sc->reuse_lock, flags);
	while (alloc < cnt) {
		obj = __llist_del_first(&sc->reuse_ready_head);
		if (obj) {
			if (llist_empty(&sc->reuse_ready_head))
				sc->reuse_ready_tail = NULL;
		} else {
			obj = __llist_del_first(&sc->wait_for_free);
			if (!obj)
				break;
		}
		if (!tail)
			tail = obj;
		obj->next = head;
		head = obj;
		alloc++;
	}
	raw_spin_unlock_irqrestore(&sc->reuse_lock, flags);

	if (alloc) {
		if (IS_ENABLED(CONFIG_PREEMPT_RT))
			local_irq_save(flags);
		WARN_ON_ONCE(local_inc_return(&c->active) != 1);
		__llist_add_batch(head, tail, &c->free_llist);
		c->free_cnt += alloc;
		local_dec(&c->active);
		if (IS_ENABLED(CONFIG_PREEMPT_RT))
			local_irq_restore(flags);
	}

	return alloc;
}

/* Mostly runs from irq_work except __init phase. */
static void alloc_bulk(struct bpf_mem_cache *c, int cnt, int node)
{
	struct mem_cgroup *memcg = NULL, *old_memcg;
	unsigned long flags;
	void *obj;
	int i;

	i = bpf_ma_get_reusable_obj(c, cnt);

	memcg = get_memcg(c);
	old_memcg = set_active_memcg(memcg);
	for (; i < cnt; i++) {
		/* Allocate, but don't deplete atomic reserves that typical
		 * GFP_ATOMIC would do. irq_work runs on this cpu and kmalloc
		 * will allocate from the current numa node which is what we
		 * want here.
		 */
		obj = __alloc(c, node, GFP_NOWAIT | __GFP_NOWARN | __GFP_ACCOUNT);
		if (!obj)
			break;
		if (IS_ENABLED(CONFIG_PREEMPT_RT))
			/* In RT irq_work runs in per-cpu kthread, so disable
			 * interrupts to avoid preemption and interrupts and
			 * reduce the chance of bpf prog executing on this cpu
			 * when active counter is busy.
			 */
			local_irq_save(flags);
		/* alloc_bulk runs from irq_work which will not preempt a bpf
		 * program that does unit_alloc/unit_free since IRQs are
		 * disabled there. There is no race to increment 'active'
		 * counter. It protects free_llist from corruption in case NMI
		 * bpf prog preempted this loop.
		 */
		WARN_ON_ONCE(local_inc_return(&c->active) != 1);
		__llist_add(obj, &c->free_llist);
		c->free_cnt++;
		local_dec(&c->active);
		if (IS_ENABLED(CONFIG_PREEMPT_RT))
			local_irq_restore(flags);
	}
	set_active_memcg(old_memcg);
	mem_cgroup_put(memcg);
}

static void free_one(void *obj, bool percpu)
{
	if (percpu) {
		free_percpu(((void **)obj)[1]);
		kfree(obj);
		return;
	}

	kfree(obj);
}

static void free_all(struct llist_node *llnode, bool percpu)
{
	struct llist_node *pos, *t;

	llist_for_each_safe(pos, t, llnode)
		free_one(pos, percpu);
}

static void free_rcu(struct rcu_head *rcu)
{
	struct bpf_mem_shared_cache *sc = container_of(rcu, struct bpf_mem_shared_cache, rcu);
	struct llist_node *head;
	unsigned long flags;

	raw_spin_lock_irqsave(&sc->reuse_lock, flags);
	head = __llist_del_all(&sc->wait_for_free);
	raw_spin_unlock_irqrestore(&sc->reuse_lock, flags);
	free_all(head, sc->percpu);
	atomic_set(&sc->call_rcu_in_progress, 0);
}

static void bpf_ma_add_to_reuse_ready_or_free(struct bpf_mem_cache *c)
{
	struct bpf_mem_shared_cache *sc = c->sc;
	struct llist_node *head, *tail;
	unsigned long flags;

	/* Draining could be running concurrently with reuse_rcu() */
	raw_spin_lock_irqsave(&c->lock, flags);
	head = __llist_del_all(&c->waiting_for_gp);
	tail = c->waiting_for_gp_tail;
	c->waiting_for_gp_tail = NULL;
	raw_spin_unlock_irqrestore(&c->lock, flags);
	/* Draining is in progress ? */
	if (!head)
		return;

	raw_spin_lock_irqsave(&sc->reuse_lock, flags);
	/* Don't move these objects to reuse_ready list and free
	 * these objects directly.
	 */
	if (sc->direct_free) {
		raw_spin_unlock_irqrestore(&sc->reuse_lock, flags);
		free_all(head, sc->percpu);
		return;
	}

	if (llist_empty(&sc->reuse_ready_head))
		sc->reuse_ready_tail = tail;
	__llist_add_batch(head, tail, &sc->reuse_ready_head);

	if (!atomic_xchg(&sc->call_rcu_in_progress, 1)) {
		head = __llist_del_all(&sc->reuse_ready_head);
		tail = sc->reuse_ready_tail;
		sc->reuse_ready_tail = NULL;
		WARN_ON_ONCE(!llist_empty(&sc->wait_for_free));
		__llist_add_batch(head, tail, &sc->wait_for_free);
		call_rcu_tasks_trace(&sc->rcu, free_rcu);
	}
	raw_spin_unlock_irqrestore(&sc->reuse_lock, flags);
}

static void reuse_rcu(struct rcu_head *rcu)
{
	struct bpf_mem_cache *c = container_of(rcu, struct bpf_mem_cache, rcu);

	bpf_ma_add_to_reuse_ready_or_free(c);
	atomic_set(&c->call_rcu_in_progress, 0);
}

static void reuse_bulk(struct bpf_mem_cache *c)
{
	struct llist_node *head, *tail, *llnode, *tmp;
	unsigned long flags;

	if (IS_ENABLED(CONFIG_PREEMPT_RT))
		local_irq_save(flags);
	WARN_ON_ONCE(local_inc_return(&c->active) != 1);
	head = __llist_del_all(&c->prepare_reuse_head);
	tail = c->prepare_reuse_tail;
	c->prepare_reuse_tail = NULL;
	c->prepare_reuse_cnt = 0;
	local_dec(&c->active);
	if (IS_ENABLED(CONFIG_PREEMPT_RT))
		local_irq_restore(flags);

	llist_for_each_safe(llnode, tmp, llist_del_all(&c->free_llist_extra)) {
		if (!head)
			tail = llnode;
		llnode->next = head;
		head = llnode->next;
	}
	WARN_ON_ONCE(!head);

	/* bpf_mem_cache is a per-cpu object. Freeing happens in irq_work.
	 * Nothing races to add to free_by_rcu list.
	 */
	if (llist_empty(&c->free_by_rcu))
		c->free_by_rcu_tail = tail;
	__llist_add_batch(head, tail, &c->free_by_rcu);

	if (atomic_xchg(&c->call_rcu_in_progress, 1))
		return;

	WARN_ON_ONCE(!llist_empty(&c->waiting_for_gp));
	head = __llist_del_all(&c->free_by_rcu);
	tail = c->free_by_rcu_tail;
	c->free_by_rcu_tail = NULL;
	if (llist_empty(&c->waiting_for_gp))
		c->waiting_for_gp_tail = tail;
	__llist_add_batch(head, tail, &c->waiting_for_gp);
	call_rcu(&c->rcu, reuse_rcu);
}

static void bpf_mem_refill(struct irq_work *work)
{
	struct bpf_mem_cache *c = container_of(work, struct bpf_mem_cache, refill_work);

	/* Racy access to free_cnt. It doesn't need to be 100% accurate */
	if (c->free_cnt < c->low_watermark)
		/* irq_work runs on this cpu and kmalloc will allocate
		 * from the current numa node which is what we want here.
		 */
		alloc_bulk(c, c->batch, NUMA_NO_NODE);

	if (c->prepare_reuse_cnt > c->high_watermark)
		reuse_bulk(c);
}

static void notrace irq_work_raise(struct bpf_mem_cache *c)
{
	irq_work_queue(&c->refill_work);
}

/* For typical bpf map case that uses bpf_mem_cache_alloc and single bucket
 * the freelist cache will be elem_size * 64 (or less) on each cpu.
 *
 * For bpf programs that don't have statically known allocation sizes and
 * assuming (low_mark + high_mark) / 2 as an average number of elements per
 * bucket and all buckets are used the total amount of memory in freelists
 * on each cpu will be:
 * 64*16 + 64*32 + 64*64 + 64*96 + 64*128 + 64*196 + 64*256 + 32*512 + 16*1024 + 8*2048 + 4*4096
 * == ~ 116 Kbyte using below heuristic.
 * Initialized, but unused bpf allocator (not bpf map specific one) will
 * consume ~ 11 Kbyte per cpu.
 * Typical case will be between 11K and 116K closer to 11K.
 * bpf progs can and should share bpf_mem_cache when possible.
 */

static void prefill_mem_cache(struct bpf_mem_cache *c, int cpu)
{
	init_irq_work(&c->refill_work, bpf_mem_refill);
	if (c->unit_size <= 256) {
		c->low_watermark = 32;
		c->high_watermark = 96;
	} else {
		/* When page_size == 4k, order-0 cache will have low_mark == 2
		 * and high_mark == 6 with batch alloc of 3 individual pages at
		 * a time.
		 * 8k allocs and above low == 1, high == 3, batch == 1.
		 */
		c->low_watermark = max(32 * 256 / c->unit_size, 1);
		c->high_watermark = max(96 * 256 / c->unit_size, 3);
	}
	c->batch = max((c->high_watermark - c->low_watermark) / 4 * 3, 1);

	/* To avoid consuming memory assume that 1st run of bpf
	 * prog won't be doing more than 4 map_update_elem from
	 * irq disabled region
	 */
	alloc_bulk(c, c->unit_size <= 256 ? 4 : 1, cpu_to_node(cpu));
}

static inline void shared_cache_init(struct bpf_mem_shared_cache *cache, bool percpu)
{
	cache->percpu = percpu;
	raw_spin_lock_init(&cache->reuse_lock);
}

/* When size != 0 bpf_mem_cache for each cpu.
 * This is typical bpf hash map use case when all elements have equal size.
 *
 * When size == 0 allocate 11 bpf_mem_cache-s for each cpu, then rely on
 * kmalloc/kfree. Max allocation size is 4096 in this case.
 * This is bpf_dynptr and bpf_kptr use case.
 */
int bpf_mem_alloc_init(struct bpf_mem_alloc *ma, int size, bool percpu)
{
	static u16 sizes[NUM_CACHES] = {96, 192, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
	struct bpf_mem_caches *cc, __percpu *pcc;
	struct bpf_mem_cache *c, __percpu *pc;
	struct bpf_mem_shared_caches *scc;
	struct bpf_mem_shared_cache *sc;
	struct obj_cgroup *objcg = NULL;
	int cpu, i, unit_size, percpu_size = 0;

	if (size) {
		sc = kzalloc(sizeof(*sc), GFP_KERNEL);
		if (!sc)
			return -ENOMEM;
		shared_cache_init(sc, percpu);

		pc = __alloc_percpu_gfp(sizeof(*pc), 8, GFP_KERNEL);
		if (!pc) {
			kfree(sc);
			return -ENOMEM;
		}

		if (percpu)
			/* room for llist_node and per-cpu pointer */
			percpu_size = LLIST_NODE_SZ + sizeof(void *);
		else
			size += LLIST_NODE_SZ; /* room for llist_node */
		unit_size = size;

#ifdef CONFIG_MEMCG_KMEM
		if (memcg_bpf_enabled())
			objcg = get_obj_cgroup_from_current();
#endif
		for_each_possible_cpu(cpu) {
			c = per_cpu_ptr(pc, cpu);
			c->unit_size = unit_size;
			c->objcg = objcg;
			c->percpu_size = percpu_size;
			raw_spin_lock_init(&c->lock);
			c->sc = sc;
			prefill_mem_cache(c, cpu);
		}
		ma->cache = pc;
		ma->s_cache = sc;
		return 0;
	}

	/* size == 0 && percpu is an invalid combination */
	if (WARN_ON_ONCE(percpu))
		return -EINVAL;

	scc = kzalloc(sizeof(*scc), GFP_KERNEL);
	if (!scc)
		return -ENOMEM;
	pcc = __alloc_percpu_gfp(sizeof(*cc), 8, GFP_KERNEL);
	if (!pcc) {
		kfree(scc);
		return -ENOMEM;
	}
#ifdef CONFIG_MEMCG_KMEM
	objcg = get_obj_cgroup_from_current();
#endif
	for (i = 0; i < NUM_CACHES; i++)
		shared_cache_init(&scc->cache[i], 0);
	for_each_possible_cpu(cpu) {
		cc = per_cpu_ptr(pcc, cpu);
		for (i = 0; i < NUM_CACHES; i++) {
			c = &cc->cache[i];
			c->unit_size = sizes[i];
			c->objcg = objcg;
			raw_spin_lock_init(&c->lock);
			c->sc = &scc->cache[i];
			prefill_mem_cache(c, cpu);
		}
	}
	ma->caches = pcc;
	ma->s_caches = scc;
	return 0;
}

static void drain_shared_mem_cache(struct bpf_mem_shared_cache *sc)
{
	struct llist_node *head[2];
	unsigned long flags;

	raw_spin_lock_irqsave(&sc->reuse_lock, flags);
	sc->direct_free = true;
	head[0] = __llist_del_all(&sc->reuse_ready_head);
	sc->reuse_ready_tail = NULL;
	head[1] = __llist_del_all(&sc->wait_for_free);
	raw_spin_unlock_irqrestore(&sc->reuse_lock, flags);

	free_all(head[0], sc->percpu);
	free_all(head[1], sc->percpu);
}

static void drain_mem_cache(struct bpf_mem_cache *c)
{
	bool percpu = !!c->percpu_size;
	struct llist_node *head;
	unsigned long flags;

	/* No progs are using this bpf_mem_cache, but htab_map_free() called
	 * bpf_mem_cache_free() for all remaining elements and they can be in
	 * free_by_rcu or in waiting_for_gp lists, so drain those lists now.
	 *
	 * Except for waiting_for_gp list, there are no concurrent operations
	 * on these lists, so it is safe to use __llist_del_all().
	 */
	free_all(__llist_del_all(&c->free_by_rcu), percpu);
	c->free_by_rcu_tail = NULL;

	/* Use lock to update head and tail atomically */
	raw_spin_lock_irqsave(&c->lock, flags);
	head = __llist_del_all(&c->waiting_for_gp);
	c->waiting_for_gp_tail = NULL;
	raw_spin_unlock_irqrestore(&c->lock, flags);
	free_all(head, percpu);

	free_all(__llist_del_all(&c->free_llist), percpu);
	free_all(__llist_del_all(&c->free_llist_extra), percpu);

	head = __llist_del_all(&c->prepare_reuse_head);
	c->prepare_reuse_tail = NULL;
	free_all(head, percpu);
}

static void free_mem_alloc_no_barrier(struct bpf_mem_alloc *ma)
{
	free_percpu(ma->cache);
	free_percpu(ma->caches);
	kfree(ma->s_cache);
	kfree(ma->s_caches);
	ma->cache = NULL;
	ma->caches = NULL;
	ma->s_cache = NULL;
	ma->s_caches = NULL;
}

static void free_mem_alloc(struct bpf_mem_alloc *ma)
{
	/* Use rcu_barrier() to wait for the pending reuse_rcu() and use
	 * rcu_barrier_tasks_trace() to wait for the pending free_rcu().
	 * direct_free has already been set to prevent reuse_rcu() from
	 * calling freee_rcu() again.
	 */
	rcu_barrier();
	rcu_barrier_tasks_trace();
	free_mem_alloc_no_barrier(ma);
}

static void free_mem_alloc_deferred(struct work_struct *work)
{
	struct bpf_mem_alloc *ma = container_of(work, struct bpf_mem_alloc, work);

	free_mem_alloc(ma);
	kfree(ma);
}

static void destroy_mem_alloc(struct bpf_mem_alloc *ma, int rcu_in_progress)
{
	struct bpf_mem_alloc *copy;

	if (!rcu_in_progress) {
		/* Fast path. No callbacks are pending, hence no need to do
		 * rcu_barrier-s.
		 */
		free_mem_alloc_no_barrier(ma);
		return;
	}

	copy = kmalloc(sizeof(*ma), GFP_KERNEL);
	if (!copy) {
		/* Slow path with inline barrier-s */
		free_mem_alloc(ma);
		return;
	}

	/* Defer barriers into worker to let the rest of map memory to be freed */
	copy->cache = ma->cache;
	copy->s_cache = ma->s_cache;
	ma->cache = NULL;
	ma->s_cache = NULL;
	copy->caches = ma->caches;
	copy->s_caches = ma->s_caches;
	ma->caches = NULL;
	ma->s_caches = NULL;
	INIT_WORK(&copy->work, free_mem_alloc_deferred);
	queue_work(system_unbound_wq, &copy->work);
}

void bpf_mem_alloc_destroy(struct bpf_mem_alloc *ma)
{
	struct bpf_mem_shared_cache *sc;
	struct bpf_mem_caches *cc;
	struct bpf_mem_cache *c;
	int cpu, i, rcu_in_progress;

	if (ma->cache) {
		rcu_in_progress = 0;
		for_each_possible_cpu(cpu) {
			c = per_cpu_ptr(ma->cache, cpu);
			/*
			 * refill_work may be unfinished for PREEMPT_RT kernel
			 * in which irq work is invoked in a per-CPU RT thread.
			 * It is also possible for kernel with
			 * arch_irq_work_has_interrupt() being false and irq
			 * work is invoked in timer interrupt. So waiting for
			 * the completion of irq work to ease the handling of
			 * concurrency.
			 */
			irq_work_sync(&c->refill_work);
			drain_mem_cache(c);
			rcu_in_progress += atomic_read(&c->call_rcu_in_progress);
		}
		sc = ma->s_cache;
		drain_shared_mem_cache(sc);
		rcu_in_progress += atomic_read(&sc->call_rcu_in_progress);
		/* objcg is the same across cpus */
		if (c->objcg)
			obj_cgroup_put(c->objcg);
		destroy_mem_alloc(ma, rcu_in_progress);
	}
	if (ma->caches) {
		rcu_in_progress = 0;
		for_each_possible_cpu(cpu) {
			cc = per_cpu_ptr(ma->caches, cpu);
			for (i = 0; i < NUM_CACHES; i++) {
				c = &cc->cache[i];
				irq_work_sync(&c->refill_work);
				drain_mem_cache(c);
				rcu_in_progress += atomic_read(&c->call_rcu_in_progress);
			}
		}
		for (i = 0; i < NUM_CACHES; i++) {
			sc = &ma->s_caches->cache[i];
			drain_shared_mem_cache(sc);
			rcu_in_progress += atomic_read(&sc->call_rcu_in_progress);
		}
		if (c->objcg)
			obj_cgroup_put(c->objcg);
		destroy_mem_alloc(ma, rcu_in_progress);
	}
}

/* notrace is necessary here and in other functions to make sure
 * bpf programs cannot attach to them and cause llist corruptions.
 */
static void notrace *unit_alloc(struct bpf_mem_cache *c)
{
	struct llist_node *llnode = NULL;
	unsigned long flags;
	int cnt = 0;

	/* Disable irqs to prevent the following race for majority of prog types:
	 * prog_A
	 *   bpf_mem_alloc
	 *      preemption or irq -> prog_B
	 *        bpf_mem_alloc
	 *
	 * but prog_B could be a perf_event NMI prog.
	 * Use per-cpu 'active' counter to order free_list access between
	 * unit_alloc/unit_free/bpf_mem_refill.
	 */
	local_irq_save(flags);
	if (local_inc_return(&c->active) == 1) {
		llnode = __llist_del_first(&c->free_llist);
		if (llnode)
			cnt = --c->free_cnt;
	}
	local_dec(&c->active);
	local_irq_restore(flags);

	WARN_ON(cnt < 0);

	if (cnt < c->low_watermark)
		irq_work_raise(c);
	return llnode;
}

/* Though 'ptr' object could have been allocated on a different cpu
 * add it to the prepare_reuse list of the current cpu.
 * Let kfree() logic deal with it when it's later called from RCU cb.
 */
static void notrace unit_free(struct bpf_mem_cache *c, void *ptr)
{
	struct llist_node *llnode = ptr - LLIST_NODE_SZ;
	unsigned long flags;
	int cnt = 0;

	BUILD_BUG_ON(LLIST_NODE_SZ > 8);

	local_irq_save(flags);
	/* In case a NMI-context bpf program is also freeing object. */
	if (local_inc_return(&c->active) == 1) {
		if (llist_empty(&c->prepare_reuse_head))
			c->prepare_reuse_tail = llnode;
		__llist_add(llnode, &c->prepare_reuse_head);
		cnt = ++c->prepare_reuse_cnt;
	} else {
		/* unit_free() cannot fail. Therefore add an object to atomic
		 * llist. reuse_bulk() will drain it. Though free_llist_extra is
		 * a per-cpu list we have to use atomic llist_add here, since
		 * it also can be interrupted by bpf nmi prog that does another
		 * unit_free() into the same free_llist_extra.
		 */
		llist_add(llnode, &c->free_llist_extra);
	}
	local_dec(&c->active);
	local_irq_restore(flags);

	if (cnt > c->high_watermark)
		/* free few objects from current cpu into global kmalloc pool */
		irq_work_raise(c);
}

/* Called from BPF program or from sys_bpf syscall.
 * In both cases migration is disabled.
 */
void notrace *bpf_mem_alloc(struct bpf_mem_alloc *ma, size_t size)
{
	int idx;
	void *ret;

	if (!size)
		return ZERO_SIZE_PTR;

	idx = bpf_mem_cache_idx(size + LLIST_NODE_SZ);
	if (idx < 0)
		return NULL;

	ret = unit_alloc(this_cpu_ptr(ma->caches)->cache + idx);
	return !ret ? NULL : ret + LLIST_NODE_SZ;
}

void notrace bpf_mem_free(struct bpf_mem_alloc *ma, void *ptr)
{
	int idx;

	if (!ptr)
		return;

	idx = bpf_mem_cache_idx(ksize(ptr - LLIST_NODE_SZ));
	if (idx < 0)
		return;

	unit_free(this_cpu_ptr(ma->caches)->cache + idx, ptr);
}

void notrace *bpf_mem_cache_alloc(struct bpf_mem_alloc *ma)
{
	void *ret;

	ret = unit_alloc(this_cpu_ptr(ma->cache));
	return !ret ? NULL : ret + LLIST_NODE_SZ;
}

void notrace bpf_mem_cache_free(struct bpf_mem_alloc *ma, void *ptr)
{
	if (!ptr)
		return;

	unit_free(this_cpu_ptr(ma->cache), ptr);
}

/* Directly does a kfree() without putting 'ptr' back to the free_llist
 * for reuse and without waiting for a rcu_tasks_trace gp.
 * The caller must first go through the rcu_tasks_trace gp for 'ptr'
 * before calling bpf_mem_cache_raw_free().
 * It could be used when the rcu_tasks_trace callback does not have
 * a hold on the original bpf_mem_alloc object that allocated the
 * 'ptr'. This should only be used in the uncommon code path.
 * Otherwise, the bpf_mem_alloc's free_llist cannot be refilled
 * and may affect performance.
 */
void bpf_mem_cache_raw_free(void *ptr)
{
	if (!ptr)
		return;

	kfree(ptr - LLIST_NODE_SZ);
}

/* When flags == GFP_KERNEL, it signals that the caller will not cause
 * deadlock when using kmalloc. bpf_mem_cache_alloc_flags() will use
 * kmalloc if the free_llist is empty.
 */
void notrace *bpf_mem_cache_alloc_flags(struct bpf_mem_alloc *ma, gfp_t flags)
{
	struct bpf_mem_cache *c;
	void *ret;

	c = this_cpu_ptr(ma->cache);

	ret = unit_alloc(c);
	if (!ret && flags == GFP_KERNEL) {
		struct mem_cgroup *memcg, *old_memcg;

		memcg = get_memcg(c);
		old_memcg = set_active_memcg(memcg);
		ret = __alloc(c, NUMA_NO_NODE, GFP_KERNEL | __GFP_NOWARN | __GFP_ACCOUNT);
		set_active_memcg(old_memcg);
		mem_cgroup_put(memcg);
	}

	return !ret ? NULL : ret + LLIST_NODE_SZ;
}
