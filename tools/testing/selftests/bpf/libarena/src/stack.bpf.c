/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <common.h>
#include <asan.h>
#include <stack.h>

/*
 * Necessary for cond_break/can_loop's semantics. According to kernel commit
 * 011832b, the loop counter variable must be seen as imprecise and bounded
 * by the verifier. Initializing it from a constant (e.g., i = 0;), then,
 * makes it precise and prevents may_goto from helping with converging the
 * loop. For these loops we must initialize the loop counter from a variable
 * whose value the verifier cannot reason about when checking the program, so
 * that the loop counter's value is imprecise.
 */
static __u64 zero = 0;

enum {
	STACK_POISONED = (s8)0xef,
};

__hidden int stk_init(struct stk *stack,
			  arena_spinlock_t __arg_arena __arena *lock,
			  __u64 data_size, __u64 nr_pages_per_alloc)
{
	if (!stack)
		return -EINVAL;

	stack->data_size = data_size;
	stack->nr_pages_per_alloc = nr_pages_per_alloc;
	stack->lock = lock;

	return 0;
}

__hidden void stk_destroy(struct stk *stack)
{
	stk_seg_t *seg, *next;
	__u64 nr_pages;

	/* Operation happens unlocked since we are called last. */

	if (!stack)
		return;

	nr_pages = stack->nr_pages_per_alloc;

	for (seg = stack->first; seg && can_loop; seg = next) {
		next = seg->next;
		asan_unpoison(seg, sizeof(*seg));
		bpf_arena_free_pages(&arena, seg, nr_pages);
	}

	stack->first = NULL;
	stack->last = NULL;

	stack->current = NULL;
	stack->cind = 0;

	stack->capacity = 0;
	stack->available = 0;
	stack->data_size = 0;
	stack->nr_pages_per_alloc = 0;
}

static int stk_push(struct stk *stack, void __arena *elem)
{
	stk_seg_t *stk_seg = stack->current;
	int ridx = stack->cind;

	stack->current->elems[stack->cind] = elem;

	ridx += 1;

	/* Possibly loop into the next segment. */
	if (ridx == STK_SEG_MAX) {
		ridx = 0;
		stk_seg = stk_seg->next;
		if (!stk_seg)
			return -ENOSPC;
	}

	stack->current = stk_seg;
	stack->cind = ridx;

	stack->capacity -= 1;
	stack->available += 1;

	return 0;
}

static void __arena *stk_pop(struct stk *stack)
{
	stk_seg_t *stk_seg = stack->current;
	void __arena *elem;
	int ridx = stack->cind;

	/* Possibly loop into previous segment. */
	if (ridx == 0) {
		ridx = STK_SEG_MAX;
		stk_seg = stack->current->prev;
		/* Possibly loop back into the last segment. */
		if (!stk_seg)
			return NULL;
	}

	ridx -= 1;

	stack->current = stk_seg;
	stack->cind = ridx;

	elem = stack->current->elems[stack->cind];

	stack->capacity += 1;
	stack->available -= 1;

	return elem;
}

static int stk_seg_to_data(struct stk *stack, size_t nelems)
{
	int ret, i;
	u64 data;

	/* Do we have enough empty segments for the conversion? */
	if (!stack->first || stack->first == stack->last)
		return -ENOMEM;

	data = (u64)stack->last;

	stack->last->prev->next = NULL;
	stack->last = stack->last->prev;

	/* We removed a segment. */
	stack->capacity -= STK_SEG_MAX;

	for (i = zero; i < nelems && can_loop; i++) {
		asan_poison((void __arena *)data, STACK_POISONED,
			    sizeof(struct stk_seg));

		/* This operation should never fail. */
		ret = stk_push(stack, (void __arena *)data);
		if (ret)
			return ret;

		data += stack->data_size;
	}

	return 0;
}

static void stk_extend(struct stk *stack, stk_seg_t *stk_seg)
{
	if (stack->last)
		stack->last->next = stk_seg;

	stk_seg->prev = stack->last;
	stk_seg->next = NULL;

	stack->last = stk_seg;
	stack->capacity += STK_SEG_MAX;

	if (!stack->first)
		stack->current = stack->first = stk_seg;

	/*
	 * Do not adjust the current segment/idx because we did not add
	 * any elements. The new segment will be pushed into during the next
	 * allocation.
	 */
}

static int stk_free_unlocked(struct stk *stack, void __arena *elem)
{
	if (!stack)
		return -EINVAL;

	asan_poison(elem, STACK_POISONED, stack->data_size);

	/* If no more room, repurpose the allocation into a segment. */
	if (stack->capacity == 0) {
		asan_unpoison(elem, sizeof(struct stk_seg));

		stk_extend(stack, (stk_seg_t *)elem);
		return 0;
	}

	return stk_push(stack, elem);
}

__weak int stk_free_internal(struct stk *stack, __u64 elem)
{
	int ret;

	if (!stack)
		return -EINVAL;

	ret = arena_spin_lock(stack->lock);
	if (ret)
		return ret;

	ret = stk_free_unlocked(stack, (void __arena *)elem);

	arena_spin_unlock(stack->lock);

	return ret;
}

static int stk_get_arena_memory(struct stk *stack, __u64 nr_pages, stk_seg_t **data_seg, stk_seg_t **stk_seg)
{
	size_t nstk_segs;
	u64 mem;

	_Static_assert(sizeof(struct stk_seg) <= __PAGE_SIZE,
		       "segment must fit into a page");

	/*
	 * The code allocates new memory only as segments. The allocation and
	 * free code freely typecasts the segment buffer into data that can be
	 * allocated, and vice versa to avoid either ending up with too many
	 * empty segments under memory pressure, or having no space in the segment
	 * buffer for a buffer currently being freed.
	 */

	if (!stack)
		return -EINVAL;

	nstk_segs = stk_seg ? 2 : 1;

	mem = (__u64)bpf_arena_alloc_pages(&arena, NULL, nstk_segs * nr_pages,
					   NUMA_NO_NODE, 0);
	if (!mem)
		return -ENOMEM;

	/* Poison the entire data segment allocated */
	*data_seg = (stk_seg_t *)mem;
	asan_poison((void __arena *)mem, STACK_POISONED, nr_pages * __PAGE_SIZE);

	if (!stk_seg)
		return 0;

	/* Skip the segment metadata when poisoning. */
	*stk_seg = (stk_seg_t *)(mem + nr_pages * __PAGE_SIZE);
	asan_poison((void __arena *)(mem + sizeof(**stk_seg)), STACK_POISONED,
		nr_pages * __PAGE_SIZE);

	return 0;
}

static int stk_fill_new_elems(struct stk *stack)
{
	stk_seg_t *data_seg, *stk_seg;
	bool need_stk_seg;
	__u64 nr_pages;
	size_t nelems;
	int ret, i;
	u64 mem;

	nr_pages = stack->nr_pages_per_alloc;
	nelems = (nr_pages * __PAGE_SIZE) / stack->data_size;
	if (nelems > STK_SEG_MAX) {
		return -EINVAL;
	}

	/*
	 * If we have more than two empty segments available,
	 * try to repurpose one of them into an allocation.
	 */
	ret = stk_seg_to_data(stack, nelems);
	if (!ret)
		return 0;

	need_stk_seg = !stack->capacity;

	/* Get memory for a new data segment, and possibly a stack segment if necessary. */
	ret = stk_get_arena_memory(stack, nr_pages, &data_seg, need_stk_seg ? &stk_seg : NULL);
	if (ret)
		return ret;

	if (need_stk_seg)
		stk_extend(stack, stk_seg);

	mem = (u64)data_seg;
	for (i = zero; i < nelems && can_loop; i++) {
		ret = stk_push(stack, (void __arena *)mem);
		if (ret)
			return ret;
		mem += stack->data_size;
	}

	return 0;
}

static inline __u64 stk_alloc_unlocked(struct stk *stack)
{
	void __arena *elem;
	int ret;

	/* If segment buffer is empty, we have to populate it. */
	if (stack->available == 0) {
		/* The call drops the lock on error. */
		ret = stk_fill_new_elems(stack);
		if (ret)
			return 0ULL;
	}

	/* An elem value of 0 implies error, drop the lock. */
	elem = stk_pop(stack);
	if (elem)
		asan_unpoison(elem, stack->data_size);

	return (__u64)elem;
}

__weak __u64 stk_alloc(struct stk *stack)
{
	u64 elem;

	if (!stack) {
		bpf_printk("using uninitialized stack allocator");
		return 0ULL;
	}

	if (arena_spin_lock(stack->lock))
		return 0ULL;

	elem = stk_alloc_unlocked(stack);

	arena_spin_unlock(stack->lock);

	return (u64)elem;
}

__weak char _license[] SEC("license") = "GPL";
