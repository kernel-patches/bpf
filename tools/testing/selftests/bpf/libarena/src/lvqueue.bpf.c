// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/*
 * Copyright (c) 2025-2026 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025-2026 Emil Tsalapatis <etsal@meta.com>
 */

#include <bpf_atomic.h>

#include <libarena/common.h>

#include <libarena/asan.h>
#include <libarena/lvqueue.h>

static inline
u64 lv_arr_size(lv_arr_t *lv_arr)
{
	return LV_ARR_BASESZ << READ_ONCE(lv_arr->order);
}

static inline
u64 lv_arr_get(lv_arr_t *lv_arr, u64 ind)
{
	u64 ret = READ_ONCE(lv_arr->data[ind % lv_arr_size(lv_arr)]);

	return ret;
}

static inline
void lv_arr_put(lv_arr_t *lv_arr, u64 ind, u64 value)
{
	WRITE_ONCE(lv_arr->data[ind % lv_arr_size(lv_arr)], value);
}

static inline
void lv_arr_copy(lv_arr_t *dst, lv_arr_t *src, u64 b, u64 t)
{
	u64 i;

	for (i = t; i < b && can_loop; i++)
		lv_arr_put(dst, i, lv_arr_get(src, i));
}

static inline
int lvq_order_init(lv_queue_t *lvq __arg_arena, int order)
{
	lv_arr_t *arr = &lvq->arr[order];

	if (unlikely(!lvq))
		return -EINVAL;

	if (order >= LV_ARR_ORDERS)
		return -E2BIG;

	/* Already allocated? */
	if (arr->data)
		return 0;

	arr->data = (u64 __arena *)malloc((LV_ARR_BASESZ << order) * sizeof(*arr->data));
	if (!arr->data)
		return -ENOMEM;

	return 0;
}

__weak
int lvq_owner_push(lv_queue_t *lvq __arg_arena, u64 val)
{
	volatile u64 b, t;
	lv_arr_t *newarr;
	lv_arr_t *arr;
	ssize_t sz;
	int ret;

	if (unlikely(!lvq))
		return -EINVAL;

	b = smp_load_acquire(&lvq->bottom);

	/*
	 * In this call, loads from bottom and top should be
	 * in this order specifically (also see lvq_steal()).
	 */
	smp_rmb();

	t = READ_ONCE(lvq->top);
	arr = READ_ONCE(lvq->cur);

	sz = b - t;
	if (sz >= lv_arr_size(arr) - 1) {
		ret = lvq_order_init(lvq, arr->order + 1);
		if (ret)
			return ret;

		newarr = &lvq->arr[arr->order + 1];

		lv_arr_copy(newarr, arr, b, t);
		smp_store_release(&lvq->cur, newarr);
	}

	lv_arr_put(lvq->cur, b, val);
	smp_store_release(&lvq->bottom, b + 1);

	return 0;
}


__weak
int lvq_owner_pop(lv_queue_t *lvq __arg_arena, u64 *val)
{
	lv_arr_t *arr;
	volatile u64 b, t;
	int ret = 0;
	ssize_t sz;
	u64 value;

	if (unlikely(!lvq || !val))
		return -EINVAL;

	arr = smp_load_acquire(&lvq->cur);

	b = READ_ONCE(lvq->bottom);
	b -= 1;

	WRITE_ONCE(lvq->bottom, b);

	smp_mb();

	t = READ_ONCE(lvq->top);
	sz = b - t;
	if (sz < 0) {
		smp_store_release(&lvq->bottom, t);
		return -ENOENT;
	}

	value = lv_arr_get(arr, b);
	if (sz > 0) {
		*val = value;
		return 0;
	}

	if (cmpxchg(&lvq->top, t, t + 1) != t)
		ret = -EAGAIN;

	smp_store_release(&lvq->bottom, t + 1);

	if (ret)
		return ret;

	*val = value;

	return 0;
}

__weak
int lvq_steal(lv_queue_t *lvq __arg_arena, u64 *val)
{
	volatile u64 b, t;
	lv_arr_t *arr;
	ssize_t sz;
	u64 value;

	if (unlikely(!lvq || !val))
		return -EINVAL;

	t = smp_load_acquire(&lvq->top);

	/*
	 * It is important that t is read before b for
	 * stealers to avoid racing with the owner.
	 * Races between stealers are dealt with using
	 * CAS to increment the top value below.
	 */
	smp_rmb();

	b = READ_ONCE(lvq->bottom);
	arr = READ_ONCE(lvq->cur);

	sz = b - t;
	if (sz <= 0)
		return -ENOENT;

	value = lv_arr_get(arr, t);

	if (cmpxchg(&lvq->top, t, t + 1) != t)
		return -EAGAIN;

	smp_store_release(val, value);

	return 0;
}


__weak
u64 lvq_create_internal(void)
{
	/*
	 * Marked as volatile because otherwise the array
	 * reference in the internal loop gets demoted to
	 * scalar and the program fails verification.
	 */
	volatile lv_queue_t *lvq;
	int ret, i;

	lvq = malloc(sizeof(*lvq));
	if (!lvq)
		return (u64)NULL;

	WRITE_ONCE(lvq->bottom, 0);
	WRITE_ONCE(lvq->top, 0);

	for (i = 0; i < LV_ARR_ORDERS && can_loop; i++) {
		lvq->arr[i].data = NULL;
		lvq->arr[i].order = i;
	}

	ret = lvq_order_init((lv_queue_t *)lvq, 0);
	if (ret) {
		free(lvq);
		return (u64)NULL;
	}

	smp_store_release(&lvq->cur, &lvq->arr[0]);

	return (u64)(lvq);
}

__weak
int lvq_destroy(lv_queue_t *lvq __arg_arena)
{
	int i;

	if (unlikely(!lvq))
		return -EINVAL;

	for (i = 0; i < LV_ARR_ORDERS && can_loop; i++)
		free(lvq->arr[i].data);

	free(lvq);

	return 0;
}
