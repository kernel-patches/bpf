// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause

#include <libarena/common.h>

#include <libarena/asan.h>
#include <libarena/lvqueue.h>

/*
 * NOTE: These selftests only test for the single-threaded use case, which for
 * Lev-Chase queues is obviously the simplest one. Still, it is important to
 * exercise the API to ensure it passes verification and basic checks.
 */

SEC("syscall")
int test_lvqueue_pop_empty(void)
{
	u64 val;
	int ret;

	lv_queue_t *lvq = lvq_create();

	if (!lvq)
		return 1;

	ret = lvq_owner_pop(lvq, &val);
	if (ret != -ENOENT)
		return 1;

	lvq_destroy(lvq);

	return 0;
}

SEC("syscall")
int test_lvqueue_steal_empty(void)
{
	u64 val;
	int ret;

	lv_queue_t *lvq = lvq_create();

	if (!lvq)
		return 1;

	ret = lvq_steal(lvq, &val);
	if (ret != -ENOENT)
		return 1;

	lvq_destroy(lvq);

	return 0;
}

SEC("syscall")
int test_lvqueue_steal_one(void)
{
	u64 val, newval;
	int ret, i;

	lv_queue_t *lvq = lvq_create();

	if (!lvq)
		return 1;

	for (i = 0; i < 10 && can_loop; i++) {
		val = i;

		ret = lvq_owner_push(lvq, val);
		if (ret)
			return 1;

		ret = lvq_steal(lvq, &newval);
		if (ret)
			return 2;

		if (val != newval)
			return 3;
	}

	lvq_destroy(lvq);

	return 0;
}

SEC("syscall")
int test_lvqueue_pop_one(void)
{
	u64 val, newval;
	int ret, i;

	lv_queue_t *lvq = lvq_create();

	if (!lvq)
		return 1;

	for (i = 0; i < 10 && can_loop; i++) {
		val = i;

		ret = lvq_owner_push(lvq, val);
		if (ret)
			return 1;

		ret = lvq_owner_pop(lvq, &newval);
		if (ret)
			return 2;

		if (val != newval)
			return 3;
	}

	lvq_destroy(lvq);

	return 0;
}

SEC("syscall")
int test_lvqueue_pop_many(void)
{
	u64 val, newval;
	int ret, i;
	u64 expected;

	lv_queue_t *lvq = lvq_create();

	if (!lvq)
		return 1;

	for (i = 0; i < 500 && can_loop; i++) {
		val = i;

		ret = lvq_owner_push(lvq, val);
		if (ret) {
			arena_stderr("%s:%d error %d\n", __func__, __LINE__, ret);
			return 1;
		}
	}

	for (i = 0; i < 500 && can_loop; i++) {
		ret = lvq_owner_pop(lvq, &newval);
		if (ret) {
			arena_stderr("%s:%d error %d\n", __func__, __LINE__, ret);
			return 1;
		}

		expected = 500 - 1 - i;
		if (newval != expected) {
			arena_stderr("%s:%d expected %lu found %lu\n", __func__, __LINE__, expected, newval);
			return 1;
		}
	}

	lvq_destroy(lvq);

	return 0;
}

SEC("syscall")
int test_lvqueue_steal_many(void)
{
	u64 val, newval;
	int ret, i;

	lv_queue_t *lvq = lvq_create();

	if (!lvq)
		return 1;

	for (i = 0; i < 500 && can_loop; i++) {
		val = i;

		ret = lvq_owner_push(lvq, val);
		if (ret) {
			arena_stderr("%s:%d error %d\n", __func__, __LINE__, ret);
			return 1;
		}
	}

	for (i = 0; i < 500 && can_loop; i++) {
		ret = lvq_steal(lvq, &newval);
		if (ret) {
			arena_stderr("%s:%d error %d\n", __func__, __LINE__, ret);
			return 1;
		}

		if (newval != i) {
			arena_stderr("%s:%d expected %lu found %lu\n", __func__, __LINE__, i, newval);
			return 1;
		}
	}

	lvq_destroy(lvq);

	return 0;
}
