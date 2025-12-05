// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * Tests for libbpf's hashmap.
 *
 * Copyright (c) 2019 Facebook
 */
#include "test_progs.h"
#include "bpf/hashmap.h"
#include <stddef.h>

static size_t hash_fn(long k, void *ctx)
{
	return k;
}

static bool equal_fn(long a, long b, void *ctx)
{
	return a == b;
}

static inline size_t next_pow_2(size_t n)
{
	size_t r = 1;

	while (r < n)
		r <<= 1;
	return r;
}

static inline size_t exp_cap(size_t sz)
{
	size_t r = next_pow_2(sz);

	if (sz * 4 / 3 > r)
		r <<= 1;
	return r;
}

#define ELEM_CNT 62

static void test_hashmap_generic(void)
{
	struct hashmap_entry *entry, *tmp;
	int err, bkt, found_cnt, i;
	long long found_msk;
	struct hashmap *map;

	map = hashmap__new(hash_fn, equal_fn, NULL);
	if (!ASSERT_OK_PTR(map, "hashmap__new"))
		return;

	for (i = 0; i < ELEM_CNT; i++) {
		long oldk, k = i;
		long oldv, v = 1024 + i;

		err = hashmap__update(map, k, v, &oldk, &oldv);
		if (!ASSERT_EQ(err, -ENOENT, "hashmap__update"))
			goto cleanup;

		if (i % 2) {
			err = hashmap__add(map, k, v);
		} else {
			err = hashmap__set(map, k, v, &oldk, &oldv);
			if (oldk != 0 || oldv != 0) {
				PRINT_FAIL("unexpected k/v: %ld=%ld\n", oldk, oldv);
				goto cleanup;
			}
		}

		if (err) {
			PRINT_FAIL("failed to add k/v %ld = %ld: %d\n", k, v, err);
			goto cleanup;
		}

		if (!hashmap__find(map, k, &oldv)) {
			PRINT_FAIL("failed to find key %ld\n", k);
			goto cleanup;
		}
		if (!ASSERT_EQ(oldv, v, "elem_val"))
			goto cleanup;
	}

	if (!ASSERT_EQ(hashmap__size(map), ELEM_CNT, "hashmap__size"))
		goto cleanup;
	if (!ASSERT_EQ(hashmap__capacity(map), exp_cap(hashmap__size(map)),
		       "hashmap_cap"))
		goto cleanup;

	found_msk = 0;
	hashmap__for_each_entry(map, entry, bkt) {
		long k = entry->key;
		long v = entry->value;

		found_msk |= 1ULL << k;
		if (!ASSERT_EQ(v - k, 1024, "check_kv")) {
			printf("invalid k/v pair: %ld = %ld\n", k, v);
			goto cleanup;
		}
	}
	if (!ASSERT_EQ(found_msk, (1ULL << ELEM_CNT) - 1, "elem_cnt"))
		goto cleanup;

	for (i = 0; i < ELEM_CNT; i++) {
		long oldk, k = i;
		long oldv, v = 256 + i;

		err = hashmap__add(map, k, v);
		if (!ASSERT_EQ(err, -EEXIST, "hashmap__add"))
			goto cleanup;

		if (i % 2)
			err = hashmap__update(map, k, v, &oldk, &oldv);
		else
			err = hashmap__set(map, k, v, &oldk, &oldv);

		if (err) {
			PRINT_FAIL("failed to update k/v %ld = %ld: %d\n", k, v, err);
			goto cleanup;
		}
		if (!hashmap__find(map, k, &oldv)) {
			PRINT_FAIL("failed to find key %ld\n", k);
			goto cleanup;
		}
		if (!ASSERT_EQ(oldv, v, "elem_val"))
			goto cleanup;
	}

	if (!ASSERT_EQ(hashmap__size(map), ELEM_CNT, "hashmap__size"))
		goto cleanup;
	if (!ASSERT_EQ(hashmap__capacity(map), exp_cap(hashmap__size(map)),
		       "hashmap__capacity"))
		goto cleanup;

	found_msk = 0;
	hashmap__for_each_entry_safe(map, entry, tmp, bkt) {
		long k = entry->key;
		long v = entry->value;

		found_msk |= 1ULL << k;
		if (!ASSERT_EQ(v - k, 256, "elem_check")) {
			printf("invalid updated k/v pair: %ld = %ld\n", k, v);
			goto cleanup;
		}
	}
	if (!ASSERT_EQ(found_msk, (1ULL << ELEM_CNT) - 1, "elem_cnt"))
		goto cleanup;

	found_cnt = 0;
	hashmap__for_each_key_entry(map, entry, 0) {
		found_cnt++;
	}
	if (!found_cnt)
		PRINT_FAIL("didn't find any entries for key 0\n");

	found_msk = 0;
	found_cnt = 0;
	hashmap__for_each_key_entry_safe(map, entry, tmp, 0) {
		long oldk, k;
		long oldv, v;

		k = entry->key;
		v = entry->value;

		found_cnt++;
		found_msk |= 1ULL << k;

		if (!hashmap__delete(map, k, &oldk, &oldv)) {
			PRINT_FAIL("failed to delete k/v %ld = %ld\n", k, v);
			goto cleanup;
		}
		if (oldk != k || oldv != v) {
			PRINT_FAIL("invalid deleted k/v: expected %ld = %ld, got %ld = %ld\n",
				   k, v, oldk, oldv);
			goto cleanup;
		}
		if (hashmap__delete(map, k, &oldk, &oldv)) {
			PRINT_FAIL("unexpectedly deleted k/v %ld = %ld\n", oldk, oldv);
			goto cleanup;
		}
	}

	if (!found_cnt || !found_msk)
		PRINT_FAIL("didn't delete any key entries\n");
	if (!ASSERT_EQ(hashmap__size(map), ELEM_CNT - found_cnt, "elem_cnt"))
		goto cleanup;
	if (!ASSERT_EQ(hashmap__capacity(map), exp_cap(hashmap__size(map)),
		       "hashmap__capacity"))
		goto cleanup;

	hashmap__for_each_entry_safe(map, entry, tmp, bkt) {
		long oldk, k;
		long oldv, v;

		k = entry->key;
		v = entry->value;

		found_cnt++;
		found_msk |= 1ULL << k;

		if (!hashmap__delete(map, k, &oldk, &oldv)) {
			PRINT_FAIL("failed to delete k/v %ld = %ld\n", k, v);
			goto cleanup;
		}
		if (oldk != k || oldv != v) {
			PRINT_FAIL("invalid old k/v: expect %ld = %ld, got %ld = %ld\n",
				   k, v, oldk, oldv);
			goto cleanup;
		}
		if (hashmap__delete(map, k, &oldk, &oldv)) {
			PRINT_FAIL("unexpectedly deleted k/v %ld = %ld\n", k, v);
			goto cleanup;
		}
	}

	if (found_cnt != ELEM_CNT || found_msk != (1ULL << ELEM_CNT) - 1) {
		PRINT_FAIL("not all keys were deleted: found_cnt:%d, found_msk:%llx\n",
			   found_cnt, found_msk);
		goto cleanup;
	}
	if (!ASSERT_EQ(hashmap__size(map), 0, "hashmap__size"))
		goto cleanup;

	found_cnt = 0;
	hashmap__for_each_entry(map, entry, bkt) {
		PRINT_FAIL("unexpected map entries left: %ld = %ld\n", entry->key, entry->value);
		goto cleanup;
	}

	hashmap__clear(map);
	hashmap__for_each_entry(map, entry, bkt) {
		PRINT_FAIL("unexpected map entries left: %ld = %ld\n", entry->key, entry->value);
		goto cleanup;
	}

cleanup:
	hashmap__free(map);
}

static size_t str_hash_fn(long a, void *ctx)
{
	return str_hash((char *)a);
}

static bool str_equal_fn(long a, long b, void *ctx)
{
	return strcmp((char *)a, (char *)b) == 0;
}

/* Verify that hashmap interface works with pointer keys and values */
static void test_hashmap_ptr_iface(void)
{
	const char *key, *value, *old_key, *old_value;
	struct hashmap_entry *cur;
	struct hashmap *map;
	int err, i, bkt;

	map = hashmap__new(str_hash_fn, str_equal_fn, NULL);
	if (!ASSERT_OK_PTR(map, "hashmap__new"))
		goto cleanup;

#define CHECK_STR(fn, var, expected)					\
	if (strcmp(var, (expected)))					\
		PRINT_FAIL("wrong value of " #var ": '%s' instead of '%s'\n", \
			   var, (expected))

	err = hashmap__insert(map, "a", "apricot", HASHMAP_ADD, NULL, NULL);
	if (!ASSERT_OK(err, "hashmap__insert"))
		goto cleanup;

	err = hashmap__insert(map, "a", "apple", HASHMAP_SET, &old_key, &old_value);
	if (!ASSERT_OK(err, "hashmap__insert"))
		goto cleanup;
	CHECK_STR("hashmap__update", old_key, "a");
	CHECK_STR("hashmap__update", old_value, "apricot");

	err = hashmap__add(map, "b", "banana");
	if (!ASSERT_OK(err, "hashmap__add"))
		goto cleanup;

	err = hashmap__set(map, "b", "breadfruit", &old_key, &old_value);
	if (!ASSERT_OK(err, "hashmap__set"))
		goto cleanup;
	CHECK_STR("hashmap__set", old_key, "b");
	CHECK_STR("hashmap__set", old_value, "banana");

	err = hashmap__update(map, "b", "blueberry", &old_key, &old_value);
	if (!ASSERT_OK(err, "hashmap__update"))
		goto cleanup;
	CHECK_STR("hashmap__update", old_key, "b");
	CHECK_STR("hashmap__update", old_value, "breadfruit");

	err = hashmap__append(map, "c", "cherry");
	if (!ASSERT_OK(err, "hashmap__append"))
		goto cleanup;

	if (!hashmap__delete(map, "c", &old_key, &old_value)) {
		PRINT_FAIL("expected to have entry for 'c'\n");
		goto cleanup;
	}
	CHECK_STR("hashmap__delete", old_key, "c");
	CHECK_STR("hashmap__delete", old_value, "cherry");

	if (!hashmap__find(map, "b", &value))
		PRINT_FAIL("can't find value for 'b'\n");
	CHECK_STR("hashmap__find", value, "blueberry");

	if (!hashmap__delete(map, "b", NULL, NULL)) {
		PRINT_FAIL("expected to have entry for 'b'\n");
		goto cleanup;
	}

	i = 0;
	hashmap__for_each_entry(map, cur, bkt) {
		if (i != 0) {
			PRINT_FAIL("too many entries\n");
			goto cleanup;
		}
		key = cur->pkey;
		value = cur->pvalue;
		CHECK_STR("entry", key, "a");
		CHECK_STR("entry", value, "apple");
		i++;
	}
#undef CHECK_STR

cleanup:
	hashmap__free(map);
}

static size_t collision_hash_fn(long k, void *ctx)
{
	return 0;
}

static void test_hashmap_multimap(void)
{
	long k1 = 0, k2 = 1;
	struct hashmap_entry *entry;
	struct hashmap *map;
	long found_msk;
	int err, bkt;

	/* force collisions */
	map = hashmap__new(collision_hash_fn, equal_fn, NULL);
	if (!ASSERT_OK_PTR(map, "hashmap__new"))
		return;

	/* set up multimap:
	 * [0] -> 1, 2, 4;
	 * [1] -> 8, 16, 32;
	 */
	err = hashmap__append(map, k1, 1);
	if (!ASSERT_OK(err, "elem_add"))
		goto cleanup;
	err = hashmap__append(map, k1, 2);
	if (!ASSERT_OK(err, "elem_add"))
		goto cleanup;
	err = hashmap__append(map, k1, 4);
	if (!ASSERT_OK(err, "elem_add"))
		goto cleanup;

	err = hashmap__append(map, k2, 8);
	if (!ASSERT_OK(err, "elem_add"))
		goto cleanup;
	err = hashmap__append(map, k2, 16);
	if (!ASSERT_OK(err, "elem_add"))
		goto cleanup;
	err = hashmap__append(map, k2, 32);
	if (!ASSERT_OK(err, "elem_add"))
		goto cleanup;

	if (!ASSERT_EQ(hashmap__size(map), 6, "hashmap_size"))
		goto cleanup;

	/* verify global iteration still works and sees all values */
	found_msk = 0;
	hashmap__for_each_entry(map, entry, bkt) {
		found_msk |= entry->value;
	}
	if (!ASSERT_EQ(found_msk, (1 << 6) - 1, "found_msk"))
		goto cleanup;

	/* iterate values for key 1 */
	found_msk = 0;
	hashmap__for_each_key_entry(map, entry, k1) {
		found_msk |= entry->value;
	}
	if (!ASSERT_EQ(found_msk, (1 | 2 | 4), "found_msk"))
		goto cleanup;

	/* iterate values for key 2 */
	found_msk = 0;
	hashmap__for_each_key_entry(map, entry, k2) {
		found_msk |= entry->value;
	}
	if (!ASSERT_EQ(found_msk, (8 | 16 | 32), "found_msk"))
		goto cleanup;

cleanup:
	hashmap__free(map);
}

static void test_hashmap_empty()
{
	struct hashmap_entry *entry;
	int bkt;
	struct hashmap *map;
	long k = 0;

	/* force collisions */
	map = hashmap__new(hash_fn, equal_fn, NULL);
	if (!ASSERT_OK_PTR(map, "hashmap__new"))
		goto cleanup;

	if (!ASSERT_EQ(hashmap__size(map), 0, "hashmap__size"))
		goto cleanup;
	if (!ASSERT_EQ(hashmap__capacity(map), 0, "hashmap__capacity"))
		goto cleanup;
	if (hashmap__find(map, k, NULL))
		PRINT_FAIL("unexpected find\n");
	if (hashmap__delete(map, k, NULL, NULL))
		PRINT_FAIL("unexpected delete\n");

	hashmap__for_each_entry(map, entry, bkt) {
		PRINT_FAIL("unexpected iterated entry: entry->value=%ld\n", entry->value);
		goto cleanup;
	}
	hashmap__for_each_key_entry(map, entry, k) {
		PRINT_FAIL("unexpected key entry k=%ld\n", k);
		goto cleanup;
	}

cleanup:
	hashmap__free(map);
}

void test_hashmap()
{
	if (test__start_subtest("generic"))
		test_hashmap_generic();
	if (test__start_subtest("multimap"))
		test_hashmap_multimap();
	if (test__start_subtest("empty"))
		test_hashmap_empty();
	if (test__start_subtest("ptr_iface"))
		test_hashmap_ptr_iface();
}
