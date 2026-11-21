// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for the stringset data structure.
 *
 * Copyright (c) 2025, Oracle and/or its affiliates.
 */

#include <kunit/resource.h>
#include <kunit/test.h>
#include <linux/stringset.h>

KUNIT_DEFINE_ACTION_WRAPPER(stringset_destroy_action, stringset_destroy,
			    struct stringset *);

/*
 * Cleanup actions run after a failed assertion has ended the test
 * thread, so the set cannot live on that thread's stack.
 */
static struct stringset *new_set(struct kunit *test)
{
	struct stringset *set;
	int err;

	set = kunit_kzalloc(test, sizeof(*set), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, set);
	stringset_init(set);
	err = kunit_add_action_or_reset(test, stringset_destroy_action, set);
	KUNIT_ASSERT_EQ(test, err, 0);
	return set;
}

/* Build a populated (but not yet finalized) set from an array of literals. */
static struct stringset *build_set(struct kunit *test,
				   const char * const *strs, unsigned int n)
{
	struct stringset *set = new_set(test);
	unsigned int i;

	KUNIT_ASSERT_TRUE(test, stringset_alloc(set, n, GFP_KERNEL));
	for (i = 0; i < n; i++)
		KUNIT_ASSERT_TRUE(test,
				  stringset_add_dup(set, strs[i], GFP_KERNEL));
	return set;
}

static void stringset_init_empty(struct kunit *test)
{
	DEFINE_STRINGSET(set);

	KUNIT_EXPECT_TRUE(test, stringset_is_empty(&set));
	KUNIT_EXPECT_EQ(test, stringset_count(&set), 0u);
	stringset_destroy(&set);
}

static void stringset_alloc_zero_is_empty_set(struct kunit *test)
{
	DEFINE_STRINGSET(set);

	KUNIT_EXPECT_TRUE(test, stringset_alloc(&set, 0, GFP_KERNEL));
	stringset_finalize(&set);
	KUNIT_EXPECT_FALSE(test, stringset_is_member(&set, "anything"));
	KUNIT_EXPECT_EQ(test, stringset_count(&set), 0u);
	stringset_destroy(&set);
}

static void stringset_alloc_twice_fails(struct kunit *test)
{
	DEFINE_STRINGSET(set);

	KUNIT_EXPECT_TRUE(test, stringset_alloc(&set, 4, GFP_KERNEL));
	KUNIT_EXPECT_FALSE(test, stringset_alloc(&set, 4, GFP_KERNEL));
	stringset_destroy(&set);
}

static void stringset_realloc_after_destroy(struct kunit *test)
{
	const char * const in[] = { "a", "b" };
	struct stringset *set;

	set = build_set(test, in, ARRAY_SIZE(in));
	stringset_finalize(set);
	stringset_destroy(set);
	KUNIT_EXPECT_TRUE(test, stringset_alloc(set, 2, GFP_KERNEL));
}

static void stringset_add_capacity_exhausted(struct kunit *test)
{
	struct stringset *set = new_set(test);
	char *overflow;
	bool added;

	KUNIT_ASSERT_TRUE(test, stringset_alloc(set, 1, GFP_KERNEL));
	KUNIT_ASSERT_TRUE(test, stringset_add_dup(set, "a", GFP_KERNEL));
	KUNIT_EXPECT_FALSE(test, stringset_add_dup(set, "b", GFP_KERNEL));

	/* The failed add does not transfer ownership, so free the string. */
	overflow = kstrdup("b", GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, overflow);
	added = stringset_add(set, overflow);
	KUNIT_EXPECT_FALSE(test, added);
	if (!added)
		kfree(overflow);

	KUNIT_EXPECT_EQ(test, stringset_count(set), 1u);
}

static void stringset_add_null_rejected(struct kunit *test)
{
	DEFINE_STRINGSET(set);

	KUNIT_ASSERT_TRUE(test, stringset_alloc(&set, 1, GFP_KERNEL));
	KUNIT_EXPECT_FALSE(test, stringset_add(&set, NULL));
	KUNIT_EXPECT_FALSE(test, stringset_add_dup(&set, NULL, GFP_KERNEL));
	stringset_destroy(&set);
}

/*
 * stringset_add takes ownership; destroy must free it. A missed
 * transfer leaks the string, which leak checkers (kmemleak) catch.
 */
static void stringset_add_takes_ownership(struct kunit *test)
{
	struct stringset *set = new_set(test);
	char *str;

	KUNIT_ASSERT_TRUE(test, stringset_alloc(set, 1, GFP_KERNEL));
	str = kstrdup("owned", GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, str);
	KUNIT_EXPECT_TRUE(test, stringset_add(set, str));
	stringset_finalize(set);
}

static void stringset_add_is_queryable(struct kunit *test)
{
	struct stringset *set = new_set(test);
	char *str;

	KUNIT_ASSERT_TRUE(test, stringset_alloc(set, 1, GFP_KERNEL));
	str = kstrdup("owned", GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, str);
	KUNIT_EXPECT_TRUE(test, stringset_add(set, str));
	KUNIT_EXPECT_FALSE(test, stringset_is_empty(set));
	stringset_finalize(set);
	KUNIT_EXPECT_TRUE(test, stringset_is_member(set, "owned"));
}

static void stringset_finalize_dedups(struct kunit *test)
{
	const char * const in[] = { "a", "b", "a", "b" };
	struct stringset *set;

	set = build_set(test, in, ARRAY_SIZE(in));
	KUNIT_EXPECT_EQ(test, stringset_count(set), 4u);
	stringset_finalize(set);
	KUNIT_EXPECT_EQ(test, stringset_count(set), 2u);
	KUNIT_EXPECT_TRUE(test, stringset_is_member(set, "a"));
	KUNIT_EXPECT_TRUE(test, stringset_is_member(set, "b"));
}

/*
 * Callers must not depend on iteration order, but the sort is what
 * makes binary-search membership work, so check it directly here.
 */
static void stringset_finalize_sorts(struct kunit *test)
{
	const char * const in[] = { "charlie", "alpha", "bravo" };
	const char *prev = NULL, *str;
	struct stringset *set;
	unsigned int i;

	set = build_set(test, in, ARRAY_SIZE(in));
	stringset_finalize(set);
	stringset_for_each(set, i, str) {
		if (prev)
			KUNIT_EXPECT_LT(test, strcmp(prev, str), 0);
		prev = str;
	}
}

static void stringset_is_member_present_and_absent(struct kunit *test)
{
	const char * const in[] = { "b", "d", "f", "h" };
	struct stringset *set;

	set = build_set(test, in, ARRAY_SIZE(in));
	stringset_finalize(set);
	/* present: first, middle, last */
	KUNIT_EXPECT_TRUE(test, stringset_is_member(set, "b"));
	KUNIT_EXPECT_TRUE(test, stringset_is_member(set, "f"));
	KUNIT_EXPECT_TRUE(test, stringset_is_member(set, "h"));
	/* absent: before first, in a gap, after last */
	KUNIT_EXPECT_FALSE(test, stringset_is_member(set, "a"));
	KUNIT_EXPECT_FALSE(test, stringset_is_member(set, "e"));
	KUNIT_EXPECT_FALSE(test, stringset_is_member(set, "z"));
}

static void stringset_intersection_overlap(struct kunit *test)
{
	const char * const a[] = { "a", "c", "e" };
	const char * const b[] = { "b", "c", "d" };
	struct stringset *s1, *s2;

	s1 = build_set(test, a, ARRAY_SIZE(a));
	s2 = build_set(test, b, ARRAY_SIZE(b));
	stringset_finalize(s1);
	stringset_finalize(s2);
	KUNIT_EXPECT_TRUE(test, stringset_intersection(s1, s2));
}

static void stringset_intersection_disjoint(struct kunit *test)
{
	const char * const a[] = { "a", "b", "c" };
	const char * const b[] = { "x", "y", "z" };
	struct stringset *s1, *s2;

	s1 = build_set(test, a, ARRAY_SIZE(a));
	s2 = build_set(test, b, ARRAY_SIZE(b));
	stringset_finalize(s1);
	stringset_finalize(s2);
	KUNIT_EXPECT_FALSE(test, stringset_intersection(s1, s2));
}

static void stringset_intersection_with_empty(struct kunit *test)
{
	const char * const a[] = { "a", "b" };
	struct stringset *s1;
	DEFINE_STRINGSET(empty);

	s1 = build_set(test, a, ARRAY_SIZE(a));
	stringset_finalize(s1);
	stringset_finalize(&empty);
	KUNIT_EXPECT_FALSE(test, stringset_intersection(s1, &empty));
	stringset_destroy(&empty);
}

/* Copy is deep: destroying the source must not disturb the copy. */
static void stringset_copy_is_independent(struct kunit *test)
{
	const char * const in[] = { "one", "two", "three" };
	struct stringset *src, *dst;

	src = build_set(test, in, ARRAY_SIZE(in));
	stringset_finalize(src);
	dst = new_set(test);
	KUNIT_ASSERT_TRUE(test, stringset_copy(dst, src, GFP_KERNEL));
	KUNIT_EXPECT_EQ(test, stringset_count(dst), 3u);

	stringset_destroy(src);
	KUNIT_EXPECT_TRUE(test, stringset_is_member(dst, "one"));
	KUNIT_EXPECT_TRUE(test, stringset_is_member(dst, "three"));
}

static void stringset_copy_empty_src(struct kunit *test)
{
	DEFINE_STRINGSET(src);
	DEFINE_STRINGSET(dst);

	stringset_finalize(&src);
	KUNIT_EXPECT_TRUE(test, stringset_copy(&dst, &src, GFP_KERNEL));
	KUNIT_EXPECT_EQ(test, stringset_count(&dst), 0u);
	/* dst is finalized, so a query is well-defined and returns false */
	KUNIT_EXPECT_FALSE(test, stringset_is_member(&dst, "x"));
	stringset_destroy(&dst);
	stringset_destroy(&src);
}

static void stringset_iteration_visits_all(struct kunit *test)
{
	const char * const in[] = { "a", "b", "c", "d" };
	unsigned int i, seen = 0;
	struct stringset *set;
	char *str;

	set = build_set(test, in, ARRAY_SIZE(in));
	stringset_finalize(set);
	stringset_for_each(set, i, str) {
		KUNIT_EXPECT_TRUE(test, stringset_is_member(set, str));
		seen++;
	}
	KUNIT_EXPECT_EQ(test, seen, stringset_count(set));
}

static struct kunit_case stringset_test_cases[] = {
	KUNIT_CASE(stringset_init_empty),
	KUNIT_CASE(stringset_alloc_zero_is_empty_set),
	KUNIT_CASE(stringset_alloc_twice_fails),
	KUNIT_CASE(stringset_realloc_after_destroy),
	KUNIT_CASE(stringset_add_capacity_exhausted),
	KUNIT_CASE(stringset_add_null_rejected),
	KUNIT_CASE(stringset_add_takes_ownership),
	KUNIT_CASE(stringset_add_is_queryable),
	KUNIT_CASE(stringset_finalize_dedups),
	KUNIT_CASE(stringset_finalize_sorts),
	KUNIT_CASE(stringset_is_member_present_and_absent),
	KUNIT_CASE(stringset_intersection_overlap),
	KUNIT_CASE(stringset_intersection_disjoint),
	KUNIT_CASE(stringset_intersection_with_empty),
	KUNIT_CASE(stringset_copy_is_independent),
	KUNIT_CASE(stringset_copy_empty_src),
	KUNIT_CASE(stringset_iteration_visits_all),
	{}
};

static struct kunit_suite stringset_test_suite = {
	.name = "stringset",
	.test_cases = stringset_test_cases,
};
kunit_test_suite(stringset_test_suite);

MODULE_DESCRIPTION("KUnit tests for the stringset data structure");
MODULE_LICENSE("GPL");
