// SPDX-License-Identifier: GPL-2.0 AND MIT
/*
 * Copyright © 2026 Intel Corporation
 */

#include <kunit/test.h>

#include "xe_device.h"
#include "xe_kunit_helpers.h"

#define GGTT_TEST_START		SZ_1M

static u64 ggtt_test_accessible_size(struct kunit *test)
{
	struct xe_tile *tile = xe_device_get_root_tile(test->priv);

	return GUC_GGTT_TOP - xe_wopcm_size(tile_to_xe(tile));
}

static void ggtt_test_fini(void *data)
{
	struct xe_ggtt *ggtt = data;

	drm_mm_takedown(&ggtt->mm);
}

static struct xe_ggtt *ggtt_test_get(struct kunit *test)
{
	return xe_device_get_root_tile(test->priv)->mem.ggtt;
}

/* Must be called after the GGTT ranges are initialized. */
static int ggtt_test_track_ggtt(struct kunit *test, struct xe_ggtt *ggtt)
{
	return kunit_add_action_or_reset(test, ggtt_test_fini, ggtt);
}

static struct xe_ggtt *ggtt_test_create(struct kunit *test, u64 full_size,
					u64 usable_size, u64 shareable_size)
{
	struct xe_ggtt *ggtt = ggtt_test_get(test);

	ggtt_init_ranges(ggtt, GGTT_TEST_START, full_size, usable_size, shareable_size);

	if (ggtt_test_track_ggtt(test, ggtt))
		return NULL;

	return ggtt;
}

static void ggtt_test_remove_node(void *data)
{
	ggtt_node_remove(data);
}

/*
 * Release the node on test exit, before the GGTT is torn down, so that an
 * aborted test does not leave it in the drm_mm.
 */
static struct xe_ggtt_node *ggtt_test_track_node(struct kunit *test,
						 struct xe_ggtt_node *node)
{
	if (!IS_ERR_OR_NULL(node) &&
	    kunit_add_action_or_reset(test, ggtt_test_remove_node, node))
		return ERR_PTR(-ENOMEM);

	return node;
}

static struct xe_ggtt_node *ggtt_test_insert_node(struct kunit *test,
						  struct xe_ggtt *ggtt, u32 size)
{
	return ggtt_test_track_node(test, xe_ggtt_insert_node(ggtt, size, XE_PAGE_SIZE));
}

static void init_native(struct kunit *test)
{
	u64 accessible = ggtt_test_accessible_size(test);
	u64 usable = min_t(u64, SZ_1G, accessible);
	struct xe_ggtt *ggtt = ggtt_test_get(test);

	ggtt_init_native(ggtt, GGTT_TEST_START, usable);
	KUNIT_ASSERT_EQ(test, ggtt_test_track_ggtt(test, ggtt), 0);

	KUNIT_EXPECT_EQ(test, ggtt->start, GGTT_TEST_START);
	KUNIT_EXPECT_EQ(test, ggtt->size, usable);
	KUNIT_EXPECT_EQ(test, ggtt->full_size, usable);
}

static void alloc_usable_pool_native(struct kunit *test)
{
	u64 accessible = ggtt_test_accessible_size(test);
	u64 usable = (accessible * 3) / 4;
	struct xe_ggtt_node *usable_node;
	struct xe_ggtt *ggtt;

	ggtt = ggtt_test_create(test, usable, usable, 0);
	KUNIT_ASSERT_NOT_NULL(test, ggtt);

	usable_node = ggtt_test_insert_node(test, ggtt, XE_PAGE_SIZE);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, usable_node);
	KUNIT_EXPECT_EQ(test, xe_ggtt_node_addr(usable_node), GGTT_TEST_START);
}

static void alloc_usable_pool_oversized(struct kunit *test)
{
	u64 accessible = ggtt_test_accessible_size(test);
	u64 usable = (accessible * 3) / 4;
	struct xe_ggtt_node *node;
	struct xe_ggtt *ggtt;

	KUNIT_ASSERT_LE(test, usable + XE_PAGE_SIZE, (u64)U32_MAX);

	ggtt = ggtt_test_create(test, usable, usable, 0);
	KUNIT_ASSERT_NOT_NULL(test, ggtt);

	node = ggtt_test_insert_node(test, ggtt, usable + XE_PAGE_SIZE);
	KUNIT_ASSERT_TRUE(test, IS_ERR(node));
	KUNIT_EXPECT_EQ(test, PTR_ERR(node), -ENOSPC);
}

static struct kunit_case ggtt_test_cases[] = {
	KUNIT_CASE(init_native),
	KUNIT_CASE(alloc_usable_pool_native),
	KUNIT_CASE(alloc_usable_pool_oversized),
	{}
};

static struct kunit_suite ggtt_suite = {
	.name = "xe_ggtt",
	.test_cases = ggtt_test_cases,
	.init = xe_kunit_helper_xe_device_test_init,
};

#if IS_ENABLED(CONFIG_PCI_IOV)
static struct xe_ggtt_node *ggtt_test_insert_node_shareable(struct kunit *test,
							    struct xe_ggtt *ggtt, u32 size)
{
	return ggtt_test_track_node(test,
				    xe_ggtt_insert_node_shareable(ggtt, size, XE_PAGE_SIZE));
}

static void init_shared_pf(struct kunit *test)
{
	u64 accessible = ggtt_test_accessible_size(test);
	struct xe_ggtt *ggtt = ggtt_test_get(test);

	ggtt_init_shared(ggtt, GGTT_TEST_START, accessible);
	KUNIT_ASSERT_EQ(test, ggtt_test_track_ggtt(test, ggtt), 0);

	KUNIT_EXPECT_EQ(test, ggtt->size, accessible);
	KUNIT_EXPECT_EQ(test, ggtt_shareable_offset(ggtt), 0);
	KUNIT_EXPECT_EQ(test, ggtt->shareable_size, accessible);
	KUNIT_EXPECT_EQ(test, ggtt->full_size, accessible);
}

static void init_partial_overlap(struct kunit *test)
{
	u64 accessible = ggtt_test_accessible_size(test);
	u64 usable = (accessible * 3) / 4;
	u64 shareable = accessible / 2;
	struct xe_ggtt *ggtt;

	KUNIT_ASSERT_GT(test, accessible, 0ULL);
	KUNIT_ASSERT_GT(test, usable, shareable);

	ggtt = ggtt_test_create(test, accessible, usable, shareable);
	KUNIT_ASSERT_NOT_NULL(test, ggtt);

	KUNIT_EXPECT_EQ(test, ggtt->size, usable);
	KUNIT_EXPECT_EQ(test, ggtt_shareable_offset(ggtt), accessible - shareable);
	KUNIT_EXPECT_EQ(test, ggtt->shareable_size, shareable);
	KUNIT_EXPECT_LT(test, ggtt_shareable_offset(ggtt), usable);
	KUNIT_EXPECT_EQ(test, ggtt->full_size, accessible);
}

static void alloc_usable_pool_low(struct kunit *test)
{
	u64 accessible = ggtt_test_accessible_size(test);
	u64 usable = (accessible * 3) / 4;
	u64 shareable = accessible / 2;
	struct xe_ggtt_node *usable_node;
	struct xe_ggtt *ggtt;

	ggtt = ggtt_test_create(test, accessible, usable, shareable);
	KUNIT_ASSERT_NOT_NULL(test, ggtt);

	usable_node = ggtt_test_insert_node(test, ggtt, XE_PAGE_SIZE);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, usable_node);
	KUNIT_EXPECT_EQ(test, xe_ggtt_node_addr(usable_node), GGTT_TEST_START);
	KUNIT_EXPECT_EQ(test, xe_ggtt_node_size(usable_node), (u64)XE_PAGE_SIZE);
}

static void alloc_shareable_pool_high(struct kunit *test)
{
	u64 accessible = ggtt_test_accessible_size(test);
	u64 usable = (accessible * 3) / 4;
	u64 shareable = accessible / 2;
	struct xe_ggtt_node *shareable_node;
	struct xe_ggtt *ggtt;

	ggtt = ggtt_test_create(test, accessible, usable, shareable);
	KUNIT_ASSERT_NOT_NULL(test, ggtt);

	shareable_node = ggtt_test_insert_node_shareable(test, ggtt, XE_PAGE_SIZE);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, shareable_node);
	KUNIT_EXPECT_EQ(test, xe_ggtt_node_addr(shareable_node),
			GGTT_TEST_START + accessible - XE_PAGE_SIZE);
	KUNIT_EXPECT_EQ(test, xe_ggtt_node_size(shareable_node), (u64)XE_PAGE_SIZE);
}

static void alloc_partial_overlap(struct kunit *test)
{
	u64 accessible = ggtt_test_accessible_size(test);
	u64 usable = (accessible * 3) / 4;
	u64 shareable = accessible / 2;
	struct xe_ggtt_node *shareable_node;
	struct xe_ggtt_node *usable_node;
	struct xe_ggtt *ggtt;

	ggtt = ggtt_test_create(test, accessible, usable, shareable);
	KUNIT_ASSERT_NOT_NULL(test, ggtt);

	usable_node = ggtt_test_insert_node(test, ggtt, XE_PAGE_SIZE);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, usable_node);
	shareable_node = ggtt_test_insert_node_shareable(test, ggtt, XE_PAGE_SIZE);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, shareable_node);

	KUNIT_EXPECT_EQ(test, xe_ggtt_node_addr(usable_node), GGTT_TEST_START);
	KUNIT_EXPECT_EQ(test, xe_ggtt_node_addr(shareable_node),
			GGTT_TEST_START + accessible - XE_PAGE_SIZE);
}

static void alloc_partial_overlap_usable_full(struct kunit *test)
{
	u64 accessible = ggtt_test_accessible_size(test);
	u64 usable = (accessible * 3) / 4;
	u64 shareable = accessible / 2;
	struct xe_ggtt_node *shareable_node;
	struct xe_ggtt_node *usable_node;
	struct xe_ggtt *ggtt;

	KUNIT_ASSERT_LE(test, usable, (u64)U32_MAX);
	KUNIT_ASSERT_LE(test, shareable, (u64)U32_MAX);

	ggtt = ggtt_test_create(test, accessible, usable, shareable);
	KUNIT_ASSERT_NOT_NULL(test, ggtt);

	usable_node = ggtt_test_insert_node(test, ggtt, usable);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, usable_node);
	shareable_node = ggtt_test_insert_node_shareable(test, ggtt, shareable);
	KUNIT_ASSERT_TRUE(test, IS_ERR(shareable_node));
	KUNIT_EXPECT_EQ(test, PTR_ERR(shareable_node), -ENOSPC);
}

static void alloc_partial_overlap_shareable_full(struct kunit *test)
{
	u64 accessible = ggtt_test_accessible_size(test);
	u64 usable = (accessible * 3) / 4;
	u64 shareable = accessible / 2;
	struct xe_ggtt_node *shareable_node;
	struct xe_ggtt_node *usable_node;
	struct xe_ggtt *ggtt;

	KUNIT_ASSERT_LE(test, usable, (u64)U32_MAX);
	KUNIT_ASSERT_LE(test, shareable, (u64)U32_MAX);

	ggtt = ggtt_test_create(test, accessible, usable, shareable);
	KUNIT_ASSERT_NOT_NULL(test, ggtt);

	shareable_node = ggtt_test_insert_node_shareable(test, ggtt, shareable);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, shareable_node);
	usable_node = ggtt_test_insert_node(test, ggtt, usable);
	KUNIT_ASSERT_TRUE(test, IS_ERR(usable_node));
	KUNIT_EXPECT_EQ(test, PTR_ERR(usable_node), -ENOSPC);
}

static void alloc_shareable_pool_unavailable(struct kunit *test)
{
	u64 accessible = ggtt_test_accessible_size(test);
	u64 usable = (accessible * 3) / 4;
	struct xe_ggtt_node *node;
	struct xe_ggtt *ggtt;

	ggtt = ggtt_test_create(test, usable, usable, 0);
	KUNIT_ASSERT_NOT_NULL(test, ggtt);

	node = ggtt_test_insert_node_shareable(test, ggtt, XE_PAGE_SIZE);
	KUNIT_ASSERT_TRUE(test, IS_ERR(node));
	KUNIT_EXPECT_EQ(test, PTR_ERR(node), -ENOSPC);
}

static void alloc_shareable_pool_oversized(struct kunit *test)
{
	u64 accessible = ggtt_test_accessible_size(test);
	u64 usable = (accessible * 3) / 4;
	u64 shareable = accessible / 2;
	struct xe_ggtt_node *node;
	struct xe_ggtt *ggtt;

	KUNIT_ASSERT_LE(test, shareable + XE_PAGE_SIZE, (u64)U32_MAX);

	ggtt = ggtt_test_create(test, accessible, usable, shareable);
	KUNIT_ASSERT_NOT_NULL(test, ggtt);

	node = ggtt_test_insert_node_shareable(test, ggtt, shareable + XE_PAGE_SIZE);
	KUNIT_ASSERT_TRUE(test, IS_ERR(node));
	KUNIT_EXPECT_EQ(test, PTR_ERR(node), -ENOSPC);
}

static struct kunit_case ggtt_iov_test_cases[] = {
	KUNIT_CASE(init_shared_pf),
	KUNIT_CASE(init_partial_overlap),
	KUNIT_CASE(alloc_usable_pool_low),
	KUNIT_CASE(alloc_shareable_pool_high),
	KUNIT_CASE(alloc_partial_overlap),
	KUNIT_CASE(alloc_partial_overlap_usable_full),
	KUNIT_CASE(alloc_partial_overlap_shareable_full),
	KUNIT_CASE(alloc_shareable_pool_unavailable),
	KUNIT_CASE(alloc_shareable_pool_oversized),
	{}
};

static struct kunit_suite ggtt_iov_suite = {
	.name = "xe_ggtt_iov",
	.test_cases = ggtt_iov_test_cases,
	.init = xe_kunit_helper_xe_device_test_init,
};
#endif

kunit_test_suites(&ggtt_suite);
#if IS_ENABLED(CONFIG_PCI_IOV)
kunit_test_suites(&ggtt_iov_suite);
#endif
