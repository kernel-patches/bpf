// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <linux/bitmap.h>
#include <test_progs.h>

#include "local_storage_excl_cache.skel.h"
#include "local_storage_excl_cache_fail.skel.h"

void test_test_local_storage_excl_cache(void)
{
	u64 cache_idx_exclusive, cache_idx_exclusive_expected;
	struct local_storage_excl_cache_fail *skel_fail = NULL;
	struct local_storage_excl_cache *skel = NULL;
	u16 cache_size, i;
	int err;

	skel_fail = local_storage_excl_cache_fail__open_and_load();
	ASSERT_ERR_PTR(skel_fail, "excl_cache_fail load should fail");
	local_storage_excl_cache_fail__destroy(skel_fail);

	skel = local_storage_excl_cache__open_and_load();
	if (!ASSERT_OK_PTR(skel, "excl_cache load should succeed"))
		goto cleanup;

	cache_size = skel->data->__BPF_LOCAL_STORAGE_CACHE_SIZE;

	err = local_storage_excl_cache__attach(skel);
	if (!ASSERT_OK(err, "excl_cache__attach"))
		goto cleanup;

	/* trigger tracepoint */
	usleep(1);
	cache_idx_exclusive = skel->data->out__cache_bitmap;
	cache_idx_exclusive_expected = 0;
	for (i = 0; i < cache_size; i++)
		cache_idx_exclusive_expected |= (1U << i);

	if (!ASSERT_EQ(cache_idx_exclusive & cache_idx_exclusive_expected,
		       cache_idx_exclusive_expected, "excl cache bitmap should be full"))
		goto cleanup;

	usleep(1);
	for (i = 0; i < cache_size; i++)
		if (!ASSERT_EQ(skel->data->out__cache_smaps[i],
			       skel->data->out__declared_smaps[i],
			       "cached map not equal"))
			goto cleanup;

cleanup:
	local_storage_excl_cache__destroy(skel);
}
