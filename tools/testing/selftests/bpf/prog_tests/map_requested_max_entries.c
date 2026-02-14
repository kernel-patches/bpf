// SPDX-License-Identifier: GPL-2.0
/* Test that bpf_map_info.requested_max_entries correctly reports the
 * original max_entries value requested by the caller, even when the
 * kernel adjusts max_entries internally (e.g., rounding up for per-CPU
 * LRU hash maps with BPF_F_NO_COMMON_LRU).
 */
#include <test_progs.h>
#include <bpf/bpf.h>

static void test_lru_hash_no_common_lru(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	/* Use a prime number to guarantee rounding on any SMP system */
	__u32 requested = 997;
	int map_fd, err;

	opts.map_flags = BPF_F_NO_COMMON_LRU;

	map_fd = bpf_map_create(BPF_MAP_TYPE_LRU_HASH, "test_lru_pcpu",
				sizeof(__u32), sizeof(__u32),
				requested, &opts);
	if (!ASSERT_GE(map_fd, 0, "bpf_map_create"))
		return;

	err = bpf_map_get_info_by_fd(map_fd, &info, &info_len);
	if (!ASSERT_OK(err, "bpf_map_get_info_by_fd"))
		goto out;

	ASSERT_EQ(info.requested_max_entries, requested,
		  "requested_max_entries");
	ASSERT_GE(info.max_entries, requested,
		  "max_entries >= requested");

out:
	close(map_fd);
}

static void test_lru_percpu_hash_no_common_lru(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	__u32 requested = 997;
	int map_fd, err;

	opts.map_flags = BPF_F_NO_COMMON_LRU;

	map_fd = bpf_map_create(BPF_MAP_TYPE_LRU_PERCPU_HASH,
				"test_lru_pcpu_v",
				sizeof(__u32), sizeof(__u32),
				requested, &opts);
	if (!ASSERT_GE(map_fd, 0, "bpf_map_create"))
		return;

	err = bpf_map_get_info_by_fd(map_fd, &info, &info_len);
	if (!ASSERT_OK(err, "bpf_map_get_info_by_fd"))
		goto out;

	ASSERT_EQ(info.requested_max_entries, requested,
		  "requested_max_entries");
	ASSERT_GE(info.max_entries, requested,
		  "max_entries >= requested");

out:
	close(map_fd);
}

static void test_lru_hash_common_lru(void)
{
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	__u32 requested = 997;
	int map_fd, err;

	/* Without BPF_F_NO_COMMON_LRU, max_entries should not be rounded */
	map_fd = bpf_map_create(BPF_MAP_TYPE_LRU_HASH, "test_lru_common",
				sizeof(__u32), sizeof(__u32),
				requested, NULL);
	if (!ASSERT_GE(map_fd, 0, "bpf_map_create"))
		return;

	err = bpf_map_get_info_by_fd(map_fd, &info, &info_len);
	if (!ASSERT_OK(err, "bpf_map_get_info_by_fd"))
		goto out;

	ASSERT_EQ(info.requested_max_entries, requested,
		  "requested_max_entries");
	ASSERT_EQ(info.max_entries, requested,
		  "max_entries == requested (no rounding)");

out:
	close(map_fd);
}

static void test_hash_map(void)
{
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	__u32 requested = 256;
	int map_fd, err;

	/* Regular hash map: max_entries should equal requested */
	map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "test_hash",
				sizeof(__u32), sizeof(__u32),
				requested, NULL);
	if (!ASSERT_GE(map_fd, 0, "bpf_map_create"))
		return;

	err = bpf_map_get_info_by_fd(map_fd, &info, &info_len);
	if (!ASSERT_OK(err, "bpf_map_get_info_by_fd"))
		goto out;

	ASSERT_EQ(info.requested_max_entries, requested,
		  "requested_max_entries");
	ASSERT_EQ(info.max_entries, requested,
		  "max_entries == requested");

out:
	close(map_fd);
}

void test_map_requested_max_entries(void)
{
	if (test__start_subtest("lru_hash_no_common_lru"))
		test_lru_hash_no_common_lru();
	if (test__start_subtest("lru_percpu_hash_no_common_lru"))
		test_lru_percpu_hash_no_common_lru();
	if (test__start_subtest("lru_hash_common_lru"))
		test_lru_hash_common_lru();
	if (test__start_subtest("hash_map"))
		test_hash_map();
}
