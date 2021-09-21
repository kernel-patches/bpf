// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <sys/syscall.h>
#include <test_progs.h>
#include "bloom_filter_map.skel.h"

static void test_bloom_filter_map_fail(void)
{
	struct bpf_create_map_attr xattr = {
		.name = "bloom_filter_map",
		.map_type = BPF_MAP_TYPE_BLOOM_FILTER,
		.max_entries = 100,
		.value_size = sizeof(__u32),
		.nr_hash_funcs = 3,
	};
	__u32 value;
	int fd, err;

	/* Invalid key size */
	xattr.key_size = 4;
	fd = bpf_create_map_xattr(&xattr);
	if (!ASSERT_LT(fd, 0, "bpf_create_map bloom filter invalid key size"))
		close(fd);
	xattr.key_size = 0;

	/* Invalid value size */
	xattr.value_size = 0;
	fd = bpf_create_map_xattr(&xattr);
	if (!ASSERT_LT(fd, 0, "bpf_create_map bloom filter invalid value size"))
		close(fd);
	xattr.value_size = sizeof(__u32);

	/* Invalid max entries size */
	xattr.max_entries = 0;
	fd = bpf_create_map_xattr(&xattr);
	if (!ASSERT_LT(fd, 0, "bpf_create_map bloom filter invalid max entries size"))
		close(fd);
	xattr.max_entries = 100;

	/* Bloom filter maps do not support BPF_F_NO_PREALLOC */
	xattr.map_flags = BPF_F_NO_PREALLOC;
	fd = bpf_create_map_xattr(&xattr);
	if (!ASSERT_LT(fd, 0, "bpf_create_map bloom filter invalid flags"))
		close(fd);
	xattr.map_flags = 0;

	fd = bpf_create_map_xattr(&xattr);
	if (!ASSERT_GE(fd, 0, "bpf_create_map bloom filter"))
		return;

	/* Test invalid flags */
	err = bpf_map_update_elem(fd, NULL, &value, -1);
	ASSERT_EQ(err, -EINVAL, "bpf_map_update_elem bloom filter invalid flags");

	err = bpf_map_update_elem(fd, NULL, &value, BPF_EXIST);
	ASSERT_EQ(err, -EINVAL, "bpf_map_update_elem bloom filter invalid flags");

	err = bpf_map_update_elem(fd, NULL, &value, BPF_F_LOCK);
	ASSERT_EQ(err, -EINVAL, "bpf_map_update_elem bloom filter invalid flags");

	err = bpf_map_update_elem(fd, NULL, &value, BPF_NOEXIST);
	ASSERT_EQ(err, -EINVAL, "bpf_map_update_elem bloom filter invalid flags");

	err = bpf_map_update_elem(fd, NULL, &value, 10000);
	ASSERT_EQ(err, -EINVAL, "bpf_map_update_elem bloom filter invalid flags");

	close(fd);
}

static void bloom_filter_map(struct bloom_filter_map *skel)
{
	const int map_size = bpf_map__max_entries(skel->maps.map_random_data);
	int err, map_random_data_fd, map_bloom_filter_fd, i;
	__u64 val;
	struct bpf_link *link;

	map_random_data_fd = bpf_map__fd(skel->maps.map_random_data);
	map_bloom_filter_fd = bpf_map__fd(skel->maps.map_bloom_filter);

	/* Generate random values and add them to the maps */
	for (i = 0; i < map_size; i++) {
		val = rand();
		err = bpf_map_update_elem(map_random_data_fd, &i, &val, BPF_ANY);
		if (!ASSERT_OK(err, "Add random value to map_random_data"))
			continue;

		err = bpf_map_update_elem(map_bloom_filter_fd, NULL, &val, 0);
		if (!ASSERT_OK(err, "Add random value to map_bloom_filter"))
			return;
	}

	link = bpf_program__attach(skel->progs.prog_bloom_filter);
	if (!ASSERT_OK_PTR(link, "link"))
		return;

	syscall(SYS_getpgid);

	ASSERT_EQ(skel->bss->error, 0, "error");

	bpf_link__destroy(link);
}

static void bloom_filter_inner_map(struct bloom_filter_map *skel)
{
	const int map_size = bpf_map__max_entries(skel->maps.map_random_data);
	int outer_map_fd, inner_map_fd, map_random_data_fd, err, i, key = 0;
	struct bpf_create_map_attr xattr = {
		.name = "bloom_filter_inner_map",
		.map_type = BPF_MAP_TYPE_BLOOM_FILTER,
		.max_entries = map_size,
		.value_size = sizeof(__u64),
	};
	struct bpf_link *link;
	__u64 val;

	/* Create a bloom filter map that will be used as the inner map */
	inner_map_fd = bpf_create_map_xattr(&xattr);
	if (!ASSERT_GE(inner_map_fd, 0, "bpf_create_map bloom filter map as inner map"))
		return;

	/* Generate random values and add them to the maps */
	map_random_data_fd = bpf_map__fd(skel->maps.map_random_data);
	for (i = 0; i < map_size; i++) {
		val = rand();
		err = bpf_map_update_elem(map_random_data_fd, &i, &val, BPF_ANY);
		if (!ASSERT_OK(err, "Add random value to map_random_data"))
			continue;

		err = bpf_map_update_elem(inner_map_fd, NULL, &val, 0);
		if (!ASSERT_OK(err, "Add random value to inner_map_fd"))
			goto done;
	}

	outer_map_fd = bpf_map__fd(skel->maps.outer_map);
	/* Add the bloom filter map to the outer map */
	err = bpf_map_update_elem(outer_map_fd, &key, &inner_map_fd, 0);
	if (!ASSERT_OK(err, "Add bloom filter map to outer map"))
		goto done;

	/* Attach the bloom_filter_inner_map prog */
	link = bpf_program__attach(skel->progs.prog_bloom_filter_inner_map);
	if (!ASSERT_OK_PTR(link, "link"))
		goto delete_inner_map;

	syscall(SYS_getpgid);

	ASSERT_EQ(skel->bss->error, 0, "error");

	bpf_link__destroy(link);

delete_inner_map:
	/* Ensure the inner bloom filter map can be deleted */
	err = bpf_map_delete_elem(outer_map_fd, &key);
	ASSERT_OK(err, "Delete inner bloom filter map");

done:
	close(inner_map_fd);
}

void test_bloom_filter_map(void)
{
	struct bloom_filter_map *skel;

	test_bloom_filter_map_fail();

	skel = bloom_filter_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bloom_filter_map__open_and_load"))
		goto cleanup;

	bloom_filter_map(skel);

	bloom_filter_inner_map(skel);

cleanup:
	bloom_filter_map__destroy(skel);
}
