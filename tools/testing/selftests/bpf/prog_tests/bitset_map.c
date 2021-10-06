// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <sys/syscall.h>
#include <test_progs.h>
#include "bitset_map.skel.h"

static void test_bitset_map_fail(bool bloom_filter)
{
	struct bpf_create_map_attr xattr = {
		.name = "bitset_map",
		.map_type = BPF_MAP_TYPE_BITSET,
		.max_entries = 100,
		.value_size = bloom_filter ? 11 : sizeof(__u32),
		.map_extra = bloom_filter ? 5 : 0,
	};
	__u32 value;
	int fd, err;

	/* Invalid key size */
	xattr.key_size = 4;
	fd = bpf_create_map_xattr(&xattr);
	if (!ASSERT_LT(fd, 0, "bpf_create_map bitset invalid key size"))
		close(fd);
	xattr.key_size = 0;

	/* Invalid value size */
	xattr.value_size = 0;
	fd = bpf_create_map_xattr(&xattr);
	if (!ASSERT_LT(fd, 0, "bpf_create_map bitset invalid value size 0"))
		close(fd);
	if (!bloom_filter) {
		/* For bitset maps that are not bloom filters, the value size must
		 * be a __u32.
		 */
		xattr.value_size = sizeof(__u64);
		fd = bpf_create_map_xattr(&xattr);
		if (!ASSERT_LT(fd, 0, "bpf_create_map bitset invalid value size u64"))
			close(fd);
	}
	xattr.value_size = bloom_filter ? 11 : sizeof(__u32);

	/* Invalid max entries size */
	xattr.max_entries = 0;
	fd = bpf_create_map_xattr(&xattr);
	if (!ASSERT_LT(fd, 0, "bpf_create_map bitset invalid max entries size"))
		close(fd);
	xattr.max_entries = 100;

	/* bitset maps do not support BPF_F_NO_PREALLOC */
	xattr.map_flags = BPF_F_NO_PREALLOC;
	fd = bpf_create_map_xattr(&xattr);
	if (!ASSERT_LT(fd, 0, "bpf_create_map bitset invalid flags"))
		close(fd);
	xattr.map_flags = 0;

	fd = bpf_create_map_xattr(&xattr);
	if (!ASSERT_GE(fd, 0, "bpf_create_map bitset"))
		return;

	/* Test invalid flags */
	err = bpf_map_update_elem(fd, NULL, &value, -1);
	ASSERT_EQ(err, -EINVAL, "bpf_map_update_elem bitset invalid flags");

	err = bpf_map_update_elem(fd, NULL, &value, BPF_EXIST);
	ASSERT_EQ(err, -EINVAL, "bpf_map_update_elem bitset invalid flags");

	err = bpf_map_update_elem(fd, NULL, &value, BPF_F_LOCK);
	ASSERT_EQ(err, -EINVAL, "bpf_map_update_elem bitset invalid flags");

	err = bpf_map_update_elem(fd, NULL, &value, BPF_NOEXIST);
	ASSERT_EQ(err, -EINVAL, "bpf_map_update_elem bitset invalid flags");

	err = bpf_map_update_elem(fd, NULL, &value, 10000);
	ASSERT_EQ(err, -EINVAL, "bpf_map_update_elem bitset invalid flags");

	if (bloom_filter) {
		err = bpf_map_update_elem(fd, NULL, &value, 0);
		ASSERT_OK(err, "bpf_map_update_elem bitset invalid flags");

		/* Clearing a bit is not allowed */
		err = bpf_map_lookup_and_delete_elem(fd, NULL, &value);
		ASSERT_EQ(err, -EOPNOTSUPP, "bpf_map_lookup_and_delete invalid");
	} else {
		/* Try clearing a bit that wasn't set */
		err = bpf_map_lookup_and_delete_elem(fd, NULL, &value);
		ASSERT_EQ(err, -EINVAL, "bpf_map_lookup_and_delete invalid bit");

		/* Try setting a bit that is outside the bitset range */
		value = xattr.max_entries;
		err = bpf_map_update_elem(fd, NULL, &value, 0);
		ASSERT_EQ(err, -EINVAL, "bpf_map_update_elem bitset out of range");
	}

	/* bpf_map_delete is not supported. Only use bpf_map_lookup_and_delete */
	err = bpf_map_delete_elem(fd, &value);
	ASSERT_EQ(err, -EINVAL, "bpf_map_delete_elem");

	close(fd);
}

static void test_bitset_map_clear(void)
{
	int fd, err;
	__u32 val;

	fd = bpf_create_map(BPF_MAP_TYPE_BITSET, 0, sizeof(__u32), 10, 0);
	if (!ASSERT_GE(fd, 0, "bpf_create_map"))
		return;

	val = 3;
	err = bpf_map_update_elem(fd, NULL, &val, 0);
	if (!ASSERT_OK(err, "Set bit in bitmap"))
		goto done;

	err = bpf_map_lookup_elem(fd, NULL, &val);
	if (!ASSERT_OK(err, "Check bit in bitmap"))
		goto done;

	err = bpf_map_lookup_and_delete_elem(fd, NULL, &val);
	if (!ASSERT_OK(err, "Clear bit in bitmap"))
		goto done;

	err = bpf_map_lookup_elem(fd, NULL, &val);
	if (!ASSERT_EQ(err, -ENOENT, "Check cleared bit in bitmap"))
		goto done;

done:
	close(fd);
}

static void bitset_map(struct bitset_map *skel, struct bpf_program *prog)
{
	struct bpf_link *link;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "link"))
		return;

	syscall(SYS_getpgid);

	ASSERT_EQ(skel->bss->error, 0, "error");

	bpf_link__destroy(link);
}

static void bitset_inner_map(struct bitset_map *skel, const __u32 *rand_vals,
			     __u32 nr_rand_vals)
{
	int outer_map_fd, inner_map_fd, err, i, key = 0;
	struct bpf_create_map_attr xattr = {
		.name = "bitset_inner_map",
		.map_type = BPF_MAP_TYPE_BITSET,
		.value_size = sizeof(__u32),
		.max_entries = 1 << 16,
	};
	struct bpf_link *link;

	/* Create a bitset map that will be used as the inner map */
	inner_map_fd = bpf_create_map_xattr(&xattr);
	if (!ASSERT_GE(inner_map_fd, 0, "bpf_create_map bitset map as inner map"))
		return;

	for (i = 0; i < nr_rand_vals; i++) {
		err = bpf_map_update_elem(inner_map_fd, NULL, rand_vals + i, BPF_ANY);
		if (!ASSERT_OK(err, "Add random value to inner_map_fd"))
			goto done;
	}

	/* Add the bitset map to the outer map */
	outer_map_fd = bpf_map__fd(skel->maps.outer_map);
	err = bpf_map_update_elem(outer_map_fd, &key, &inner_map_fd, BPF_ANY);
	if (!ASSERT_OK(err, "Add bitset map to outer map"))
		goto done;

	/* Attach the bitset_inner_map prog */
	link = bpf_program__attach(skel->progs.prog_bitset_inner_map);
	if (!ASSERT_OK_PTR(link, "link"))
		goto delete_inner_map;

	syscall(SYS_getpgid);

	ASSERT_EQ(skel->bss->error, 0, "error");

	bpf_link__destroy(link);

delete_inner_map:
	/* Ensure the inner bitset map can be deleted */
	err = bpf_map_delete_elem(outer_map_fd, &key);
	ASSERT_OK(err, "Delete inner bitset map");

done:
	close(inner_map_fd);
}

static int setup_bitset_progs(struct bitset_map **out_skel, __u32 **out_rand_vals,
			      __u32 *out_nr_rand_vals)
{
	int random_data_fd, bitset_fd, bloom_filter_fd;
	struct bitset_map *skel;
	__u32 *rand_vals = NULL;
	__u32 map_size;
	__u32 val;
	int err, i;

	/* Set up a bitset map skeleton */
	skel = bitset_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bitset_map__open_and_load"))
		return -EINVAL;

	/* Set up rand_vals */
	map_size = bpf_map__max_entries(skel->maps.map_random_data);
	rand_vals = malloc(sizeof(*rand_vals) * map_size);
	if (!rand_vals) {
		err = -ENOMEM;
		goto error;
	}

	/* Generate random values and populate both skeletons */
	random_data_fd = bpf_map__fd(skel->maps.map_random_data);
	bitset_fd = bpf_map__fd(skel->maps.map_bitset);
	bloom_filter_fd = bpf_map__fd(skel->maps.map_bloom_filter);
	for (i = 0; i < map_size; i++) {
		val = rand();

		err = bpf_map_update_elem(random_data_fd, &i, &val, BPF_ANY);
		if (!ASSERT_OK(err, "Add random value to map_random_data"))
			goto error;

		err = bpf_map_update_elem(bloom_filter_fd, NULL, &val, BPF_ANY);
		if (!ASSERT_OK(err, "Add random value to map_bloom_filter"))
			goto error;

		/* Take the lower 16 bits */
		val &= 0xFFFF;

		rand_vals[i] = val;

		err = bpf_map_update_elem(bitset_fd, NULL, &val, BPF_ANY);
		if (!ASSERT_OK(err, "Add random value to map_bitset"))
			goto error;
	}

	*out_skel = skel;
	*out_rand_vals = rand_vals;
	*out_nr_rand_vals = map_size;

	return 0;

error:
	bitset_map__destroy(skel);
	if (rand_vals)
		free(rand_vals);
	return err;
}

void test_bitset_map(void)
{
	__u32 *rand_vals, nr_rand_vals;
	struct bitset_map *skel;
	int err;

	test_bitset_map_fail(false);
	test_bitset_map_fail(true);

	test_bitset_map_clear();

	err = setup_bitset_progs(&skel, &rand_vals, &nr_rand_vals);
	if (err)
		return;

	bitset_inner_map(skel, rand_vals, nr_rand_vals);
	free(rand_vals);

	bitset_map(skel, skel->progs.prog_bitset);
	bitset_map(skel, skel->progs.prog_bloom_filter);

	bitset_map__destroy(skel);
}
