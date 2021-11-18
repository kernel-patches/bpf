// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <test_progs.h>
#include <network_helpers.h>
#include "for_each_hash_map_elem.skel.h"
#include "for_each_array_map_elem.skel.h"
#include "for_each_helper.skel.h"

static unsigned int duration;

static void test_hash_map(void)
{
	int i, err, hashmap_fd, max_entries, percpu_map_fd;
	struct for_each_hash_map_elem *skel;
	__u64 *percpu_valbuf = NULL;
	__u32 key, num_cpus, retval;
	__u64 val;

	skel = for_each_hash_map_elem__open_and_load();
	if (!ASSERT_OK_PTR(skel, "for_each_hash_map_elem__open_and_load"))
		return;

	hashmap_fd = bpf_map__fd(skel->maps.hashmap);
	max_entries = bpf_map__max_entries(skel->maps.hashmap);
	for (i = 0; i < max_entries; i++) {
		key = i;
		val = i + 1;
		err = bpf_map_update_elem(hashmap_fd, &key, &val, BPF_ANY);
		if (!ASSERT_OK(err, "map_update"))
			goto out;
	}

	num_cpus = bpf_num_possible_cpus();
	percpu_map_fd = bpf_map__fd(skel->maps.percpu_map);
	percpu_valbuf = malloc(sizeof(__u64) * num_cpus);
	if (!ASSERT_OK_PTR(percpu_valbuf, "percpu_valbuf"))
		goto out;

	key = 1;
	for (i = 0; i < num_cpus; i++)
		percpu_valbuf[i] = i + 1;
	err = bpf_map_update_elem(percpu_map_fd, &key, percpu_valbuf, BPF_ANY);
	if (!ASSERT_OK(err, "percpu_map_update"))
		goto out;

	err = bpf_prog_test_run(bpf_program__fd(skel->progs.test_pkt_access),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);
	if (CHECK(err || retval, "ipv4", "err %d errno %d retval %d\n",
		  err, errno, retval))
		goto out;

	ASSERT_EQ(skel->bss->hashmap_output, 4, "hashmap_output");
	ASSERT_EQ(skel->bss->hashmap_elems, max_entries, "hashmap_elems");

	key = 1;
	err = bpf_map_lookup_elem(hashmap_fd, &key, &val);
	ASSERT_ERR(err, "hashmap_lookup");

	ASSERT_EQ(skel->bss->percpu_called, 1, "percpu_called");
	ASSERT_LT(skel->bss->cpu, num_cpus, "num_cpus");
	ASSERT_EQ(skel->bss->percpu_map_elems, 1, "percpu_map_elems");
	ASSERT_EQ(skel->bss->percpu_key, 1, "percpu_key");
	ASSERT_EQ(skel->bss->percpu_val, skel->bss->cpu + 1, "percpu_val");
	ASSERT_EQ(skel->bss->percpu_output, 100, "percpu_output");
out:
	free(percpu_valbuf);
	for_each_hash_map_elem__destroy(skel);
}

static void test_array_map(void)
{
	__u32 key, num_cpus, max_entries, retval;
	int i, arraymap_fd, percpu_map_fd, err;
	struct for_each_array_map_elem *skel;
	__u64 *percpu_valbuf = NULL;
	__u64 val, expected_total;

	skel = for_each_array_map_elem__open_and_load();
	if (!ASSERT_OK_PTR(skel, "for_each_array_map_elem__open_and_load"))
		return;

	arraymap_fd = bpf_map__fd(skel->maps.arraymap);
	expected_total = 0;
	max_entries = bpf_map__max_entries(skel->maps.arraymap);
	for (i = 0; i < max_entries; i++) {
		key = i;
		val = i + 1;
		/* skip the last iteration for expected total */
		if (i != max_entries - 1)
			expected_total += val;
		err = bpf_map_update_elem(arraymap_fd, &key, &val, BPF_ANY);
		if (!ASSERT_OK(err, "map_update"))
			goto out;
	}

	num_cpus = bpf_num_possible_cpus();
	percpu_map_fd = bpf_map__fd(skel->maps.percpu_map);
	percpu_valbuf = malloc(sizeof(__u64) * num_cpus);
	if (!ASSERT_OK_PTR(percpu_valbuf, "percpu_valbuf"))
		goto out;

	key = 0;
	for (i = 0; i < num_cpus; i++)
		percpu_valbuf[i] = i + 1;
	err = bpf_map_update_elem(percpu_map_fd, &key, percpu_valbuf, BPF_ANY);
	if (!ASSERT_OK(err, "percpu_map_update"))
		goto out;

	err = bpf_prog_test_run(bpf_program__fd(skel->progs.test_pkt_access),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);
	if (CHECK(err || retval, "ipv4", "err %d errno %d retval %d\n",
		  err, errno, retval))
		goto out;

	ASSERT_EQ(skel->bss->arraymap_output, expected_total, "array_output");
	ASSERT_EQ(skel->bss->cpu + 1, skel->bss->percpu_val, "percpu_val");

out:
	free(percpu_valbuf);
	for_each_array_map_elem__destroy(skel);
}

static void test_for_each_helper(void)
{
	struct for_each_helper *skel;
	__u32 retval;
	int err;

	skel = for_each_helper__open_and_load();
	if (!ASSERT_OK_PTR(skel, "for_each_helper__open_and_load"))
		return;

	skel->bss->nr_iterations = 100;
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.test_prog),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);
	if (CHECK(err || retval, "bpf_for_each helper test_prog",
		  "err %d errno %d retval %d\n", err, errno, retval))
		goto out;
	ASSERT_EQ(skel->bss->nr_iterations_completed, skel->bss->nr_iterations,
		  "nr_iterations mismatch");
	ASSERT_EQ(skel->bss->g_output, (100 * 99) / 2, "wrong output");

	/* test callback_fn returning 1 to stop iteration */
	skel->bss->nr_iterations = 400;
	skel->data->stop_index = 50;
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.test_prog),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);
	if (CHECK(err || retval, "bpf_for_each helper test_prog",
		  "err %d errno %d retval %d\n", err, errno, retval))
		goto out;
	ASSERT_EQ(skel->bss->nr_iterations_completed, skel->data->stop_index + 1,
		  "stop_index not followed");
	ASSERT_EQ(skel->bss->g_output, (50 * 49) / 2, "wrong output");

	/* test passing in a null ctx */
	skel->bss->nr_iterations = 10;
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.prog_null_ctx),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);
	if (CHECK(err || retval, "bpf_for_each helper prog_null_ctx",
		  "err %d errno %d retval %d\n", err, errno, retval))
		goto out;
	ASSERT_EQ(skel->bss->nr_iterations_completed, skel->bss->nr_iterations,
		  "nr_iterations mismatch");

	/* test invalid flags */
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.prog_invalid_flags),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);
	if (CHECK(err || retval, "bpf_for_each helper prog_invalid_flags",
		  "err %d errno %d retval %d\n", err, errno, retval))
		goto out;
	ASSERT_EQ(skel->bss->err, -EINVAL, "invalid_flags");

out:
	for_each_helper__destroy(skel);
}

void test_for_each(void)
{
	if (test__start_subtest("hash_map"))
		test_hash_map();
	if (test__start_subtest("array_map"))
		test_array_map();
	if (test__start_subtest("for_each_helper"))
		test_for_each_helper();
}
