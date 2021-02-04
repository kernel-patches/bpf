// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <test_progs.h>
#include "for_each_hash_map_elem.skel.h"

static int duration;

static void do_dummy_read(struct bpf_program *prog)
{
	struct bpf_link *link;
	char buf[16] = {};
	int iter_fd, len;

	link = bpf_program__attach_iter(prog, NULL);
	if (CHECK(IS_ERR(link), "attach_iter", "attach_iter failed\n"))
		return;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto free_link;

	/* not check contents, but ensure read() ends without error */
	while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
		;
	CHECK(len < 0, "read", "read failed: %s\n", strerror(errno));

	close(iter_fd);

free_link:
	bpf_link__destroy(link);
}

static void test_hash_map(void)
{
	int i, hashmap_fd, percpu_map_fd, err;
	struct for_each_hash_map_elem *skel;
	__u64 *percpu_valbuf = NULL;
	__u32 key, num_cpus;
	__u64 val;

	skel = for_each_hash_map_elem__open_and_load();
	if (CHECK(!skel, "for_each_hash_map_elem__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	hashmap_fd = bpf_map__fd(skel->maps.hashmap);
	for (i = 0; i < bpf_map__max_entries(skel->maps.hashmap); i++) {
		key = i;
		val = i + 1;
		err = bpf_map_update_elem(hashmap_fd, &key, &val, BPF_ANY);
		if (CHECK(err, "map_update", "map_update failed\n"))
			goto out;
	}

	num_cpus = bpf_num_possible_cpus();
	percpu_map_fd = bpf_map__fd(skel->maps.percpu_map);
	percpu_valbuf = malloc(sizeof(__u64) * num_cpus);
	if (CHECK_FAIL(!percpu_valbuf))
		goto out;

	key = 1;
	for (i = 0; i < num_cpus; i++)
		percpu_valbuf[i] = i + 1;
	err = bpf_map_update_elem(percpu_map_fd, &key, percpu_valbuf, BPF_ANY);
	if (CHECK(err, "percpu_map_update", "map_update failed\n"))
		goto out;

	do_dummy_read(skel->progs.dump_task);

	ASSERT_EQ(skel->bss->called, 1, "called");
	ASSERT_EQ(skel->bss->hashmap_output, 4, "output_val");

	key = 1;
	err = bpf_map_lookup_elem(hashmap_fd, &key, &val);
	ASSERT_ERR(err, "hashmap_lookup");

	ASSERT_EQ(skel->bss->percpu_called, 1, "percpu_called");
	CHECK_FAIL(skel->bss->cpu >= num_cpus);
	ASSERT_EQ(skel->bss->percpu_key, 1, "percpu_key");
	ASSERT_EQ(skel->bss->percpu_val, skel->bss->cpu + 1, "percpu_val");
	ASSERT_EQ(skel->bss->percpu_output, 100, "percpu_output");
out:
	free(percpu_valbuf);
	for_each_hash_map_elem__destroy(skel);
}

void test_for_each(void)
{
	if (test__start_subtest("hash_map"))
		test_hash_map();
}
