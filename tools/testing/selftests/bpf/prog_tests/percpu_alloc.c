// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "percpu_alloc_array.skel.h"
#include "percpu_alloc_cgrp_local_storage.skel.h"
#include "percpu_alloc_fail.skel.h"

static void test_array(void)
{
	struct percpu_alloc_array *skel;
	int err, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = percpu_alloc_array__open();
	if (!ASSERT_OK_PTR(skel, "percpu_alloc_array__open"))
		return;

	bpf_program__set_autoload(skel->progs.test_array_map_1, true);
	bpf_program__set_autoload(skel->progs.test_array_map_2, true);
	bpf_program__set_autoload(skel->progs.test_array_map_3, true);
	bpf_program__set_autoload(skel->progs.test_array_map_4, true);

	skel->bss->my_pid = getpid();
	skel->rodata->nr_cpus = libbpf_num_possible_cpus();

	err = percpu_alloc_array__load(skel);
	if (!ASSERT_OK(err, "percpu_alloc_array__load"))
		goto out;

	err = percpu_alloc_array__attach(skel);
	if (!ASSERT_OK(err, "percpu_alloc_array__attach"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.test_array_map_1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run array_map 1-4");
	ASSERT_EQ(topts.retval, 0, "test_run array_map 1-4");
	ASSERT_EQ(skel->bss->cpu0_field_d, 2, "cpu0_field_d");
	ASSERT_EQ(skel->bss->sum_field_c, 1, "sum_field_c");
out:
	percpu_alloc_array__destroy(skel);
}

static void test_array_sleepable(void)
{
	struct percpu_alloc_array *skel;
	int err, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = percpu_alloc_array__open();
	if (!ASSERT_OK_PTR(skel, "percpu_alloc__open"))
		return;

	bpf_program__set_autoload(skel->progs.test_array_map_10, true);

	skel->bss->my_pid = getpid();
	skel->rodata->nr_cpus = libbpf_num_possible_cpus();

	err = percpu_alloc_array__load(skel);
	if (!ASSERT_OK(err, "percpu_alloc_array__load"))
		goto out;

	err = percpu_alloc_array__attach(skel);
	if (!ASSERT_OK(err, "percpu_alloc_array__attach"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.test_array_map_10);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run array_map_10");
	ASSERT_EQ(topts.retval, 0, "test_run array_map_10");
	ASSERT_EQ(skel->bss->cpu0_field_d, 2, "cpu0_field_d");
	ASSERT_EQ(skel->bss->sum_field_c, 1, "sum_field_c");
out:
	percpu_alloc_array__destroy(skel);
}

static void test_cgrp_local_storage(void)
{
	struct percpu_alloc_cgrp_local_storage *skel;
	int err, cgroup_fd, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	cgroup_fd = test__join_cgroup("/percpu_alloc");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup /percpu_alloc"))
		return;

	skel = percpu_alloc_cgrp_local_storage__open();
	if (!ASSERT_OK_PTR(skel, "percpu_alloc_cgrp_local_storage__open"))
		goto close_fd;

	skel->bss->my_pid = getpid();
	skel->rodata->nr_cpus = libbpf_num_possible_cpus();

	err = percpu_alloc_cgrp_local_storage__load(skel);
	if (!ASSERT_OK(err, "percpu_alloc_cgrp_local_storage__load"))
		goto destroy_skel;

	err = percpu_alloc_cgrp_local_storage__attach(skel);
	if (!ASSERT_OK(err, "percpu_alloc_cgrp_local_storage__attach"))
		goto destroy_skel;

	prog_fd = bpf_program__fd(skel->progs.test_cgrp_local_storage_1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run cgrp_local_storage 1-3");
	ASSERT_EQ(topts.retval, 0, "test_run cgrp_local_storage 1-3");
	ASSERT_EQ(skel->bss->cpu0_field_d, 2, "cpu0_field_d");
	ASSERT_EQ(skel->bss->sum_field_c, 1, "sum_field_c");

destroy_skel:
	percpu_alloc_cgrp_local_storage__destroy(skel);
close_fd:
	close(cgroup_fd);
}

static void test_failure(void) {
	RUN_TESTS(percpu_alloc_fail);
}

static void test_percpu_map_op_cpu_flag(struct bpf_map *map, void *keys, size_t key_sz,
					u32 max_entries, bool test_batch)
{
	int i, j, cpu, map_fd, value_size, nr_cpus, err;
	u64 *values = NULL, batch = 0, flags;
	const u64 value = 0xDEADC0DE;
	size_t value_sz = sizeof(u64);
	u32 count;
	LIBBPF_OPTS(bpf_map_batch_opts, batch_opts);

	nr_cpus = libbpf_num_possible_cpus();
	if (!ASSERT_GT(nr_cpus, 0, "libbpf_num_possible_cpus"))
		return;

	value_size = value_sz * nr_cpus;
	values = calloc(max_entries, value_size);
	if (!ASSERT_OK_PTR(values, "calloc values"))
		goto out;
	memset(values, 0, value_size * max_entries);

	map_fd = bpf_map__fd(map);
	flags = BPF_F_CPU | BPF_F_ALL_CPUS;
	err = bpf_map_lookup_elem_flags(map_fd, keys, values, flags);
	if (!ASSERT_ERR(err, "bpf_map_lookup_elem_flags err"))
		goto out;

	err = bpf_map_update_elem(map_fd, keys, values, flags);
	if (!ASSERT_ERR(err, "bpf_map_update_elem err"))
		goto out;

	flags = (u64)nr_cpus << 32 | BPF_F_CPU;
	err = bpf_map_update_elem(map_fd, keys, values, flags);
	if (!ASSERT_EQ(err, -ERANGE, "bpf_map_update_elem -ERANGE"))
		goto out;

	err = bpf_map__update_elem(map, keys, key_sz, values, value_sz, flags);
	if (!ASSERT_EQ(err, -ERANGE, "bpf_map__update_elem -ERANGE"))
		goto out;

	err = bpf_map_lookup_elem_flags(map_fd, keys, values, flags);
	if (!ASSERT_EQ(err, -ERANGE, "bpf_map_lookup_elem_flags -ERANGE"))
		goto out;

	err = bpf_map__lookup_elem(map, keys, key_sz, values, value_sz, flags);
	if (!ASSERT_EQ(err, -ERANGE, "bpf_map__lookup_elem -ERANGE"))
		goto out;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		/* clear value on all cpus */
		values[0] = 0;
		flags = BPF_F_ALL_CPUS;
		for (i = 0; i < max_entries; i++) {
			err = bpf_map__update_elem(map, keys + i * key_sz, key_sz, values,
						   value_sz, flags);
			if (!ASSERT_OK(err, "bpf_map__update_elem all_cpus"))
				goto out;
		}

		/* update value on specified cpu */
		for (i = 0; i < max_entries; i++) {
			values[0] = value;
			flags = (u64)cpu << 32 | BPF_F_CPU;
			err = bpf_map__update_elem(map, keys + i * key_sz, key_sz, values,
						   value_sz, flags);
			if (!ASSERT_OK(err, "bpf_map__update_elem specified cpu"))
				goto out;

			/* lookup then check value on CPUs */
			for (j = 0; j < nr_cpus; j++) {
				flags = (u64)j << 32 | BPF_F_CPU;
				err = bpf_map__lookup_elem(map, keys + i * key_sz, key_sz, values,
							   value_sz, flags);
				if (!ASSERT_OK(err, "bpf_map__lookup_elem specified cpu"))
					goto out;
				if (!ASSERT_EQ(values[0], j != cpu ? 0 : value,
					       "bpf_map__lookup_elem value on specified cpu"))
					goto out;
			}
		}
	}

	if (!test_batch)
		goto out;

	batch_opts.elem_flags = (u64)nr_cpus << 32 | BPF_F_CPU;
	err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &batch_opts);
	if (!ASSERT_EQ(err, -ERANGE, "bpf_map_update_batch -ERANGE"))
		goto out;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		memset(values, 0, max_entries * value_size);

		/* clear values across all CPUs */
		batch_opts.elem_flags = BPF_F_ALL_CPUS;
		err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &batch_opts);
		if (!ASSERT_OK(err, "bpf_map_update_batch all_cpus"))
			goto out;

		/* update values on specified CPU */
		for (i = 0; i < max_entries; i++)
			values[i] = value;

		batch_opts.elem_flags = (u64)cpu << 32 | BPF_F_CPU;
		err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &batch_opts);
		if (!ASSERT_OK(err, "bpf_map_update_batch specified cpu"))
			goto out;

		/* lookup values on specified CPU */
		memset(values, 0, max_entries * value_sz);
		err = bpf_map_lookup_batch(map_fd, NULL, &batch, keys, values, &count, &batch_opts);
		if (!ASSERT_TRUE(!err || err == -ENOENT, "bpf_map_lookup_batch specified cpu"))
			goto out;

		for (i = 0; i < max_entries; i++)
			if (!ASSERT_EQ(values[i], value, "value on specified cpu"))
				goto out;

		/* lookup values from all CPUs */
		batch_opts.elem_flags = 0;
		memset(values, 0, max_entries * value_size);
		err = bpf_map_lookup_batch(map_fd, NULL, &batch, keys, values, &count, &batch_opts);
		if (!ASSERT_TRUE(!err || err == -ENOENT, "bpf_map_lookup_batch all_cpus"))
			goto out;

		for (i = 0; i < max_entries; i++) {
			for (j = 0; j < nr_cpus; j++) {
				if (!ASSERT_EQ(values[i*nr_cpus + j], j != cpu ? 0 : value,
					       "value on specified cpu"))
					goto out;
			}
		}
	}

out:
	if (values)
		free(values);
}

static void test_percpu_map_cpu_flag(enum bpf_map_type map_type)
{
	struct percpu_alloc_array *skel;
	size_t key_sz = sizeof(int);
	int *keys = NULL, i, err;
	struct bpf_map *map;
	u32 max_entries;

	skel = percpu_alloc_array__open();
	if (!ASSERT_OK_PTR(skel, "percpu_alloc_array__open"))
		return;

	map = skel->maps.percpu;
	bpf_map__set_type(map, map_type);

	err = percpu_alloc_array__load(skel);
	if (!ASSERT_OK(err, "test_percpu_alloc__load"))
		goto out;

	max_entries = bpf_map__max_entries(map);
	keys = calloc(max_entries, key_sz);
	if (!ASSERT_OK_PTR(keys, "calloc keys"))
		goto out;

	for (i = 0; i < max_entries; i++)
		keys[i] = i;

	test_percpu_map_op_cpu_flag(map, keys, key_sz, max_entries, true);
out:
	if (keys)
		free(keys);
	percpu_alloc_array__destroy(skel);
}

static void test_percpu_array_cpu_flag(void)
{
	test_percpu_map_cpu_flag(BPF_MAP_TYPE_PERCPU_ARRAY);
}

static void test_percpu_hash_cpu_flag(void)
{
	test_percpu_map_cpu_flag(BPF_MAP_TYPE_PERCPU_HASH);
}

static void test_lru_percpu_hash_cpu_flag(void)
{
	test_percpu_map_cpu_flag(BPF_MAP_TYPE_LRU_PERCPU_HASH);
}

static void test_percpu_cgroup_storage_cpu_flag(void)
{
	struct bpf_cgroup_storage_key key;
	struct percpu_alloc_array *skel;
	int cgroup = -1, prog_fd, err;
	struct bpf_map *map;

	skel = percpu_alloc_array__open_and_load();
	if (!ASSERT_OK_PTR(skel, "percpu_alloc_array__open_and_load"))
		return;

	cgroup = create_and_get_cgroup("/cg_percpu");
	if (!ASSERT_GE(cgroup, 0, "create_and_get_cgroup"))
		goto out;

	err = join_cgroup("/cg_percpu");
	if (!ASSERT_OK(err, "join_cgroup"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.cgroup_egress);
	err = bpf_prog_attach(prog_fd, cgroup, BPF_CGROUP_INET_EGRESS, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	map = skel->maps.percpu_cgroup_storage;
	err = bpf_map_get_next_key(bpf_map__fd(map), NULL, &key);
	if (!ASSERT_OK(err, "bpf_map_get_next_key"))
		goto out;

	test_percpu_map_op_cpu_flag(map, &key, sizeof(key), 1, false);
out:
	bpf_prog_detach2(-1, cgroup, BPF_CGROUP_INET_EGRESS);
	close(cgroup);
	cleanup_cgroup_environment();
	percpu_alloc_array__destroy(skel);
}

void test_percpu_alloc(void)
{
	if (test__start_subtest("array"))
		test_array();
	if (test__start_subtest("array_sleepable"))
		test_array_sleepable();
	if (test__start_subtest("cgrp_local_storage"))
		test_cgrp_local_storage();
	if (test__start_subtest("failure_tests"))
		test_failure();
	if (test__start_subtest("cpu_flag_percpu_array"))
		test_percpu_array_cpu_flag();
	if (test__start_subtest("cpu_flag_percpu_hash"))
		test_percpu_hash_cpu_flag();
	if (test__start_subtest("cpu_flag_lru_percpu_hash"))
		test_lru_percpu_hash_cpu_flag();
	if (test__start_subtest("cpu_flag_percpu_cgroup_storage"))
		test_percpu_cgroup_storage_cpu_flag();
}
