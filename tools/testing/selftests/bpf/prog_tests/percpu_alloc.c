// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
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

static void test_cpu_flag(void)
{
	int map_fd, *keys = NULL, value_size, cpu, i, j, nr_cpus, err;
	size_t key_sz = sizeof(int), value_sz = sizeof(u64);
	u64 batch = 0, *values = NULL, flags;
	struct percpu_alloc_array *skel;
	const u64 value = 0xDEADC0DE;
	u32 count, max_entries;
	struct bpf_map *map;
	LIBBPF_OPTS(bpf_map_batch_opts, batch_opts);

	nr_cpus = libbpf_num_possible_cpus();
	if (!ASSERT_GT(nr_cpus, 0, "libbpf_num_possible_cpus"))
		return;

	skel = percpu_alloc_array__open_and_load();
	if (!ASSERT_OK_PTR(skel, "percpu_alloc_array__open_and_load"))
		return;

	map = skel->maps.percpu;
	map_fd = bpf_map__fd(map);
	max_entries = bpf_map__max_entries(map);

	value_size = value_sz * nr_cpus;
	values = calloc(max_entries, value_size);
	if (!ASSERT_OK_PTR(values, "calloc values"))
		goto out;
	keys = calloc(max_entries, key_sz);
	if (!ASSERT_OK_PTR(keys, "calloc keys"))
		goto out;

	for (i = 0; i < max_entries; i++)
		keys[i] = i;
	memset(values, 0, max_entries * value_size);

	batch_opts.elem_flags = (u64)nr_cpus << 32 | BPF_F_CPU;
	err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &batch_opts);
	if (!ASSERT_EQ(err, -ERANGE, "bpf_map_update_batch -ERANGE"))
		goto out;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		memset(values, 0, max_entries * value_size);

		/* clear values across all CPUs */
		batch_opts.elem_flags = BPF_F_ALL_CPUS;
		err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &batch_opts);
		if (!ASSERT_OK(err, "bpf_map_update_batch all cpus"))
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
		if (!ASSERT_TRUE(!err || err == -ENOENT, "bpf_map_lookup_batch all cpus"))
			goto out;

		for (i = 0; i < max_entries; i++) {
			for (j = 0; j < nr_cpus; j++) {
				if (!ASSERT_EQ(values[i*nr_cpus + j], j != cpu ? 0 : value,
					       "value on specified cpu"))
					goto out;
			}
		}
	}

	flags = (u64)nr_cpus << 32 | BPF_F_CPU;
	err = bpf_map_update_elem(map_fd, keys, values, flags);
	if (!ASSERT_EQ(err, -ERANGE, "bpf_map_update_elem_opts -ERANGE"))
		goto out;

	err = bpf_map__update_elem(map, keys, key_sz, values, value_sz, flags);
	if (!ASSERT_EQ(err, -ERANGE, "bpf_map__update_elem_opts -ERANGE"))
		goto out;

	err = bpf_map_lookup_elem_flags(map_fd, keys, values, flags);
	if (!ASSERT_EQ(err, -ERANGE, "bpf_map_lookup_elem_opts -ERANGE"))
		goto out;

	err = bpf_map__lookup_elem(map, keys, key_sz, values, value_sz, flags);
	if (!ASSERT_EQ(err, -ERANGE, "bpf_map__lookup_elem_opts -ERANGE"))
		goto out;

	/* clear value on all cpus */
	batch_opts.elem_flags = BPF_F_ALL_CPUS;
	memset(values, 0, max_entries * value_sz);
	err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &batch_opts);
	if (!ASSERT_OK(err, "bpf_map_update_batch all cpus"))
		goto out;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		/* update value on specified cpu */
		values[0] = value;
		flags = (u64)cpu << 32 | BPF_F_CPU;
		for (i = 0; i < max_entries; i++) {
			err = bpf_map__update_elem(map, keys + i, key_sz, values, value_sz, flags);
			if (!ASSERT_OK(err, "bpf_map__update_elem specified cpu"))
				goto out;

			for (j = 0; j < nr_cpus; j++) {
				/* lookup then check value on CPUs */
				flags = (u64)j << 32 | BPF_F_CPU;
				err = bpf_map__lookup_elem(map, keys + i, key_sz, values, value_sz,
							   flags);
				if (!ASSERT_OK(err, "bpf_map__lookup_elem specified cpu"))
					goto out;
				if (!ASSERT_EQ(values[0], j != cpu ? 0 : value,
					       "bpf_map__lookup_elem value on specified cpu"))
					goto out;
			}
		}

		/* clear value on specified cpu */
		values[0] = 0;
		flags = (u64)cpu << 32 | BPF_F_CPU;
		err = bpf_map__update_elem(map, keys, key_sz, values, value_sz, flags);
		if (!ASSERT_OK(err, "bpf_map__update_elem specified cpu"))
			goto out;
	}

out:
	if (keys)
		free(keys);
	if (values)
		free(values);
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
	if (test__start_subtest("cpu_flag_tests"))
		test_cpu_flag();
}
