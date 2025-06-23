// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "percpu_alloc_array.skel.h"
#include "percpu_alloc_cgrp_local_storage.skel.h"
#include "percpu_alloc_fail.skel.h"
#include "percpu_array_flag.skel.h"

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
	struct percpu_array_flag *skel;
	u64 batch = 0, *values = NULL;
	const u64 value = 0xDEADC0DE;
	u32 count, max_entries;
	struct bpf_map *map;
	LIBBPF_OPTS(bpf_map_lookup_elem_opts, lookup_opts,
		    .flags = BPF_F_CPU,
		    .cpu = 0,
	);
	LIBBPF_OPTS(bpf_map_update_elem_opts, update_opts,
		    .flags = BPF_F_CPU,
		    .cpu = 0,
	);
	LIBBPF_OPTS(bpf_map_batch_opts, batch_opts,
		    .elem_flags = BPF_F_CPU,
		    .flags = 0,
	);

	nr_cpus = libbpf_num_possible_cpus();
	if (!ASSERT_GT(nr_cpus, 0, "libbpf_num_possible_cpus"))
		return;

	skel = percpu_array_flag__open_and_load();
	if (!ASSERT_OK_PTR(skel, "percpu_array_flag__open_and_load"))
		return;

	map = skel->maps.percpu;
	map_fd = bpf_map__fd(map);
	max_entries = bpf_map__max_entries(map);

	value_size = value_sz * nr_cpus;
	values = calloc(max_entries, value_size);
	keys = calloc(max_entries, key_sz);
	if (!ASSERT_FALSE(!keys || !values, "calloc keys and values"))
		goto out;

	for (i = 0; i < max_entries; i++)
		keys[i] = i;
	memset(values, 0, max_entries * value_size);

	batch_opts.cpu = nr_cpus;
	err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &batch_opts);
	if (!ASSERT_EQ(err, -E2BIG, "bpf_map_update_batch -E2BIG"))
		goto out;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		memset(values, 0, max_entries * value_size);

		/* clear values on all CPUs */
		batch_opts.cpu = BPF_ALL_CPUS;
		batch_opts.elem_flags = BPF_F_CPU;
		err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &batch_opts);
		if (!ASSERT_OK(err, "bpf_map_update_batch all cpus"))
			goto out;

		/* update values on current CPU */
		for (i = 0; i < max_entries; i++)
			values[i] = value;

		batch_opts.cpu = cpu;
		err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &batch_opts);
		if (!ASSERT_OK(err, "bpf_map_update_batch current cpu"))
			goto out;

		/* lookup values on current CPU */
		batch_opts.cpu = cpu;
		batch_opts.elem_flags = BPF_F_CPU;
		memset(values, 0, max_entries * value_sz);
		err = bpf_map_lookup_batch(map_fd, NULL, &batch, keys, values, &count, &batch_opts);
		if (!ASSERT_TRUE(!err || err == -ENOENT, "bpf_map_lookup_batch current cpu"))
			goto out;

		for (i = 0; i < max_entries; i++)
			if (!ASSERT_EQ(values[i], value, "value on current cpu"))
				goto out;

		/* lookup values on all CPUs */
		batch_opts.cpu = 0;
		batch_opts.elem_flags = 0;
		memset(values, 0, max_entries * value_size);
		err = bpf_map_lookup_batch(map_fd, NULL, &batch, keys, values, &count, &batch_opts);
		if (!ASSERT_TRUE(!err || err == -ENOENT, "bpf_map_lookup_batch all cpus"))
			goto out;

		for (i = 0; i < max_entries; i++) {
			for (j = 0; j < nr_cpus; j++) {
				if (!ASSERT_EQ(values[i*nr_cpus + j], j != cpu ? 0 : value,
					       "value on cpu"))
					goto out;
			}
		}
	}

	update_opts.cpu = nr_cpus;
	err = bpf_map_update_elem_opts(map_fd, keys, values, &update_opts);
	if (!ASSERT_EQ(err, -E2BIG, "bpf_map_update_elem_opts -E2BIG"))
		goto out;

	err = bpf_map__update_elem_opts(map, keys, key_sz, values, value_sz,
					&update_opts);
	if (!ASSERT_EQ(err, -E2BIG, "bpf_map__update_elem_opts -E2BIG"))
		goto out;

	lookup_opts.cpu = nr_cpus;
	err = bpf_map_lookup_elem_opts(map_fd, keys, values, &lookup_opts);
	if (!ASSERT_EQ(err, -E2BIG, "bpf_map_lookup_elem_opts -E2BIG"))
		goto out;

	err = bpf_map__lookup_elem_opts(map, keys, key_sz, values, value_sz,
					&lookup_opts);
	if (!ASSERT_EQ(err, -E2BIG, "bpf_map__lookup_elem_opts -E2BIG"))
		goto out;

	/* clear value on all cpus */
	batch_opts.cpu = BPF_ALL_CPUS;
	batch_opts.elem_flags = BPF_F_CPU;
	memset(values, 0, max_entries * value_sz);
	err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &batch_opts);
	if (!ASSERT_OK(err, "bpf_map_update_batch all cpus"))
		goto out;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		/* update value on current cpu */
		values[0] = value;
		update_opts.cpu = cpu;
		for (i = 0; i < max_entries; i++) {
			err = bpf_map__update_elem_opts(map, keys + i,
							key_sz, values,
							value_sz, &update_opts);
			if (!ASSERT_OK(err, "bpf_map__update_elem_opts current cpu"))
				goto out;

			for (j = 0; j < nr_cpus; j++) {
				/* lookup then check value on CPUs */
				lookup_opts.cpu = j;
				err = bpf_map__lookup_elem_opts(map, keys + i,
								key_sz, values,
								value_sz,
								&lookup_opts);
				if (!ASSERT_OK(err, "bpf_map__lookup_elem_opts current cpu"))
					goto out;
				if (!ASSERT_EQ(values[0], j != cpu ? 0 : value,
					       "bpf_map__lookup_elem_opts value on current cpu"))
					goto out;
			}
		}

		/* clear value on current cpu */
		values[0] = 0;
		err = bpf_map__update_elem_opts(map, keys, key_sz, values,
						value_sz, &update_opts);
		if (!ASSERT_OK(err, "bpf_map__update_elem_opts current cpu"))
			goto out;
	}

out:
	if (keys)
		free(keys);
	if (values)
		free(values);
	percpu_array_flag__destroy(skel);
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
