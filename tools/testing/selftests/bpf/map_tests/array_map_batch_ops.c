// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <test_maps.h>

static int nr_cpus;

static void map_batch_update(int map_fd, __u32 max_entries, int *keys,
			     __s64 *values, bool is_pcpu)
{
	int i, j, err;
	int cpu_offset = 0;
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);

	for (i = 0; i < max_entries; i++) {
		keys[i] = i;
		if (is_pcpu) {
			cpu_offset = i * nr_cpus;
			for (j = 0; j < nr_cpus; j++)
				(values + cpu_offset)[j] = i + 1 + j;
		} else {
			values[i] = i + 1;
		}
	}

	err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &opts);
	CHECK(err, "bpf_map_update_batch()", "error:%s\n", strerror(errno));
}

static void map_batch_verify(int *visited, __u32 max_entries, int *keys,
			     __s64 *values, bool is_pcpu)
{
	int i, j;
	int cpu_offset = 0;

	memset(visited, 0, max_entries * sizeof(*visited));
	for (i = 0; i < max_entries; i++) {
		if (is_pcpu) {
			cpu_offset = i * nr_cpus;
			for (j = 0; j < nr_cpus; j++) {
				__s64 value = (values + cpu_offset)[j];
				CHECK(keys[i] + j + 1 != value,
				      "key/value checking",
				      "error: i %d j %d key %d value %lld\n", i,
				      j, keys[i], value);
			}
		} else {
			CHECK(keys[i] + 1 != values[i], "key/value checking",
			      "error: i %d key %d value %lld\n", i, keys[i],
			      values[i]);
		}
		visited[i] = 1;
	}
	for (i = 0; i < max_entries; i++) {
		CHECK(visited[i] != 1, "visited checking",
		      "error: keys array at index %d missing\n", i);
	}
}

static void __test_map_lookup_and_update_batch(bool is_pcpu)
{
	int map_fd, *keys, *visited;
	__u32 count, total, total_success;
	const __u32 max_entries = 10;
	__u64 batch = 0;
	int err, step, value_size;
	void *values;
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);

	map_fd = bpf_map_create(is_pcpu ? BPF_MAP_TYPE_PERCPU_ARRAY : BPF_MAP_TYPE_ARRAY,
				"array_map", sizeof(int), sizeof(__s64), max_entries, NULL);
	CHECK(map_fd == -1,
	      "bpf_map_create()", "error:%s\n", strerror(errno));

	value_size = sizeof(__s64);
	if (is_pcpu)
		value_size *= nr_cpus;

	keys = calloc(max_entries, sizeof(*keys));
	values = calloc(max_entries, value_size);
	visited = calloc(max_entries, sizeof(*visited));
	CHECK(!keys || !values || !visited, "malloc()", "error:%s\n",
	      strerror(errno));

	/* test 1: lookup in a loop with various steps. */
	total_success = 0;
	for (step = 1; step < max_entries; step++) {
		map_batch_update(map_fd, max_entries, keys, values, is_pcpu);
		map_batch_verify(visited, max_entries, keys, values, is_pcpu);
		memset(keys, 0, max_entries * sizeof(*keys));
		memset(values, 0, max_entries * value_size);
		batch = 0;
		total = 0;
		/* iteratively lookup/delete elements with 'step'
		 * elements each.
		 */
		count = step;
		while (true) {
			err = bpf_map_lookup_batch(map_fd,
						   total ? &batch : NULL,
						   &batch, keys + total,
						   values + total * value_size,
						   &count, &opts);

			CHECK((err && errno != ENOENT), "lookup with steps",
			      "error: %s\n", strerror(errno));

			total += count;
			if (err)
				break;

		}

		CHECK(total != max_entries, "lookup with steps",
		      "total = %u, max_entries = %u\n", total, max_entries);

		map_batch_verify(visited, max_entries, keys, values, is_pcpu);

		total_success++;
	}

	CHECK(total_success == 0, "check total_success",
	      "unexpected failure\n");

	free(keys);
	free(values);
	free(visited);
	close(map_fd);
}

static void array_map_batch_ops(void)
{
	__test_map_lookup_and_update_batch(false);
	printf("test_%s:PASS\n", __func__);
}

static void array_percpu_map_batch_ops(void)
{
	__test_map_lookup_and_update_batch(true);
	printf("test_%s:PASS\n", __func__);
}

static void array_percpu_map_batch_cpu(void)
{
	int map_fd, *keys, value_size, cpu, i, j, err;
	u32 max_entries = 1, count = max_entries;
	const u64 value = 0xDEADC0DE;
	u64 batch = 0, cpu_flag;
	__s64 *values;
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
			    .elem_flags = 0,
			    .flags = 0,
	);

	map_fd = bpf_map_create(BPF_MAP_TYPE_PERCPU_ARRAY, "percpu_array_map",
				sizeof(int), sizeof(__s64), max_entries, NULL);
	if (!ASSERT_FALSE(map_fd < 0, "bpf_map_create"))
		return;

	value_size = sizeof(__s64) * nr_cpus;
	values = calloc(max_entries, value_size);
	keys = calloc(max_entries, sizeof(*keys));
	if (!ASSERT_FALSE(!keys || !values, "calloc keys and values"))
		goto out;

	cpu_flag = nr_cpus;
	opts.elem_flags = (cpu_flag << 32) | BPF_F_CPU;
	err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &opts);
	if (!ASSERT_EQ(err, -E2BIG, "bpf_map_update_batch E2BIG"))
		goto out;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		memset(values, 0, max_entries * value_size);

		/* clear value on all cpus */
		cpu_flag = BPF_F_CPU_MASK;
		opts.elem_flags = (cpu_flag << 32) | BPF_F_CPU;
		err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &opts);
		if (!ASSERT_OK(err, "bpf_map_update_batch all cpus"))
			goto out;

		/* update value on current cpu */
		cpu_flag = cpu;
		values[0] = value;
		opts.elem_flags = (cpu_flag << 32) | BPF_F_CPU;
		err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &opts);
		if (!ASSERT_OK(err, "bpf_map_update_batch current cpu"))
			goto out;

		opts.elem_flags = 0;
		err = bpf_map_lookup_batch(map_fd, NULL, &batch, keys, values, &count, &opts);
		if (!ASSERT_TRUE(!err || err == -ENOENT, "bpf_map_lookup_batch"))
			goto out;

		for (i = 0; i < max_entries; i++) {
			for (j = 0; j < nr_cpus; j++) {
				if (!ASSERT_EQ(values[i*nr_cpus + j], j != cpu ? 0 : value,
					       "value on cpu"))
					goto out;
			}
		}
	}

	printf("test_%s:PASS\n", __func__);
out:
	if (keys)
		free(keys);
	if (values)
		free(values);
	close(map_fd);
}

void test_array_map_batch_ops(void)
{
	nr_cpus = libbpf_num_possible_cpus();

	CHECK(nr_cpus < 0, "nr_cpus checking",
	      "error: get possible cpus failed");

	array_map_batch_ops();
	array_percpu_map_batch_ops();
	array_percpu_map_batch_cpu();
}
