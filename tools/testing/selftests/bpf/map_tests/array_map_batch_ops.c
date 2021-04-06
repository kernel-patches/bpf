// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <bpf_util.h>
#include <test_maps.h>

typedef BPF_PERCPU_TYPE(int) pcpu_map_value_t;

static void map_batch_update(int map_fd, __u32 max_entries, int *keys,
			     void *values, bool is_pcpu)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	pcpu_map_value_t *v;
	int i, j, err;
	int offset = 0;
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);

	if (is_pcpu)
		v = values;

	for (i = 0; i < max_entries; i++) {
		keys[i] = i;
		if (is_pcpu)
			for (j = 0; j < nr_cpus; j++)
				bpf_percpu(v + offset, j) = i + 1 + j;
		else
			((int *)values)[i] = i + 1;
		offset += nr_cpus;
	}

	err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &opts);
	CHECK(err, "bpf_map_update_batch()", "error:%s\n", strerror(errno));
}

static void map_batch_verify(int *visited, __u32 max_entries, int *keys,
			     void *values, bool is_pcpu)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	pcpu_map_value_t *v;
	int i, j;
	int offset = 0;

	if (is_pcpu)
		v = values;

	memset(visited, 0, max_entries * sizeof(*visited));
	for (i = 0; i < max_entries; i++) {
		if (is_pcpu) {
			for (j = 0; j < nr_cpus; j++) {
				int value = bpf_percpu(v + offset, j);
				CHECK(keys[i] + j + 1 != value,
				      "key/value checking",
				      "error: i %d j %d key %d value %d\n", i,
				      j, keys[i], value);
			}
		} else {
			CHECK(keys[i] + 1 != ((int *)values)[i],
			      "key/value checking",
			      "error: i %d key %d value %d\n", i, keys[i],
			      ((int *)values)[i]);
		}
		offset += nr_cpus;
		visited[i] = 1;
	}
	for (i = 0; i < max_entries; i++) {
		CHECK(visited[i] != 1, "visited checking",
		      "error: keys array at index %d missing\n", i);
	}
}

void __test_map_lookup_and_update_batch(bool is_pcpu)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct bpf_create_map_attr xattr = {
		.name = "array_map",
		.map_type = is_pcpu ? BPF_MAP_TYPE_PERCPU_ARRAY :
				      BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(int),
		.value_size = sizeof(int),
	};
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

	xattr.max_entries = max_entries;
	map_fd = bpf_create_map_xattr(&xattr);
	CHECK(map_fd == -1,
	      "bpf_create_map_xattr()", "error:%s\n", strerror(errno));

	if (is_pcpu)
		value_size = sizeof(pcpu_map_value_t) * nr_cpus;
	else
		value_size = sizeof(int);

	keys = malloc(max_entries * sizeof(*keys));
	values = calloc(max_entries, value_size);
	visited = malloc(max_entries * sizeof(*visited));
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
	free(visited);

	if (!is_pcpu)
		free(values);
}

void array_map_batch_ops(void)
{
	__test_map_lookup_and_update_batch(false);
	printf("test_%s:PASS\n", __func__);
}

void array_percpu_map_batch_ops(void)
{
	__test_map_lookup_and_update_batch(true);
	printf("test_%s:PASS\n", __func__);
}

void test_array_map_batch_ops(void)
{
	array_map_batch_ops();
	array_percpu_map_batch_ops();
}
