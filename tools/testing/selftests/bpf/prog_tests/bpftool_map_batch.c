// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <test_progs.h>
#include <bpf/btf.h>
#include "bpftool_helpers.h"
#include "bpftool_map_batch.skel.h"

/* Fits the plain and JSON dumps of the multi-batch cases below. */
#define OUTPUT_SIZE (8U << 20)

struct dump_case {
	const char *name;
	enum bpf_map_type type;
	__u32 key_size;
	__u32 value_size;
	__u32 entries;
	bool btf;
	/* Values large enough that the 1 MiB budget needs several batches. */
	bool multi_batch;
};

static bool is_percpu(enum bpf_map_type type)
{
	return type == BPF_MAP_TYPE_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_PERCPU_ARRAY;
}

static int run_dump(struct bpftool_map_batch *skel, __u32 id, bool json,
		    int fail_batch, char *output)
{
	char command[64];
	int err;

	snprintf(command, sizeof(command), "%smap dump id %u",
		 json ? "-j " : "", id);
	skel->bss->fail_batch = fail_batch;
	skel->bss->batch_calls = 0;
	skel->bss->elem_calls = 0;
	output[0] = '\0';
	err = get_bpftool_command_output(command, output, OUTPUT_SIZE);
	if (!ASSERT_LT(strlen(output), OUTPUT_SIZE - 1, "output_fits"))
		return -1;
	return err;
}

static void check_same(const char *output, const char *expected, const char *name)
{
	size_t i;

	for (i = 0; output[i] && output[i] == expected[i]; i++)
		;
	if (!ASSERT_EQ(output[i], expected[i], name))
		printf("%s: first difference at offset %zu\n", name, i);
}

/* Failing every batch lookup gives the dump of individual lookups. */
static void check_dump(struct bpftool_map_batch *skel, const struct dump_case *test,
		       __u32 id, bool json, char *expected, char *output)
{
	int fail;

	if (!ASSERT_OK(run_dump(skel, id, json, -1, expected), "individual_dump") ||
	    !ASSERT_EQ(skel->bss->elem_calls, test->entries, "individual_lookups"))
		return;

	if (!ASSERT_OK(run_dump(skel, id, json, 0, output), "batch_dump"))
		return;
	ASSERT_GE(skel->bss->batch_calls, test->multi_batch ? 2 : 1, "batch_calls");
	ASSERT_EQ(skel->bss->elem_calls, 0, "batch_only");
	check_same(output, expected, "batch_output");

	if (!test->multi_batch)
		return;
	/* Fail before and after a batch has been printed. */
	for (fail = 1; fail <= 2; fail++) {
		if (!ASSERT_OK(run_dump(skel, id, json, fail, output), "fallback_dump"))
			return;
		ASSERT_EQ(skel->bss->batch_calls, fail, "fallback_batch_calls");
		if (fail == 1) {
			ASSERT_EQ(skel->bss->elem_calls, test->entries, "fallback_lookups");
		} else {
			ASSERT_GT(skel->bss->elem_calls, 0, "resumed_lookups");
			ASSERT_LT(skel->bss->elem_calls, test->entries, "not_restarted");
		}
		check_same(output, expected, "fallback_output");
	}
}

static void fill_bytes(void *buf, __u32 size, __u32 seed)
{
	__u8 *bytes = buf;
	__u32 i;

	for (i = 0; i < size; i++)
		bytes[i] = seed * 37 + i;
}

static void run_case(struct bpftool_map_batch *skel, const struct dump_case *test,
		     char *expected, char *output)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	int fd = -1, inner_fd = -1, cpus = 1, cpu;
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	__u32 i, max_entries, stride;
	struct btf *btf = NULL;
	__u8 key[8] = {};
	void *values = NULL;

	if (is_percpu(test->type)) {
		cpus = libbpf_num_possible_cpus();
		if (!ASSERT_GT(cpus, 0, "possible_cpus"))
			return;
	}
	stride = is_percpu(test->type) ? (test->value_size + 7) & ~7U : test->value_size;
	values = calloc(cpus, stride);
	if (!ASSERT_OK_PTR(values, "values"))
		return;

	if (test->btf) {
		btf = btf__new_empty();
		if (!ASSERT_OK_PTR(btf, "btf_new") ||
		    !ASSERT_EQ(btf__add_int(btf, "unsigned int", 4, 0), 1, "btf_int") ||
		    !ASSERT_OK(btf__load_into_kernel(btf), "btf_load"))
			goto out;
		opts.btf_fd = btf__fd(btf);
		opts.btf_key_type_id = 1;
		opts.btf_value_type_id = 1;
	}
	if (test->type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
	    test->type == BPF_MAP_TYPE_HASH_OF_MAPS) {
		inner_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "batch_inner", 4, 4, 1, NULL);
		if (!ASSERT_OK_FD(inner_fd, "inner_map"))
			goto out;
		opts.inner_map_fd = inner_fd;
	}
	if (test->type == BPF_MAP_TYPE_LPM_TRIE || test->type == BPF_MAP_TYPE_RHASH)
		opts.map_flags = BPF_F_NO_PREALLOC;
	max_entries = test->entries ?: 1;
	/* Leave room for per-CPU LRU free lists instead of testing eviction. */
	if (test->type == BPF_MAP_TYPE_LRU_HASH ||
	    test->type == BPF_MAP_TYPE_LRU_PERCPU_HASH)
		max_entries *= 4;
	/* Avoid asynchronous growth during dump comparisons. */
	if (test->type == BPF_MAP_TYPE_RHASH)
		opts.map_extra = max_entries;

	fd = bpf_map_create(test->type, "batch_dump", test->key_size,
			    test->value_size, max_entries, &opts);
	if (!ASSERT_OK_FD(fd, "map_create"))
		goto out;
	for (i = 0; i < test->entries; i++) {
		if (test->type == BPF_MAP_TYPE_LPM_TRIE) {
			__u32 prefix[] = { 32, htonl(i) };

			memcpy(key, prefix, sizeof(prefix));
		} else if (test->key_size == 1) {
			key[0] = (__u8)i;
		} else {
			/* Array map indices use native byte order. */
			memcpy(key, &i, sizeof(i));
		}
		if (inner_fd >= 0)
			memcpy(values, &inner_fd, sizeof(inner_fd));
		else
			for (cpu = 0; cpu < cpus; cpu++)
				fill_bytes(values + cpu * stride, test->value_size,
					   i + cpu * 101);
		if (!ASSERT_OK(bpf_map_update_elem(fd, key, values, BPF_ANY), "map_update"))
			goto out;
	}
	if (!ASSERT_OK(bpf_map_get_info_by_fd(fd, &info, &len), "map_info"))
		goto out;

	check_dump(skel, test, info.id, false, expected, output);
	check_dump(skel, test, info.id, true, expected, output);
out:
	if (fd >= 0)
		close(fd);
	if (inner_fd >= 0)
		close(inner_fd);
	btf__free(btf);
	free(values);
}

void test_bpftool_map_batch(void)
{
	static const struct dump_case cases[] = {
		{ "hash", BPF_MAP_TYPE_HASH, 4, 4, 100 },
		{ "empty", BPF_MAP_TYPE_HASH, 4, 4, 0 },
		/* The hash cursor is wider than the key; values are unaligned. */
		{ "odd_sizes", BPF_MAP_TYPE_HASH, 1, 3, 100 },
		{ "btf", BPF_MAP_TYPE_HASH, 4, 4, 100, true },
		{ "lru_hash", BPF_MAP_TYPE_LRU_HASH, 4, 4, 100 },
		{ "percpu_hash", BPF_MAP_TYPE_PERCPU_HASH, 4, 3, 100 },
		{ "lru_percpu_hash", BPF_MAP_TYPE_LRU_PERCPU_HASH, 4, 4, 100 },
		{ "btf_percpu_hash", BPF_MAP_TYPE_PERCPU_HASH, 4, 4, 100, true },
		{ "rhash", BPF_MAP_TYPE_RHASH, 4, 4, 100 },
		{ "array", BPF_MAP_TYPE_ARRAY, 4, 4, 100 },
		{ "percpu_array", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 3, 100 },
		{ "lpm_trie", BPF_MAP_TYPE_LPM_TRIE, 8, 4, 100 },
		{ "array_of_maps", BPF_MAP_TYPE_ARRAY_OF_MAPS, 4, 4, 100 },
		{ "hash_of_maps", BPF_MAP_TYPE_HASH_OF_MAPS, 4, 4, 100 },
		/* Bucket and key cursors, up to 255 entries per batch. */
		{ "multi_batch_hash", BPF_MAP_TYPE_HASH, 4, 4096, 256, false, true },
		{ "multi_batch_array", BPF_MAP_TYPE_ARRAY, 4, 4096, 256, false, true },
	};
	struct bpftool_map_batch *skel;
	char *expected = NULL, *output = NULL;
	unsigned int i;

	skel = bpftool_map_batch__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;
	skel->bss->test_tgid = getpid();
	if (!ASSERT_OK(bpftool_map_batch__attach(skel), "skel_attach"))
		goto out;
	expected = malloc(OUTPUT_SIZE);
	output = malloc(OUTPUT_SIZE);
	if (!ASSERT_OK_PTR(expected, "expected") || !ASSERT_OK_PTR(output, "output"))
		goto out;

	for (i = 0; i < ARRAY_SIZE(cases); i++)
		if (test__start_subtest(cases[i].name))
			run_case(skel, &cases[i], expected, output);
out:
	free(expected);
	free(output);
	bpftool_map_batch__destroy(skel);
}
