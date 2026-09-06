// SPDX-License-Identifier: GPL-2.0-only
#include <test_progs.h>
#include <bpftool_helpers.h>
#include <bpf/btf.h>

#define OUTPUT_SIZE 8192

static bool dump_map(__u32 id, const char *options, char *output)
{
	char command[MAX_BPFTOOL_CMD_LEN];

	snprintf(command, sizeof(command), "%s map dump id %u", options, id);
	memset(output, 0, OUTPUT_SIZE);
	if (!ASSERT_OK(get_bpftool_command_output(command, output, OUTPUT_SIZE - 1),
		       "dump_map"))
		return false;
	/* The helper doesn't terminate or strip the output. */
	output[strcspn(output, "\n")] = '\0';
	return true;
}

static __u32 map_id(int fd)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);

	if (!ASSERT_OK(bpf_map_get_info_by_fd(fd, &info, &len), "map_info"))
		return 0;
	return info.id;
}

static int count_token(const char *output, const char *token)
{
	int count = 0;

	while ((output = strstr(output, token))) {
		count++;
		output += strlen(token);
	}
	return count;
}

static void check_plain(__u32 root_id, __u32 inner_id, const char *type,
			int entries, bool typed)
{
	char command[MAX_BPFTOOL_CMD_LEN], header[128];
	char output[OUTPUT_SIZE] = {};
	const char *root, *inner;

	snprintf(command, sizeof(command), "--recursive map dump id %u", root_id);
	if (!ASSERT_OK(get_bpftool_command_output(command, output, sizeof(output) - 1),
		       "plain_dump"))
		return;
	snprintf(header, sizeof(header), "%u: %s  name dump_outer  ", root_id, type);
	root = strstr(output, header);
	if (!ASSERT_OK_PTR(root, "plain_root_header"))
		return;
	ASSERT_EQ(root - output, 0, "plain_root_first");
	ASSERT_EQ(count_token(output, "inner_map_id:"), entries, "plain_references");
	if (entries) {
		snprintf(header, sizeof(header), "%u: hash  name dump_inner  ", inner_id);
		inner = strstr(output, header);
		if (ASSERT_OK_PTR(inner, "plain_inner_header"))
			ASSERT_GT(inner - root, 0, "plain_inner_after_root");
		ASSERT_EQ(count_token(output, header), 1, "plain_inner_once");
	}
	ASSERT_EQ(count_token(output, "Found "), entries && !typed ? 2 : 1,
		  "plain_map_count");
	if (typed) {
		ASSERT_HAS_SUBSTR(output, "\"key\": 0", "plain_btf_key");
		ASSERT_HAS_SUBSTR(output, "\"value\": 16843009", "plain_btf_value");
	}
}

static void test_outer(enum bpf_map_type type, int entries, bool empty_inner,
		       bool typed)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	LIBBPF_OPTS(bpf_map_create_opts, inner_opts);
	struct btf *btf = NULL;
	char outer[OUTPUT_SIZE], inner[OUTPUT_SIZE], output[OUTPUT_SIZE];
	char expected[OUTPUT_SIZE * 3], reference[64];
	const char *type_name = libbpf_bpf_map_type_str(type);
	int inner_fd = -1, outer_fd = -1;
	__u32 root_id, inner_id, key, value = 0x01010101;

	if (typed) {
		btf = btf__new_empty();
		if (!ASSERT_OK_PTR(btf, "create_btf") ||
		    !ASSERT_EQ(btf__add_int(btf, "unsigned int", 4, 0), 1, "btf_int") ||
		    !ASSERT_OK(btf__load_into_kernel(btf), "load_btf"))
			goto out;
		inner_opts.btf_fd = btf__fd(btf);
		inner_opts.btf_key_type_id = 1;
		inner_opts.btf_value_type_id = 1;
	}
	inner_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "dump_inner", sizeof(key),
				  sizeof(value), 2, &inner_opts);
	if (!ASSERT_OK_FD(inner_fd, "create_inner"))
		goto out;
	key = 0;
	if (!empty_inner &&
	    !ASSERT_OK(bpf_map_update_elem(inner_fd, &key, &value, BPF_ANY),
		       "populate_inner"))
		goto out;
	opts.inner_map_fd = inner_fd;
	outer_fd = bpf_map_create(type, "dump_outer", sizeof(key), sizeof(__u32),
				 3, &opts);
	if (!ASSERT_OK_FD(outer_fd, "create_outer"))
		goto out;
	/* The unused third array slot also exercises failed lookups. */
	for (key = 0; key < entries; key++)
		if (!ASSERT_OK(bpf_map_update_elem(outer_fd, &key, &inner_fd, BPF_ANY),
			       "populate_outer"))
			goto out;
	root_id = map_id(outer_fd);
	inner_id = map_id(inner_fd);
	if (!root_id || !inner_id || !dump_map(root_id, "-j", outer) ||
	    !dump_map(inner_id, "-j", inner))
		goto out;

	ASSERT_EQ(outer[0], '[', "default_array");
	ASSERT_EQ(count_token(outer, "\"elements\":"), 0, "default_no_wrapper");
	ASSERT_EQ(count_token(outer, "\"id\":"), 0, "default_no_header");
	snprintf(reference, sizeof(reference), "\"inner_map_id\":%u", inner_id);
	ASSERT_EQ(count_token(outer, reference), entries, "default_references");
	if (!entries)
		ASSERT_STREQ(outer, "[]", "empty_outer_default");
	if (empty_inner)
		ASSERT_STREQ(inner, "[]", "empty_inner_default");
	else if (typed)
		ASSERT_HAS_SUBSTR(inner, "\"formatted\":{\"key\":0,\"value\":16843009}",
				  "typed_inner");
	else
		ASSERT_STREQ(inner,
			     "[{\"key\":[\"0x00\",\"0x00\",\"0x00\",\"0x00\"],"
			     "\"value\":[\"0x01\",\"0x01\",\"0x01\",\"0x01\"]}]",
			     "ordinary_default");

	/* Compare the complete JSON document: a flat array with the root first,
	 * one copy of the shared inner map, and unchanged entry representations.
	 */
	if (entries)
		snprintf(expected, sizeof(expected),
			 "[{\"id\":%u,\"type\":\"%s\",\"name\":\"dump_outer\","
			 "\"flags\":0,\"elements\":%s},{\"id\":%u,\"type\":\"hash\","
			 "\"name\":\"dump_inner\",\"flags\":0,\"elements\":%s}]",
			 root_id, type_name, outer, inner_id, inner);
	else
		snprintf(expected, sizeof(expected),
			 "[{\"id\":%u,\"type\":\"%s\",\"name\":\"dump_outer\","
			 "\"flags\":0,\"elements\":[]}]", root_id, type_name);
	if (dump_map(root_id, "-j -r", output))
		ASSERT_STREQ(output, expected, "recursive_json");
	if (dump_map(root_id, "--json --recursive", output))
		ASSERT_STREQ(output, expected, "recursive_long_options");
	check_plain(root_id, inner_id, type_name, entries, typed);

	/* Recursion on an ordinary map still emits a single map object. */
	snprintf(expected, sizeof(expected),
		 "[{\"id\":%u,\"type\":\"hash\",\"name\":\"dump_inner\","
		 "\"flags\":0,\"elements\":%s}]", inner_id, inner);
	if (dump_map(inner_id, "-j -r", output))
		ASSERT_STREQ(output, expected, "ordinary_recursive");
out:
	if (outer_fd >= 0)
		close(outer_fd);
	if (inner_fd >= 0)
		close(inner_fd);
	btf__free(btf);
}

static void test_multiple_roots(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	char command[MAX_BPFTOOL_CMD_LEN], name[BPF_OBJ_NAME_LEN];
	char output[OUTPUT_SIZE] = {}, expected[OUTPUT_SIZE * 4], elements[OUTPUT_SIZE];
	static const char * const types[] = { "hash", "array_of_maps", "hash_of_maps", "hash" };
	int fds[] = { -1, -1, -1, -1 };
	__u32 ids[4], key;
	int i, len = 0;

	/* Select the first inner map and both outers as roots. The other inner
	 * map must be appended after all three roots, even though it is found
	 * while dumping the first outer. A process-specific name avoids other
	 * tests' maps joining the selection.
	 */
	snprintf(name, sizeof(name), "dump_%u", getpid());
	fds[0] = bpf_map_create(BPF_MAP_TYPE_HASH, name, 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(fds[0], "create_selected_inner"))
		goto out;
	fds[3] = bpf_map_create(BPF_MAP_TYPE_HASH, "dump_discovered", 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(fds[3], "create_discovered_inner"))
		goto out;
	opts.inner_map_fd = fds[0];
	fds[1] = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, name, 4, 4, 2, &opts);
	if (!ASSERT_OK_FD(fds[1], "create_array_root"))
		goto out;
	fds[2] = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, name, 4, 4, 2, &opts);
	if (!ASSERT_OK_FD(fds[2], "create_hash_root"))
		goto out;
	for (i = 1; i <= 2; i++) {
		key = 0;
		if (!ASSERT_OK(bpf_map_update_elem(fds[i], &key, &fds[0], BPF_ANY),
			       "reference_selected_inner"))
			goto out;
		key = 1;
		if (!ASSERT_OK(bpf_map_update_elem(fds[i], &key, &fds[3], BPF_ANY),
			       "reference_discovered_inner"))
			goto out;
	}
	for (i = 0; i < ARRAY_SIZE(fds); i++) {
		ids[i] = map_id(fds[i]);
		if (!ids[i] || !dump_map(ids[i], "-j", elements))
			goto out;
		len += snprintf(expected + len, sizeof(expected) - len,
				"%s{\"id\":%u,\"type\":\"%s\",\"name\":\"%s\","
				"\"flags\":0,\"elements\":%s}%s",
				i ? "," : "[", ids[i], types[i],
				i == 3 ? "dump_discovered" : name, elements, i == 3 ? "]" : "");
	}
	snprintf(command, sizeof(command), "-j -r map dump name %s", name);
	if (ASSERT_OK(get_bpftool_command_output(command, output, sizeof(output) - 1),
		      "dump_multiple_roots")) {
		output[strcspn(output, "\n")] = '\0';
		ASSERT_STREQ(output, expected, "roots_first_and_seed_dedup");
	}
out:
	for (i = 0; i < ARRAY_SIZE(fds); i++)
		if (fds[i] >= 0)
			close(fds[i]);
}

void test_bpftool_map_dump(void)
{
	if (test__start_subtest("multiple_roots"))
		test_multiple_roots();
	if (test__start_subtest("array_of_maps"))
		test_outer(BPF_MAP_TYPE_ARRAY_OF_MAPS, 1, false, false);
	if (test__start_subtest("hash_of_maps"))
		test_outer(BPF_MAP_TYPE_HASH_OF_MAPS, 1, false, false);
	if (test__start_subtest("shared_inner"))
		test_outer(BPF_MAP_TYPE_ARRAY_OF_MAPS, 2, false, false);
	if (test__start_subtest("empty_array_of_maps"))
		test_outer(BPF_MAP_TYPE_ARRAY_OF_MAPS, 0, false, false);
	if (test__start_subtest("empty_hash_of_maps"))
		test_outer(BPF_MAP_TYPE_HASH_OF_MAPS, 0, false, false);
	if (test__start_subtest("btf_inner"))
		test_outer(BPF_MAP_TYPE_HASH_OF_MAPS, 1, false, true);
	if (test__start_subtest("empty_inner"))
		test_outer(BPF_MAP_TYPE_HASH_OF_MAPS, 1, true, false);
}
