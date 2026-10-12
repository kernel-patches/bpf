// SPDX-License-Identifier: GPL-2.0-only
#include <test_progs.h>
#include <bpftool_helpers.h>
#include <bpf/btf.h>

#define OUTPUT_SIZE (1024 * 1024)

static void check_show(char *output, struct bpf_map_info *info)
{
	char id[32];
	char *map, *end, *btf;

	snprintf(id, sizeof(id), "{\"id\":%u,", info->id);
	map = strstr(output, id);
	if (!ASSERT_OK_PTR(map, "map_in_output"))
		return;
	end = strchr(map, '}');
	if (!ASSERT_OK_PTR(end, "map_object_end"))
		return;
	btf = strstr(map, "\"btf_id\":");
	if (info->btf_id) {
		ASSERT_TRUE(btf && btf < end, "typed_map_btf");
		if (btf && btf < end)
			ASSERT_EQ(strtoul(btf + strlen("\"btf_id\":"), NULL, 10),
				  info->btf_id, "btf_id");
	} else {
		ASSERT_TRUE(!btf || btf > end, "raw_map_no_btf");
	}
}

static void test_map_info(const char *operation)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct bpf_map_info info[2] = {};
	char command[MAX_BPFTOOL_CMD_LEN], name[BPF_OBJ_NAME_LEN];
	char elements[2][1024] = {}, expected[4096];
	struct btf *btf = NULL;
	int fds[] = { -1, -1 };
	__u64 wide_key = 0, wide_value = 1;
	__u32 key = 0, value = 2;
	char *output;
	int i;

	output = malloc(OUTPUT_SIZE);
	if (!ASSERT_OK_PTR(output, "output"))
		return;
	snprintf(name, sizeof(name), "info_%u", getpid());
	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "create_btf") ||
	    !ASSERT_EQ(btf__add_int(btf, "unsigned long long", 8, 0), 1, "btf_int") ||
	    !ASSERT_OK(btf__load_into_kernel(btf), "load_btf"))
		goto out;
	opts.btf_fd = btf__fd(btf);
	opts.btf_key_type_id = 1;
	opts.btf_value_type_id = 1;
	/* Query the typed map before a smaller map without BTF. */
	fds[0] = bpf_map_create(BPF_MAP_TYPE_HASH, name, 8, 8, 1, &opts);
	fds[1] = bpf_map_create(BPF_MAP_TYPE_HASH, name, 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(fds[0], "create_typed") ||
	    !ASSERT_OK_FD(fds[1], "create_raw") ||
	    !ASSERT_OK(bpf_map_update_elem(fds[0], &wide_key, &wide_value, BPF_ANY),
		       "populate_typed") ||
	    !ASSERT_OK(bpf_map_update_elem(fds[1], &key, &value, BPF_ANY), "populate_raw"))
		goto out;
	for (i = 0; i < ARRAY_SIZE(fds); i++) {
		__u32 len = sizeof(info[i]);

		if (!ASSERT_OK(bpf_map_get_info_by_fd(fds[i], &info[i], &len), "map_info"))
			goto out;
	}
	if (!ASSERT_LT(info[0].id, info[1].id, "map_order"))
		goto out;

	if (!strcmp(operation, "show_all"))
		snprintf(command, sizeof(command), "-j map show");
	else if (!strcmp(operation, "show_name"))
		snprintf(command, sizeof(command), "-j map show name %s", name);
	else
		snprintf(command, sizeof(command), "%s map dump name %s",
			 !strcmp(operation, "dump_json") ? "-j" : "", name);
	output[0] = '\0';
	if (!ASSERT_OK(get_bpftool_command_output(command, output, OUTPUT_SIZE), operation))
		goto out;
	if (!strncmp(operation, "show_", 5)) {
		check_show(output, &info[0]);
		check_show(output, &info[1]);
	} else if (!strcmp(operation, "dump_json")) {
		for (i = 0; i < ARRAY_SIZE(fds); i++) {
			snprintf(command, sizeof(command), "-j map dump id %u", info[i].id);
			if (!ASSERT_OK(get_bpftool_command_output(command, elements[i],
							 sizeof(elements[i])), "single_dump"))
				goto out;
			elements[i][strcspn(elements[i], "\n")] = '\0';
		}
		snprintf(expected, sizeof(expected),
			 "[{\"id\":%u,\"type\":\"hash\",\"name\":\"%s\",\"flags\":0,"
			 "\"elements\":%s},{\"id\":%u,\"type\":\"hash\",\"name\":\"%s\","
			 "\"flags\":0,\"elements\":%s}]\n",
			 info[0].id, name, elements[0], info[1].id, name, elements[1]);
		ASSERT_STREQ(output, expected, "independent_map_formatting");
	} else {
		char *count = strstr(output, "Found 1 element\n");

		ASSERT_NULL(strstr(output, "\"value\":"), "mixed_maps_use_raw_output");
		if (ASSERT_OK_PTR(count, "first_map_count"))
			ASSERT_HAS_SUBSTR(count + 1, "Found 1 element\n", "second_map_count");
	}
out:
	for (i = 0; i < ARRAY_SIZE(fds); i++)
		if (fds[i] >= 0)
			close(fds[i]);
	btf__free(btf);
	free(output);
}

void serial_test_bpftool_map_info(void)
{
	if (test__start_subtest("show_all"))
		test_map_info("show_all");
	if (test__start_subtest("show_name"))
		test_map_info("show_name");
	if (test__start_subtest("dump_json"))
		test_map_info("dump_json");
	if (test__start_subtest("dump_plain"))
		test_map_info("dump_plain");
}
