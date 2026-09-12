// SPDX-License-Identifier: GPL-2.0-only
#include <test_progs.h>
#include <bpftool_helpers.h>
#include <bpf/btf.h>
#include <sys/resource.h>
#include <dirent.h>

#define OUTPUT_SIZE 8192
#define MANY_MAPS_OUTPUT_SIZE 65536

static bool dump_map(__u32 id, const char *options, char *output)
{
	char command[MAX_BPFTOOL_CMD_LEN];

	snprintf(command, sizeof(command), "%s map dump id %u", options, id);
	memset(output, 0, OUTPUT_SIZE);
	if (!ASSERT_OK(get_bpftool_command_output(command, output, OUTPUT_SIZE - 1),
		       "dump_map"))
		return false;
	/* The helper leaves the trailing newline in place. */
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
	/* For arrays, unused slots also exercise failed lookups. */
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

	/*
	 * Compare the complete JSON document: a flat array with the root first,
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
	size_t len = 0;
	int i, n;

	/*
	 * Select the first inner map and both outers as roots. The other inner
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
		n = snprintf(expected + len, sizeof(expected) - len,
			     "%s{\"id\":%u,\"type\":\"%s\",\"name\":\"%s\","
			     "\"flags\":0,\"elements\":%s}%s",
			     i ? "," : "[", ids[i], types[i],
			     i == 3 ? "dump_discovered" : name, elements, i == 3 ? "]" : "");
		if (!ASSERT_GE(n, 0, "format_expected") ||
		    !ASSERT_LT(n, sizeof(expected) - len, "expected_length"))
			goto out;
		len += n;
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

static void test_unreadable(bool outer)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	char elements[OUTPUT_SIZE], output[OUTPUT_SIZE], root[OUTPUT_SIZE];
	char expected[OUTPUT_SIZE * 3], plain[OUTPUT_SIZE] = {};
	char command[MAX_BPFTOOL_CMD_LEN];
	int inner_fd = -1, outer_fd = -1, lookup_errno;
	__u32 inner_id, root_id, key = 0, value;

	/*
	 * Every key is enumerable, but PERF_EVENT_ARRAY lookup returns
	 * ENOTSUPP (the kernel-internal errno). Check both entries so an
	 * early exit on the first lookup failure cannot pass.
	 */
	inner_fd = bpf_map_create(BPF_MAP_TYPE_PERF_EVENT_ARRAY, "dump_unreadable",
				  sizeof(key), sizeof(value), 2, NULL);
	if (!ASSERT_OK_FD(inner_fd, "create_unreadable"))
		goto out;
	if (!ASSERT_LT(bpf_map_lookup_elem(inner_fd, &key, &value), 0,
		       "unreadable_lookup"))
		goto out;
	lookup_errno = errno;
	if (!ASSERT_NEQ(lookup_errno, ENOENT, "unreadable_not_missing"))
		goto out;
	inner_id = map_id(inner_fd);
	if (!inner_id || !dump_map(inner_id, "-j", elements))
		goto out;
	ASSERT_EQ(count_token(elements, "\"error\":"), 2, "default_json_errors");
	snprintf(command, sizeof(command), "map dump id %u", inner_id);
	if (!ASSERT_OK(get_bpftool_command_output(command, plain, sizeof(plain) - 1),
		       "default_plain_unreadable"))
		goto out;
	ASSERT_EQ(count_token(plain, strerror(lookup_errno)), 2, "default_plain_errors");
	ASSERT_HAS_SUBSTR(plain, "Found 0 elements", "default_plain_count");

	root_id = inner_id;
	if (outer) {
		opts.inner_map_fd = inner_fd;
		outer_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "dump_outer",
					  sizeof(key), sizeof(value), 1, &opts);
		if (!ASSERT_OK_FD(outer_fd, "create_outer") ||
		    !ASSERT_OK(bpf_map_update_elem(outer_fd, &key, &inner_fd, BPF_ANY),
			       "populate_outer"))
			goto out;
		root_id = map_id(outer_fd);
		if (!root_id || !dump_map(root_id, "-j", root))
			goto out;
		snprintf(expected, sizeof(expected),
			 "[{\"id\":%u,\"type\":\"array_of_maps\",\"name\":\"dump_outer\","
			 "\"flags\":0,\"elements\":%s},{\"id\":%u,"
			 "\"type\":\"perf_event_array\",\"name\":\"dump_unreadable\","
			 "\"flags\":0,\"elements\":%s}]", root_id, root, inner_id, elements);
	} else {
		snprintf(expected, sizeof(expected),
			 "[{\"id\":%u,\"type\":\"perf_event_array\","
			 "\"name\":\"dump_unreadable\",\"flags\":0,\"elements\":%s}]",
			 inner_id, elements);
	}
	if (dump_map(root_id, "-j -r", output))
		ASSERT_STREQ(output, expected, "recursive_unreadable_json");
	memset(output, 0, sizeof(output));
	snprintf(command, sizeof(command), "-r map dump id %u", root_id);
	if (ASSERT_OK(get_bpftool_command_output(command, output, sizeof(output) - 1),
		      "recursive_unreadable_plain")) {
		ASSERT_HAS_SUBSTR(output, plain, "recursive_plain_preserves_errors");
		ASSERT_EQ(count_token(output, strerror(lookup_errno)), 2,
			  "recursive_plain_errors");
		ASSERT_EQ(count_token(output, "Found "), outer ? 2 : 1,
			  "recursive_plain_maps");
	}
out:
	if (outer_fd >= 0)
		close(outer_fd);
	if (inner_fd >= 0)
		close(inner_fd);
}

static void test_many_inner_maps(bool json)
{
	enum {
		DUMP_OK,
		DUMP_ERR_RLIMIT,
		DUMP_ERR_COMMAND,
		DUMP_ERR_COUNTS,
		DUMP_ERR_IDS,
		DUMP_ERR_JSON,
		DUMP_ERR_FDS,
	};
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	const struct rlimit limit = { .rlim_cur = 32, .rlim_max = 32 };
	char command[MAX_BPFTOOL_CMD_LEN], token[64];
	__u32 ids[64], root_id, key;
	int inner_fd = -1, outer_fd = -1, status;
	int inherited_fds[32], nr_inherited = 0, i;
	char *output = NULL;
	pid_t pid;

	inner_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "dump_inner", 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(inner_fd, "create_template"))
		goto out;
	opts.inner_map_fd = inner_fd;
	outer_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "dump_outer", 4, 4,
				  ARRAY_SIZE(ids), &opts);
	close(inner_fd);
	inner_fd = -1;
	if (!ASSERT_OK_FD(outer_fd, "create_outer"))
		goto out;
	for (key = 0; key < ARRAY_SIZE(ids); key++) {
		inner_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "dump_inner", 4, 4, 1, NULL);
		if (!ASSERT_OK_FD(inner_fd, "create_inner") ||
		    !ASSERT_OK(bpf_map_update_elem(outer_fd, &key, &inner_fd, BPF_ANY),
			       "populate_outer"))
			goto out;
		ids[key] = map_id(inner_fd);
		if (!ids[key])
			goto out;
		/* The outer map keeps each distinct inner map alive. */
		close(inner_fd);
		inner_fd = -1;
	}
	root_id = map_id(outer_fd);
	output = calloc(1, MANY_MAPS_OUTPUT_SIZE);
	if (!root_id || !ASSERT_OK_PTR(output, "allocate_output"))
		goto out;

	/* Fill the low FD slots to exercise inherited descriptor cleanup. */
	for (i = 0; i < ARRAY_SIZE(inherited_fds); i++) {
		int fd = open("/dev/null", O_RDONLY);

		if (!ASSERT_OK_FD(fd, "open_inherited_fd"))
			goto out;
		inherited_fds[nr_inherited++] = fd;
	}

	/*
	 * Create all fixtures before lowering the limit, and keep the test
	 * runner's limit unchanged. Retaining every discovered FD would exceed
	 * this limit before the recursive dump could visit all inner maps.
	 */
	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		goto out;
	if (!pid) {
		struct dirent *entry;
		DIR *dir;

		/* Reserve a slot for the directory even if the parent is full. */
		close(inherited_fds[nr_inherited - 1]);
		dir = opendir("/proc/self/fd");
		if (!dir)
			_exit(DUMP_ERR_FDS);
		/* The parent keeps the outer map and its inner maps alive. */
		for (;;) {
			char *end;
			long fd;

			errno = 0;
			entry = readdir(dir);
			if (!entry) {
				if (errno)
					_exit(DUMP_ERR_FDS);
				break;
			}
			fd = strtol(entry->d_name, &end, 10);
			if (*end || fd < 3 || fd == dirfd(dir))
				continue;
			close(fd);
		}
		if (closedir(dir))
			_exit(DUMP_ERR_FDS);
		if (setrlimit(RLIMIT_NOFILE, &limit))
			_exit(DUMP_ERR_RLIMIT);
		snprintf(command, sizeof(command), "%s -r map dump id %u",
			 json ? "-j" : "", root_id);
		if (get_bpftool_command_output(command, output, MANY_MAPS_OUTPUT_SIZE - 1))
			_exit(DUMP_ERR_COMMAND);
		if (count_token(output, json ? "\"id\":" : "Found ") != ARRAY_SIZE(ids) + 1 ||
		    count_token(output, json ? "\"inner_map_id\":" : "inner_map_id:") !=
		    ARRAY_SIZE(ids))
			_exit(DUMP_ERR_COUNTS);
		for (key = 0; key < ARRAY_SIZE(ids); key++) {
			if (json)
				snprintf(token, sizeof(token), "\"id\":%u,", ids[key]);
			else
				snprintf(token, sizeof(token), "\n%u: hash  name dump_inner  ",
					 ids[key]);
			if (count_token(output, token) != 1)
				_exit(DUMP_ERR_IDS);
		}
		if (json && (output[0] != '[' ||
			     strcmp(output + strlen(output) - 2, "]\n")))
			_exit(DUMP_ERR_JSON);
		_exit(DUMP_OK);
	}
	if (ASSERT_EQ(waitpid(pid, &status, 0), pid, "waitpid") &&
	    ASSERT_TRUE(WIFEXITED(status), "child_exited"))
		ASSERT_EQ(WEXITSTATUS(status), DUMP_OK, "dump_with_low_fd_limit");
	for (i = 0; i < nr_inherited; i++)
		ASSERT_GE(fcntl(inherited_fds[i], F_GETFD), 0, "parent_fd_preserved");
	ASSERT_EQ(map_id(outer_fd), root_id, "parent_outer_preserved");
out:
	while (nr_inherited)
		close(inherited_fds[--nr_inherited]);
	free(output);
	if (outer_fd >= 0)
		close(outer_fd);
	if (inner_fd >= 0)
		close(inner_fd);
}

void test_bpftool_map_dump(void)
{
	if (test__start_subtest("unreadable_ordinary"))
		test_unreadable(false);
	if (test__start_subtest("unreadable_inner"))
		test_unreadable(true);
	if (test__start_subtest("many_inner_maps_json"))
		test_many_inner_maps(true);
	if (test__start_subtest("many_inner_maps_plain"))
		test_many_inner_maps(false);
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
