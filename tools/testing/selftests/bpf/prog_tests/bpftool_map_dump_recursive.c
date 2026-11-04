// SPDX-License-Identifier: GPL-2.0-only
#include <stdarg.h>
#include <test_progs.h>
#include <bpftool_helpers.h>
#include <bpf/btf.h>
#include "bpftool_map_dump_recursive.skel.h"

#define OUTPUT_SIZE 16384

static bool run(char *output, const char *fmt, ...)
{
	char command[MAX_BPFTOOL_CMD_LEN];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(command, sizeof(command), fmt, ap);
	va_end(ap);
	output[0] = '\0';
	return ASSERT_OK(get_bpftool_command_output(command, output, OUTPUT_SIZE),
			 command) &&
	       ASSERT_LT(strlen(output), OUTPUT_SIZE - 1, "output_fits");
}

static bool append(char *buf, size_t *len, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf + *len, OUTPUT_SIZE - *len, fmt, ap);
	va_end(ap);
	if (!ASSERT_GE(n, 0, "format") || !ASSERT_LT(n, OUTPUT_SIZE - *len, "expected_fits"))
		return false;
	*len += n;
	return true;
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

static __u32 map_id(int fd)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);

	if (!ASSERT_OK(bpf_map_get_info_by_fd(fd, &info, &len), "map_info"))
		return 0;
	return info.id;
}

static bool map_info(__u32 id, struct bpf_map_info *info)
{
	__u32 len = sizeof(*info);
	int fd, err;

	memset(info, 0, sizeof(*info));
	fd = bpf_map_get_fd_by_id(id);
	if (!ASSERT_OK_FD(fd, "map_fd"))
		return false;
	err = bpf_map_get_info_by_fd(fd, info, &len);
	close(fd);
	return ASSERT_OK(err, "map_info");
}

/* Expect an "inner_map" member after each "inner_map_id" of a default dump. */
static bool expect_json(const char *dump, __u32 hidden, char *expected)
{
	const char *tag = "\"inner_map_id\":", *p;
	char inner[OUTPUT_SIZE];
	struct bpf_map_info info;
	size_t len = 0;
	char *end;
	__u32 id;

	while ((p = strstr(dump, tag))) {
		id = strtoul(p + strlen(tag), &end, 10);
		if (!append(expected, &len, "%.*s,\"inner_map\":", (int)(end - dump), dump))
			return false;
		dump = end;
		if (id == hidden) {
			if (!append(expected, &len, "{\"error\":\"can't get map by id (%u): %s\"}",
				    id, strerror(ENOENT)))
				return false;
			continue;
		}
		if (!map_info(id, &info) || !run(inner, "-j map dump id %u", id))
			return false;
		inner[strcspn(inner, "\n")] = '\0';
		if (!append(expected, &len,
			    "{\"id\":%u,\"type\":\"%s\",\"name\":\"%s\",\"flags\":%u,\"elements\":%s}",
			    id, libbpf_bpf_map_type_str(info.type), info.name,
			    info.map_flags, inner))
			return false;
	}
	return append(expected, &len, "%s", dump);
}

/* Expect the inner map after each "inner_map_id" line of a default dump. */
static bool expect_plain(const char *dump, __u32 hidden, char *expected)
{
	const char *tag = "inner_map_id: ", *p, *eol;
	char inner[OUTPUT_SIZE];
	struct bpf_map_info info;
	size_t len = 0;
	__u32 id;

	while ((p = strstr(dump, tag))) {
		id = strtoul(p + strlen(tag), NULL, 10);
		eol = strchr(p, '\n');
		if (!ASSERT_OK_PTR(eol, "entry_line") ||
		    !append(expected, &len, "%.*s", (int)(eol + 1 - dump), dump))
			return false;
		dump = eol + 1;
		if (id == hidden)
			continue;
		if (!map_info(id, &info) || !run(inner, "map dump id %u", id) ||
		    !append(expected, &len, "%u: %s  name %s  flags 0x%x\n%s", id,
			    libbpf_bpf_map_type_str(info.type), info.name,
			    info.map_flags, inner))
			return false;
	}
	return append(expected, &len, "%s", dump);
}

static void check_dumps(const char *handle, __u32 hidden, bool plain)
{
	char dump[OUTPUT_SIZE], expected[OUTPUT_SIZE], output[OUTPUT_SIZE];

	if (run(dump, "-j map dump %s", handle) &&
	    expect_json(dump, hidden, expected) &&
	    run(output, "-j map dump %s recursive", handle))
		ASSERT_STREQ(output, expected, "json");
	if (plain && run(dump, "map dump %s", handle) &&
	    expect_plain(dump, hidden, expected) &&
	    run(output, "map dump %s recursive 2>/dev/null", handle))
		ASSERT_STREQ(output, expected, "plain");
}

static int create_inner(const char *name, struct btf **btf, bool populate)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	__u32 key = 0, value = 0x01010101;
	int fd;

	if (btf) {
		*btf = btf__new_empty();
		if (!ASSERT_OK_PTR(*btf, "btf_new") ||
		    !ASSERT_EQ(btf__add_int(*btf, "unsigned int", 4, 0), 1, "btf_int") ||
		    !ASSERT_OK(btf__load_into_kernel(*btf), "btf_load"))
			return -1;
		opts.btf_fd = btf__fd(*btf);
		opts.btf_key_type_id = 1;
		opts.btf_value_type_id = 1;
	}
	fd = bpf_map_create(BPF_MAP_TYPE_HASH, name, sizeof(key), sizeof(value), 1, &opts);
	if (!ASSERT_OK_FD(fd, "create_inner"))
		return -1;
	if (populate && !ASSERT_OK(bpf_map_update_elem(fd, &key, &value, BPF_ANY),
				   "update_inner")) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Entries 0 and 2 share @a, entry 1 refers to @b; arrays leave slot 3 empty. */
static int create_outer(enum bpf_map_type type, const char *name, int a, int b)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .inner_map_fd = a);
	int inner[] = { a, b, a };
	__u32 key;
	int fd;

	fd = bpf_map_create(type, name, sizeof(key), sizeof(__u32), 4, &opts);
	if (!ASSERT_OK_FD(fd, "create_outer"))
		return -1;
	for (key = 0; key < ARRAY_SIZE(inner); key++) {
		if (!ASSERT_OK(bpf_map_update_elem(fd, &key, &inner[key], BPF_ANY),
			       "update_outer")) {
			close(fd);
			return -1;
		}
	}
	return fd;
}

static void test_outer(enum bpf_map_type type, bool typed_inner)
{
	char handle[32], token[64], output[OUTPUT_SIZE];
	int a = -1, b = -1, outer = -1;
	struct btf *btf = NULL;
	__u32 a_id, b_id;

	a = create_inner("rec_a", typed_inner ? &btf : NULL, true);
	b = create_inner("rec_b", NULL, false);
	if (a < 0 || b < 0)
		goto out;
	outer = create_outer(type, "rec_outer", a, b);
	if (outer < 0)
		goto out;
	snprintf(handle, sizeof(handle), "id %u", map_id(outer));
	check_dumps(handle, 0, !typed_inner);
	if (!typed_inner)
		goto out;

	/* Plain output uses BTF for the inner maps that have it. */
	a_id = map_id(a);
	b_id = map_id(b);
	if (!run(output, "map dump %s recursive", handle))
		goto out;
	snprintf(token, sizeof(token), "\"id\": %u,", a_id);
	ASSERT_EQ(count_token(output, token), 2, "btf_inner_dumps");
	ASSERT_EQ(count_token(output, "\"value\": 16843009"), 2, "btf_inner_values");
	snprintf(token, sizeof(token), "%u: hash  name rec_b  flags 0x0\nFound 0 elements\n",
		 b_id);
	ASSERT_EQ(count_token(output, token), 1, "plain_inner_dump");
out:
	if (outer >= 0)
		close(outer);
	if (a >= 0)
		close(a);
	if (b >= 0)
		close(b);
	btf__free(btf);
}

static void test_missing_inner(void)
{
	char handle[32], message[96], output[OUTPUT_SIZE];
	struct bpftool_map_dump_recursive *skel;
	int a = -1, b = -1, outer = -1;
	__u32 hidden;

	skel = bpftool_map_dump_recursive__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;
	if (!ASSERT_OK(bpftool_map_dump_recursive__attach(skel), "skel_attach"))
		goto out;
	a = create_inner("rec_a", NULL, true);
	b = create_inner("rec_b", NULL, true);
	if (a < 0 || b < 0)
		goto out;
	outer = create_outer(BPF_MAP_TYPE_HASH_OF_MAPS, "rec_outer", a, b);
	hidden = map_id(b);
	if (outer < 0 || !hidden)
		goto out;
	snprintf(handle, sizeof(handle), "id %u", map_id(outer));
	skel->bss->hidden_id = hidden;

	/* Only the entry of the missing map has an error; the dump succeeds. */
	check_dumps(handle, hidden, true);
	snprintf(message, sizeof(message), "Error: can't get map by id (%u): %s\n",
		 hidden, strerror(ENOENT));
	if (run(output, "map dump %s recursive 2>&1 >/dev/null", handle))
		ASSERT_STREQ(output, message, "plain_error");
out:
	if (outer >= 0)
		close(outer);
	if (a >= 0)
		close(a);
	if (b >= 0)
		close(b);
	bpftool_map_dump_recursive__destroy(skel);
}

static void test_multiple_roots(void)
{
	int a = -1, b = -1, outer[] = { -1, -1 };
	char name[BPF_OBJ_NAME_LEN], handle[32];
	size_t i;

	snprintf(name, sizeof(name), "rec_root_%u", getpid() % 100000);
	a = create_inner("rec_a", NULL, true);
	b = create_inner("rec_b", NULL, false);
	if (a < 0 || b < 0)
		goto out;
	for (i = 0; i < ARRAY_SIZE(outer); i++) {
		outer[i] = create_outer(BPF_MAP_TYPE_ARRAY_OF_MAPS, name, a, b);
		if (outer[i] < 0)
			goto out;
	}
	snprintf(handle, sizeof(handle), "name %s", name);
	check_dumps(handle, 0, true);
out:
	for (i = 0; i < ARRAY_SIZE(outer); i++)
		if (outer[i] >= 0)
			close(outer[i]);
	if (a >= 0)
		close(a);
	if (b >= 0)
		close(b);
}

/* The keyword has no effect on other maps or on maps of maps without entries. */
static void test_unchanged(void)
{
	char dump[OUTPUT_SIZE], output[OUTPUT_SIZE];
	const char * const options[] = { "", "-j " };
	int fds[] = { -1, -1 };
	size_t i, j;

	fds[0] = create_inner("rec_a", NULL, true);
	if (fds[0] < 0)
		return;
	fds[1] = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "rec_empty", 4, 4, 1,
				&(struct bpf_map_create_opts){
					.sz = sizeof(struct bpf_map_create_opts),
					.inner_map_fd = fds[0],
				});
	if (!ASSERT_OK_FD(fds[1], "create_outer"))
		goto out;
	for (i = 0; i < ARRAY_SIZE(fds); i++) {
		for (j = 0; j < ARRAY_SIZE(options); j++) {
			if (run(dump, "%smap dump id %u", options[j], map_id(fds[i])) &&
			    run(output, "%smap dump id %u recursive", options[j],
				map_id(fds[i])))
				ASSERT_STREQ(output, dump, "unchanged");
		}
	}
out:
	for (i = 0; i < ARRAY_SIZE(fds); i++)
		if (fds[i] >= 0)
			close(fds[i]);
}

static void test_arguments(void)
{
	const char * const invalid[] = { "''", "unknown", "recursive unknown" };
	char command[MAX_BPFTOOL_CMD_LEN], output[OUTPUT_SIZE] = {};
	__u32 id;
	size_t i;
	int fd;

	fd = create_inner("rec_args", NULL, false);
	if (fd < 0)
		return;
	id = map_id(fd);
	for (i = 0; i < ARRAY_SIZE(invalid); i++) {
		snprintf(command, sizeof(command), "map dump id %u %s", id, invalid[i]);
		ASSERT_NEQ(run_bpftool_command(command), 0, invalid[i]);
	}
	snprintf(command, sizeof(command), "map dump id %u rec", id);
	ASSERT_OK(run_bpftool_command(command), "prefix");
	snprintf(command, sizeof(command), "-j map dump recursive id %u", id);
	ASSERT_NEQ(get_bpftool_command_output(command, output, sizeof(output)), 0,
		   "misplaced_recursive");
	ASSERT_HAS_SUBSTR(output, "got: 'recursive'", "misplaced_error");
	close(fd);
}

void test_bpftool_map_dump_recursive(void)
{
	if (test__start_subtest("array_of_maps"))
		test_outer(BPF_MAP_TYPE_ARRAY_OF_MAPS, false);
	if (test__start_subtest("hash_of_maps"))
		test_outer(BPF_MAP_TYPE_HASH_OF_MAPS, false);
	if (test__start_subtest("btf_inner"))
		test_outer(BPF_MAP_TYPE_HASH_OF_MAPS, true);
	if (test__start_subtest("missing_inner"))
		test_missing_inner();
	if (test__start_subtest("multiple_roots"))
		test_multiple_roots();
	if (test__start_subtest("unchanged"))
		test_unchanged();
	if (test__start_subtest("arguments"))
		test_arguments();
}
