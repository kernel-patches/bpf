// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpftool_helpers.h>
#include <test_progs.h>

static const struct map_flags_test {
	const char *name;
	const char *flags;
	__u32 expected_flags;
	const char *error;
} tests[] = {
	{ "zero", "0", 0 },
	{ "decimal", "129", BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG },
	{ "hexadecimal", "0x81", BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG },
	{ "octal", "0201", BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG },
	{ "positive_sign", "+1", BPF_F_NO_PREALLOC },
	{ "single_name", "BPF_F_NO_PREALLOC", BPF_F_NO_PREALLOC },
	{ "combined_names", "BPF_F_NO_PREALLOC,BPF_F_RDONLY_PROG",
	  BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG },
	{ "repeated_name", "BPF_F_NO_PREALLOC,BPF_F_NO_PREALLOC", BPF_F_NO_PREALLOC },
	{ "unknown_name", "BPF_F_NOT_A_MAP_FLAG", 0, "can't parse" },
	{ "other_command_flag", "BPF_F_PATH_FD", 0, "can't parse" },
	{ "update_flag", "BPF_F_LOCK", 0, "can't parse" },
	{ "abbreviated_name", "BPF_F_NO_PRE", 0, "can't parse" },
	{ "lowercase_name", "bpf_f_no_prealloc", 0, "can't parse" },
	{ "empty", "", 0, "can't parse" },
	{ "whitespace", " ", 0, "can't parse" },
	{ "empty_list", ",", 0, "can't parse" },
	{ "leading_comma", ",BPF_F_NO_PREALLOC", 0, "can't parse" },
	{ "trailing_comma", "BPF_F_NO_PREALLOC,", 0, "can't parse" },
	{ "empty_element", "BPF_F_NO_PREALLOC,,BPF_F_RDONLY_PROG", 0, "can't parse" },
	{ "number_then_name", "1,BPF_F_RDONLY_PROG", 0, "can't parse" },
	{ "name_then_number", "BPF_F_NO_PREALLOC,128", 0, "can't parse" },
	{ "numeric_list", "1,128", 0, "can't parse" },
	{ "whitespace_in_list", "BPF_F_NO_PREALLOC, BPF_F_RDONLY_PROG", 0, "can't parse" },
	{ "overflow_u32", "4294967296", 0, "can't parse" },
	{ "overflow_hex", "0x100000000", 0, "can't parse" },
	{ "overflow_u64", "18446744073709551616", 0, "can't parse" },
	{ "negative", "-1", 0, "can't parse" },
	/* Numeric bits unknown to bpftool must still reach the kernel. */
	{ "all_bits", "0xffffffff", 0, "map create failed" },
	/* The kernel validates combinations of known map creation flags. */
	{ "invalid_combination", "BPF_F_RDONLY,BPF_F_WRONLY", 0, "map create failed" },
};

static void test_map_flags(const struct map_flags_test *test, const char *path)
{
	char cmd[MAX_BPFTOOL_CMD_LEN], output[1024] = {};
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	int fd, err;

	/* Let the flags parser handle negative numbers instead of getopt(). */
	err = snprintf(cmd, sizeof(cmd),
		       "-- map create %s type hash key 4 value 4 entries 1 name flags_test flags '%s' 2>&1",
		       path, test->flags);
	if (!ASSERT_GT(err, 0, "format_command") ||
	    !ASSERT_LT(err, sizeof(cmd), "command_length"))
		return;

	err = get_bpftool_command_output(cmd, output, sizeof(output));
	if (test->error) {
		ASSERT_NEQ(err, 0, "reject_flags");
		ASSERT_HAS_SUBSTR(output, test->error, "error_message");
		err = access(path, F_OK);
		ASSERT_EQ(err, -1, "no_pin");
		ASSERT_EQ(errno, ENOENT, "pin_absent");
		goto cleanup;
	}
	if (!ASSERT_OK(err, "create_map"))
		goto cleanup;

	fd = bpf_obj_get(path);
	if (!ASSERT_OK_FD(fd, "open_map"))
		goto cleanup;
	if (ASSERT_OK(bpf_map_get_info_by_fd(fd, &info, &info_len), "map_info"))
		ASSERT_EQ(info.map_flags, test->expected_flags, "map_flags");
	close(fd);
cleanup:
	unlink(path);
}

void test_bpftool_map_flags(void)
{
	char dir[] = "/sys/fs/bpf/bpftool_flags_XXXXXX";
	char path[sizeof(dir) + sizeof("/map")];
	int i;

	if (!ASSERT_OK_PTR(mkdtemp(dir), "create_pin_dir"))
		return;
	snprintf(path, sizeof(path), "%s/map", dir);
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (test__start_subtest(tests[i].name))
			test_map_flags(&tests[i], path);
	}
	ASSERT_OK(rmdir(dir), "remove_pin_dir");
}
