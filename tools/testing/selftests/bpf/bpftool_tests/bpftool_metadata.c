// SPDX-License-Identifier: GPL-2.0-only
#include <bpftool_helpers.h>
#include <test_bpftool.h>
#include <assert_helpers.h>
#include <linux/bpf.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>

#define BPFFS_DIR	"/sys/fs/bpf/test_metadata"
#define BPFFS_USED	BPFFS_DIR "/used"
#define BPFFS_UNUSED	BPFFS_DIR "/unused"

#define BPF_FILE_USED	"metadata_used.bpf.o"
#define BPF_FILE_UNUSED "metadata_unused.bpf.o"

#define MAX_BPFTOOL_OUTPUT_LEN	(100*1000)

#define MAX_TOKENS_TO_CHECK	3
static char output[MAX_BPFTOOL_OUTPUT_LEN];

struct test_desc {
	char *name;
	char *bpf_prog;
	char *bpffs_path;
	char *expected_output[MAX_TOKENS_TO_CHECK];
	char *expected_output_json[MAX_TOKENS_TO_CHECK];
};

static int setup(struct test_desc *test)
{
	return mkdir(BPFFS_DIR, 0700);
}

static void cleanup(struct test_desc *test)
{
	unlink(test->bpffs_path);
	rmdir(BPFFS_DIR);
}

static int check_metadata(char *buf, char * const *tokens, int count)
{
	int i;

	for (i = 0; i < count && tokens[i]; i++)
		if (!strstr(buf, tokens[i]))
			return 1;

	return 0;
}

static void run_test(struct test_desc *test)
{
	int ret;
	char cmd[MAX_BPFTOOL_CMD_LEN];

	snprintf(cmd, MAX_BPFTOOL_CMD_LEN, "prog load %s %s",
			test->bpf_prog, test->bpffs_path);
	ret = run_bpftool_command(cmd);
	if (!ASSERT_OK(ret, "load program"))
		return;

	/* Check output with default format */
	ret = get_bpftool_command_output("prog show name prog", output,
			MAX_BPFTOOL_OUTPUT_LEN);
	if (ASSERT_OK(ret, "get program info")) {
		ret = check_metadata(output, test->expected_output,
				ARRAY_SIZE(test->expected_output));
		ASSERT_OK(ret, "find metadata");
	}

	/* Check output with json format */
	ret = get_bpftool_command_output("prog -j show name prog", output,
					 MAX_BPFTOOL_OUTPUT_LEN);
	if (ASSERT_OK(ret, "get program info in json")) {
		ret = check_metadata(output, test->expected_output_json,
				ARRAY_SIZE(test->expected_output_json));
		ASSERT_OK(ret, "find metadata in json");
	}

}

struct test_desc tests[] = {
	{
		.name = "metadata_unused",
		.bpf_prog = BPF_FILE_UNUSED,
		.bpffs_path = BPFFS_UNUSED,
		.expected_output = {
			"a = \"foo\"",
			"b = 1"
		},
		.expected_output_json = {
			"\"metadata\":{\"a\":\"foo\",\"b\":1}"
		}
	},
	{
		.name = "metadata_used",
		.bpf_prog = BPF_FILE_USED,
		.bpffs_path = BPFFS_USED,
		.expected_output = {
			"a = \"bar\"",
			"b = 2"
		},
		.expected_output_json = {
			"\"metadata\":{\"a\":\"bar\",\"b\":2}"
		}
	}
};

static const int tests_count = ARRAY_SIZE(tests);

void test_metadata(void)
{
	int i, ret;

	for (i = 0; i < tests_count; i++) {
		test__start_subtest(tests[i].name);
		ret = setup(&tests[i]);
		if (!ASSERT_OK(ret, "setup bpffs pin dir"))
			continue;
		run_test(&tests[i]);
		cleanup(&tests[i]);
	}

}

