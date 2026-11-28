// SPDX-License-Identifier: GPL-2.0-only
#include <bpftool_helpers.h>
#include <test_progs.h>

#define MAX_BPFTOOL_OUTPUT_LEN	(64 * 1024)

static char output[MAX_BPFTOOL_OUTPUT_LEN];

static void test_lskel_non_autoload(void)
{
	char cmd[MAX_BPFTOOL_CMD_LEN];
	int ret;

	ret = snprintf(cmd, sizeof(cmd),
		       "gen skeleton -L test_global_percpu_data_failure.bpf.o 2>&1");
	if (!ASSERT_GT(ret, 0, "format cmd"))
		return;

	ret = get_bpftool_command_output(cmd, output, sizeof(output));
	ASSERT_NEQ(ret, 0, "gen skeleton -L non-autoload should fail");
	ASSERT_HAS_SUBSTR(output,
			  "is marked as non-autoload, which is not supported for light skeletons",
			  "error message");
}

void test_bpftool_gen(void)
{
	if (test__start_subtest("lskel_non_autoload"))
		test_lskel_non_autoload();
}
