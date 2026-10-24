// SPDX-License-Identifier: GPL-2.0
#include <bpftool_helpers.h>
#include <test_progs.h>
#include <linux/bpf.h>
#include "bpftool_cfg.skel.h"

#define MAX_BPFTOOL_OUTPUT_LEN (64 * 1024)

void test_bpftool_cfg(void)
{
	struct bpftool_cfg *skel = NULL;
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	char output[MAX_BPFTOOL_OUTPUT_LEN];
	char cmd[MAX_BPFTOOL_CMD_LEN];
	const char *expected = "return\\ bpf_ktime_get_ns()\\ ?\\ skb->len\\ :\\ 0;";
	int err;

	skel = bpftool_cfg__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpftool_cfg__open_and_load"))
		return;

	err = bpf_obj_get_info_by_fd(bpf_program__fd(skel->progs.bpftool_cfg),
				     &info, &info_len);
	if (!ASSERT_OK(err, "bpf_obj_get_info_by_fd"))
		goto cleanup;

	err = snprintf(cmd, sizeof(cmd), "prog dump xlated id %u visual linum",
		       info.id);
	if (!ASSERT_GT(err, 0, "format bpftool command"))
		goto cleanup;

	err = get_bpftool_command_output(cmd, output, sizeof(output));
	if (ASSERT_OK(err, "dump program CFG")) {
		ASSERT_HAS_SUBSTR(output, "cluster_1", "second function in CFG");
		ASSERT_HAS_SUBSTR(output, expected, "second function line info");
	}

cleanup:
	bpftool_cfg__destroy(skel);
}
