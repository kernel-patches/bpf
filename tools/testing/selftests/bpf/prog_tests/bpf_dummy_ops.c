// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021. Huawei Technologies Co., Ltd */
#include <linux/err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <test_progs.h>

#include "bpf_dummy_ops.skel.h"

#define OPS_CTL_CMD_SIZE 64

static void do_ctl(const char *cmd)
{
	int duration = 0;
	int fd;
	size_t len;
	ssize_t wr;

	fd = open("/sys/kernel/bpf_test/dummy_ops_ctl", O_WRONLY);
	if (CHECK(fd < 0, "open", "open errno %d", errno))
		goto out;

	len = strlen(cmd);
	wr = write(fd, cmd, len);
	if (CHECK(wr != len, "write", "write cmd %s errno %d", cmd, errno))
		goto out;
out:
	if (fd >= 0)
		close(fd);
}

static void test_ret_value(void)
{
	int duration = 0;
	struct bpf_dummy_ops *skel;
	struct bpf_link *link;
	char cmd[OPS_CTL_CMD_SIZE];

	skel = bpf_dummy_ops__open_and_load();
	if (CHECK(!skel, "bpf_dummy_ops__open_and_load", "failed\n"))
		return;

	skel->bss->init_ret = 1024;
	link = bpf_map__attach_struct_ops(skel->maps.dummy);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto out;

	snprintf(cmd, sizeof(cmd), "init_1 %d", skel->bss->init_ret);
	do_ctl(cmd);
out:
	bpf_link__destroy(link);
	bpf_dummy_ops__destroy(skel);
}

static void test_ret_by_ptr(void)
{
	int duration = 0;
	struct bpf_dummy_ops *skel;
	struct bpf_link *link;
	char cmd[OPS_CTL_CMD_SIZE];

	skel = bpf_dummy_ops__open_and_load();
	if (CHECK(!skel, "bpf_dummy_ops__open_and_load", "failed\n"))
		return;

	skel->bss->state_val = 0x5a;
	link = bpf_map__attach_struct_ops(skel->maps.dummy);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto out;

	snprintf(cmd, sizeof(cmd), "init_2 %d", skel->bss->state_val);
	do_ctl(cmd);
out:
	bpf_link__destroy(link);
	bpf_dummy_ops__destroy(skel);
}

void test_bpf_dummy_ops(void)
{
	if (!env.has_testmod) {
		test__skip();
		return;
	}

	if (test__start_subtest("ret_value"))
		test_ret_value();
	if (test__start_subtest("ret_by_ptr"))
		test_ret_by_ptr();
}
