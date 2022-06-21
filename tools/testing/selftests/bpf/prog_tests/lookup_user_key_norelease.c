// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include <test_progs.h>

#include "test_lookup_user_key_norelease.skel.h"

#define LOG_BUF_SIZE 16384

void test_lookup_user_key_norelease(void)
{
	char *buf = NULL, *result;
	struct test_lookup_user_key_norelease *skel = NULL;
	int ret;

	LIBBPF_OPTS(bpf_object_open_opts, opts);

	buf = malloc(LOG_BUF_SIZE);
	if (!ASSERT_OK_PTR(buf, "malloc"))
		goto close_prog;

	opts.kernel_log_buf = buf;
	opts.kernel_log_size = LOG_BUF_SIZE;
	opts.kernel_log_level = 1;

	skel = test_lookup_user_key_norelease__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "test_lookup_user_key_norelease__open_opts"))
		goto close_prog;

	ret = test_lookup_user_key_norelease__load(skel);
	if (!ASSERT_LT(ret, 0, "test_lookup_user_key_norelease__load\n"))
		goto close_prog;

	if (strstr(buf, "unknown func bpf_lookup_user_key")) {
		printf("%s:SKIP:bpf_lookup_user_key() helper not supported\n",
		       __func__);
		test__skip();
		goto close_prog;
	}

	result = strstr(buf, "Unreleased reference");
	ASSERT_OK_PTR(result, "Error message not found");

close_prog:
	free(buf);
	test_lookup_user_key_norelease__destroy(skel);
}
