// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include <linux/keyctl.h>
#include <test_progs.h>

#include "test_lookup_user_key.skel.h"

#define LOG_BUF_SIZE 16384

#define KEY_LOOKUP_CREATE	0x01
#define KEY_LOOKUP_PARTIAL	0x02

void test_lookup_user_key(void)
{
	char *buf = NULL;
	struct test_lookup_user_key *skel = NULL;
	u32 next_id;
	int ret;

	LIBBPF_OPTS(bpf_object_open_opts, opts);

	buf = malloc(LOG_BUF_SIZE);
	if (!ASSERT_OK_PTR(buf, "malloc"))
		goto close_prog;

	opts.kernel_log_buf = buf;
	opts.kernel_log_size = LOG_BUF_SIZE;
	opts.kernel_log_level = 1;

	skel = test_lookup_user_key__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "test_lookup_user_key__open_opts"))
		goto close_prog;

	ret = test_lookup_user_key__load(skel);

	if (ret < 0 && strstr(buf, "unknown func bpf_lookup_user_key")) {
		printf("%s:SKIP:bpf_lookup_user_key() helper not supported\n",
		       __func__);
		test__skip();
		goto close_prog;
	}

	if (!ASSERT_OK(ret, "test_lookup_user_key__load"))
		goto close_prog;

	ret = test_lookup_user_key__attach(skel);
	if (!ASSERT_OK(ret, "test_lookup_user_key__attach"))
		goto close_prog;

	skel->bss->monitored_pid = getpid();
	skel->bss->key_serial = KEY_SPEC_THREAD_KEYRING;

	/* The thread-specific keyring does not exist, this test fails. */
	skel->bss->flags = 0;

	ret = bpf_prog_get_next_id(0, &next_id);
	if (!ASSERT_LT(ret, 0, "bpf_prog_get_next_id"))
		goto close_prog;

	/* Force creation of the thread-specific keyring, this test succeeds. */
	skel->bss->flags = KEY_LOOKUP_CREATE;

	ret = bpf_prog_get_next_id(0, &next_id);
	if (!ASSERT_OK(ret, "bpf_prog_get_next_id"))
		goto close_prog;

	/* Pass both lookup flags for parameter validation. */
	skel->bss->flags = KEY_LOOKUP_CREATE | KEY_LOOKUP_PARTIAL;

	ret = bpf_prog_get_next_id(0, &next_id);
	if (!ASSERT_OK(ret, "bpf_prog_get_next_id"))
		goto close_prog;

	/* Pass invalid flags. */
	skel->bss->flags = UINT64_MAX;

	ret = bpf_prog_get_next_id(0, &next_id);
	ASSERT_LT(ret, 0, "bpf_prog_get_next_id");

close_prog:
	free(buf);

	if (!skel)
		return;

	skel->bss->monitored_pid = 0;
	test_lookup_user_key__destroy(skel);
}
