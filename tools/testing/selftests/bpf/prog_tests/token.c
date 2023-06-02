// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#include "linux/bpf.h"
#include <test_progs.h>
#include <bpf/btf.h>
#include "cap_helpers.h"

static int drop_priv_caps(__u64 *old_caps)
{
	return cap_disable_effective((1ULL << CAP_BPF) |
				     (1ULL << CAP_PERFMON) |
				     (1ULL << CAP_NET_ADMIN) |
				     (1ULL << CAP_SYS_ADMIN), old_caps);
}

static int restore_priv_caps(__u64 old_caps)
{
	return cap_enable_effective(old_caps, NULL);
}

#define TOKEN_PATH "/sys/fs/bpf/test_token"

static void subtest_token_create(void)
{
	LIBBPF_OPTS(bpf_token_create_opts, opts);
	int token_fd = 0, limited_token_fd = 0, tmp_fd = 0, err;
	__u64 old_caps = 0;

	/* create BPF token which allows creating derived BPF tokens */
	opts.allowed_cmds = 1ULL << BPF_TOKEN_CREATE;
	token_fd = bpf_token_create(&opts);
	if (!ASSERT_GT(token_fd, 0, "token_create"))
		return;

	/* check that IGNORE_UNKNOWN_CMDS flag is respected */
	opts.flags = BPF_F_TOKEN_IGNORE_UNKNOWN_CMDS;
	opts.allowed_cmds = ~0ULL; /* any current and future cmd is allowed */
	tmp_fd = bpf_token_create(&opts);
	if (!ASSERT_GT(token_fd, 0, "token_create_future_proof"))
		return;
	close(tmp_fd);
	tmp_fd = 0;

	/* validate pinning and getting works as expected */
	err = bpf_obj_pin(token_fd, TOKEN_PATH);
	if (!ASSERT_OK(err, "token_pin"))
		goto cleanup;

	tmp_fd = bpf_obj_get(TOKEN_PATH);
	ASSERT_GT(tmp_fd, 0, "token_get");
	close(tmp_fd);
	tmp_fd = 0;
	unlink(TOKEN_PATH);

	/* drop privileges to test token_fd passing */
	if (!ASSERT_OK(drop_priv_caps(&old_caps), "drop_caps"))
		goto cleanup;

	/* unprivileged BPF_TOKEN_CREATE should fail */
	tmp_fd = bpf_token_create(NULL);
	if (!ASSERT_LT(tmp_fd, 0, "token_create_unpriv_fail"))
		goto cleanup;

	/* unprivileged BPF_TOKEN_CREATE with associated BPF token succeeds */
	opts.flags = 0;
	opts.allowed_cmds = 0; /* ask for BPF token which doesn't allow new tokens */
	opts.token_fd = token_fd;
	limited_token_fd = bpf_token_create(&opts);
	if (!ASSERT_GT(limited_token_fd, 0, "token_create_limited"))
		goto cleanup;

	/* creating yet another token using "limited" BPF token should fail */
	opts.flags = 0;
	opts.allowed_cmds = 0;
	opts.token_fd = limited_token_fd;
	tmp_fd = bpf_token_create(&opts);
	if (!ASSERT_LT(tmp_fd, 0, "token_create_from_lim_fail"))
		goto cleanup;

cleanup:
	if (tmp_fd)
		close(tmp_fd);
	if (token_fd)
		close(token_fd);
	if (limited_token_fd)
		close(limited_token_fd);
	if (old_caps)
		ASSERT_OK(restore_priv_caps(old_caps), "restore_caps");
}

void test_token(void)
{
	if (test__start_subtest("token_create"))
		subtest_token_create();
}
