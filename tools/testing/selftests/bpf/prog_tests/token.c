// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#include "linux/bpf.h"
#include <test_progs.h>
#include <bpf/btf.h>
#include "cap_helpers.h"
#include <linux/filter.h>

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

	/* check that any current and future cmd can be specified */
	opts.allowed_cmds = ~0ULL;
	token_fd = bpf_token_create(&opts);
	if (!ASSERT_GT(token_fd, 0, "token_create_future_proof"))
		return;
	close(token_fd);

	/* create BPF token which allows creating derived BPF tokens */
	opts.allowed_cmds = 1ULL << BPF_TOKEN_CREATE;
	token_fd = bpf_token_create(&opts);
	if (!ASSERT_GT(token_fd, 0, "token_create"))
		return;

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

static void subtest_map_token(void)
{
	LIBBPF_OPTS(bpf_token_create_opts, token_opts);
	LIBBPF_OPTS(bpf_map_create_opts, map_opts);
	int token_fd = 0, map_fd = 0;
	__u64 old_caps = 0;

	/* check that it's ok to allow any map type */
	token_opts.allowed_map_types = ~0ULL; /* any current and future map types is allowed */
	token_fd = bpf_token_create(&token_opts);
	if (!ASSERT_GT(token_fd, 0, "token_create_future_proof"))
		return;
	close(token_fd);

	/* create BPF token allowing STACK, but not QUEUE map */
	token_opts.allowed_cmds = 1ULL << BPF_MAP_CREATE;
	token_opts.allowed_map_types = 1ULL << BPF_MAP_TYPE_STACK; /* but not QUEUE */
	token_fd = bpf_token_create(&token_opts);
	if (!ASSERT_GT(token_fd, 0, "token_create"))
		return;

	/* drop privileges to test token_fd passing */
	if (!ASSERT_OK(drop_priv_caps(&old_caps), "drop_caps"))
		goto cleanup;

	/* BPF_MAP_TYPE_STACK is privileged, but with given token_fd should succeed */
	map_opts.token_fd = token_fd;
	map_fd = bpf_map_create(BPF_MAP_TYPE_STACK, "token_stack", 0, 8, 1, &map_opts);
	if (!ASSERT_GT(map_fd, 0, "stack_map_fd"))
		goto cleanup;
	close(map_fd);
	map_fd = 0;

	/* BPF_MAP_TYPE_QUEUE is privileged, and token doesn't allow it, so should fail */
	map_opts.token_fd = token_fd;
	map_fd = bpf_map_create(BPF_MAP_TYPE_QUEUE, "token_queue", 0, 8, 1, &map_opts);
	if (!ASSERT_EQ(map_fd, -EPERM, "queue_map_fd"))
		goto cleanup;

cleanup:
	if (map_fd > 0)
		close(map_fd);
	if (token_fd)
		close(token_fd);
	if (old_caps)
		ASSERT_OK(restore_priv_caps(old_caps), "restore_caps");
}

static void subtest_btf_token(void)
{
	LIBBPF_OPTS(bpf_token_create_opts, token_opts);
	LIBBPF_OPTS(bpf_btf_load_opts, btf_opts);
	int token_fd = 0, btf_fd = 0;
	const void *raw_btf_data;
	struct btf *btf = NULL;
	__u32 raw_btf_size;
	__u64 old_caps = 0;

	/* create BPF token allowing BPF_BTF_LOAD command */
	token_opts.allowed_cmds = 1ULL << BPF_BTF_LOAD;
	token_fd = bpf_token_create(&token_opts);
	if (!ASSERT_GT(token_fd, 0, "token_create"))
		return;

	/* drop privileges to test token_fd passing */
	if (!ASSERT_OK(drop_priv_caps(&old_caps), "drop_caps"))
		goto cleanup;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "empty_btf"))
		goto cleanup;

	ASSERT_GT(btf__add_int(btf, "int", 4, 0), 0, "int_type");

	raw_btf_data = btf__raw_data(btf, &raw_btf_size);
	if (!ASSERT_OK_PTR(raw_btf_data, "raw_btf_data"))
		goto cleanup;

	/* validate we can successfully load new BTF with token */
	btf_opts.token_fd = token_fd;
	btf_fd = bpf_btf_load(raw_btf_data, raw_btf_size, &btf_opts);
	if (!ASSERT_GT(btf_fd, 0, "btf_fd"))
		goto cleanup;
	close(btf_fd);

	/* now validate that we *cannot* load BTF without token */
	btf_opts.token_fd = 0;
	btf_fd = bpf_btf_load(raw_btf_data, raw_btf_size, &btf_opts);
	if (!ASSERT_EQ(btf_fd, -EPERM, "btf_fd_eperm"))
		goto cleanup;

cleanup:
	btf__free(btf);
	if (btf_fd > 0)
		close(btf_fd);
	if (token_fd)
		close(token_fd);
	if (old_caps)
		ASSERT_OK(restore_priv_caps(old_caps), "restore_caps");
}

static void subtest_prog_token(void)
{
	LIBBPF_OPTS(bpf_token_create_opts, token_opts);
	LIBBPF_OPTS(bpf_prog_load_opts, prog_opts);
	int token_fd = 0, prog_fd = 0;
	__u64 old_caps = 0;
	struct bpf_insn insns[] = {
		/* bpf_jiffies64() requires CAP_BPF */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		/* bpf_get_current_task() requires CAP_PERFMON */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_current_task),
		/* r0 = 0; exit; */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	size_t insn_cnt = ARRAY_SIZE(insns);

	/* create BPF token allowing BPF_PROG_LOAD command */
	token_opts.flags = 0;
	token_opts.allowed_cmds = 1ULL << BPF_PROG_LOAD;
	token_opts.allowed_prog_types = 1ULL << BPF_PROG_TYPE_XDP;
	token_opts.allowed_attach_types = 1ULL << BPF_XDP;
	token_fd = bpf_token_create(&token_opts);
	if (!ASSERT_GT(token_fd, 0, "token_create"))
		return;

	/* drop privileges to test token_fd passing */
	if (!ASSERT_OK(drop_priv_caps(&old_caps), "drop_caps"))
		goto cleanup;

	/* validate we can successfully load BPF program with token; this
	 * being XDP program (CAP_NET_ADMIN) using bpf_jiffies64() (CAP_BPF)
	 * and bpf_get_current_task() (CAP_PERFMON) helpers validates we have
	 * BPF token wired properly in a bunch of places in the kernel
	 */
	prog_opts.token_fd = token_fd;
	prog_opts.expected_attach_type = BPF_XDP;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "token_prog", "GPL",
				insns, insn_cnt, &prog_opts);
	if (!ASSERT_GT(prog_fd, 0, "prog_fd"))
		goto cleanup;
	close(prog_fd);

	/* now validate that we *cannot* load BPF program without token */
	prog_opts.token_fd = 0;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "token_prog", "GPL",
				insns, insn_cnt, &prog_opts);
	if (!ASSERT_EQ(prog_fd, -EPERM, "prog_fd_eperm"))
		goto cleanup;

cleanup:
	if (prog_fd > 0)
		close(prog_fd);
	if (token_fd)
		close(token_fd);
	if (old_caps)
		ASSERT_OK(restore_priv_caps(old_caps), "restore_caps");
}

void test_token(void)
{
	if (test__start_subtest("token_create"))
		subtest_token_create();
	if (test__start_subtest("map_token"))
		subtest_map_token();
	if (test__start_subtest("btf_token"))
		subtest_btf_token();
	if (test__start_subtest("prog_token"))
		subtest_prog_token();
}
