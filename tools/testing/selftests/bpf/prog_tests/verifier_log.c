// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <bpf/btf.h>

#include "test_log_buf.skel.h"

void test_verifier_log(void)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts);
	char full_log[1024], log_buf[1024], *exp_log;
	char prog_name[16], op_name[32];
	struct test_log_buf *skel;
	const struct bpf_insn *insns;
	size_t insn_cnt, fixed_log_sz;
	int i, err, prog_fd;

	skel = test_log_buf__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	bpf_program__set_autoload(skel->progs.bad_prog, false);

	err = test_log_buf__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	insns = bpf_program__insns(skel->progs.good_prog);
	insn_cnt = bpf_program__insn_cnt(skel->progs.good_prog);

	opts.log_buf = full_log;
	opts.log_size = sizeof(full_log);
	opts.log_level = 2 | 8 /* BPF_LOG_FIXED */;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT, "log_fixed",
				"GPL", insns, insn_cnt, &opts);
	if (!ASSERT_GT(prog_fd, 0, "fixed_log_prog_load"))
		goto cleanup;
	close(prog_fd);

	fixed_log_sz = strlen(full_log) + 1;
	if (!ASSERT_GT(fixed_log_sz, 100, "fixed_log_sz"))
		goto cleanup;

	/* validate BPF_LOG_FIXED works as verifier log used to work, that is:
	 * we get -ENOSPC and beginning of the full verifier log
	 */
	opts.log_buf = log_buf;
	opts.log_level = 2 | 8; /* verbose level 2, fixed-length log */
	opts.log_size = 50;

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT, "log_fixed50",
				"GPL", insns, insn_cnt, &opts);
	if (!ASSERT_EQ(prog_fd, -ENOSPC, "unexpected_log_fixed_prog_load_result")) {
		if (prog_fd >= 0)
			close(prog_fd);
		goto cleanup;
	}
	if (!ASSERT_EQ(strlen(log_buf), 49, "log_fixed_50"))
		goto cleanup;
	if (!ASSERT_STRNEQ(log_buf, full_log, 49, op_name))
		goto cleanup;

	/* validate rolling verifier log logic: try all variations of log buf
	 * length to force various truncation scenarios
	 */
	opts.log_buf = log_buf;
	opts.log_level = 2; /* verbose level 2, rolling log */
	for (i = 1; i <= fixed_log_sz; i++) {
		opts.log_size = i;

		snprintf(prog_name, sizeof(prog_name), "log_roll_%d", i);
		prog_fd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT, prog_name,
					"GPL", insns, insn_cnt, &opts);

		snprintf(op_name, sizeof(op_name), "log_roll_prog_load_%d", i);
		if (!ASSERT_GT(prog_fd, 0, op_name))
			goto cleanup;
		close(prog_fd);

		exp_log = full_log + fixed_log_sz - i;
		snprintf(op_name, sizeof(op_name), "log_roll_contents_%d", i);
		if (!ASSERT_STREQ(log_buf, exp_log, op_name))
			goto cleanup;
	}

cleanup:
	test_log_buf__destroy(skel);
}
