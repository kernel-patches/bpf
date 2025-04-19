// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <sys/mman.h>

#include "stream.skel.h"
#include "stream_fail.skel.h"

void test_stream_failure(void)
{
	RUN_TESTS(stream_fail);
}

void test_stream_success(void)
{
	RUN_TESTS(stream);
	return;
}

struct {
	int prog_off;
	const char *errstr;
} stream_error_arr[] = {
	{
		offsetof(struct stream, progs.stream_cond_break),
		"ERROR: Timeout detected for may_goto instruction",
	},
	{
		offsetof(struct stream, progs.stream_deadlock),
		"ERROR: AA or ABBA deadlock detected",
	},
};

void test_stream_errors(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct stream *skel;
	int ret, prog_fd;
	char buf[64];

	skel = stream__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stream__open_and_load"))
		return;

	for (int i = 0; i < ARRAY_SIZE(stream_error_arr); i++) {
		struct bpf_program **prog;

		prog = (struct bpf_program **)(((char *)skel) + stream_error_arr[i].prog_off);
		prog_fd = bpf_program__fd(*prog);
		ret = bpf_prog_test_run_opts(prog_fd, &opts);
		ASSERT_OK(ret, "ret");
		ASSERT_OK(opts.retval, "retval");

#if !defined(__x86_64__)
		ASSERT_TRUE(1, "Timed may_goto unsupported, skip.");
		if (i == 0) {
			ret = bpf_prog_stream_read(prog_fd, 2, buf, sizeof(buf));
			ASSERT_EQ(ret, 0, "stream read");
			continue;
		}
#endif

		ret = bpf_prog_stream_read(prog_fd, 2, buf, sizeof(buf));
		ASSERT_EQ(ret, sizeof(buf), "stream read");
		ASSERT_STRNEQ(stream_error_arr[i].errstr, buf, strlen(stream_error_arr[i].errstr),
			      "compare error msg");
	}

	stream__destroy(skel);
}

void test_stream_syscall(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct stream *skel;
	int ret, prog_fd;
	char buf[64];

	skel = stream__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stream__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.stream_syscall);
	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(ret, "ret");
	ASSERT_OK(opts.retval, "retval");

	bpf_prog_stream_read(0, 1, buf, sizeof(buf));
	ret = -errno;
	ASSERT_EQ(ret, -EINVAL, "bad prog_fd");

	bpf_prog_stream_read(prog_fd, 0, buf, sizeof(buf));
	ret = -errno;
	ASSERT_EQ(ret, -ENOENT, "bad stream id");

	bpf_prog_stream_read(prog_fd, 1, NULL, sizeof(buf));
	ret = -errno;
	ASSERT_EQ(ret, -EFAULT, "bad stream buf");

	ret = bpf_prog_stream_read(prog_fd, 1, buf, 2);
	ASSERT_EQ(ret, 2, "bytes");
	ret = bpf_prog_stream_read(prog_fd, 1, buf, 2);
	ASSERT_EQ(ret, 2, "bytes");
	ret = bpf_prog_stream_read(prog_fd, 1, buf, 1);
	ASSERT_EQ(ret, 0, "no bytes stdout");
	ret = bpf_prog_stream_read(prog_fd, 2, buf, 1);
	ASSERT_EQ(ret, 0, "no bytes stderr");

	stream__destroy(skel);
}
