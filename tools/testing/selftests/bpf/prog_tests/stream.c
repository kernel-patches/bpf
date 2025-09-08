// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <sys/mman.h>
#include <regex.h>

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

int prog_off[] = {
	offsetof(struct stream, progs.stream_arena_read_fault),
	offsetof(struct stream, progs.stream_arena_write_fault),
};

static int match_regex(const char *pattern, const char *string)
{
	int err, rc;
	regex_t re;

	err = regcomp(&re, pattern, REG_EXTENDED | REG_NEWLINE);
	if (err)
		return -1;
	rc = regexec(&re, string, 0, NULL, 0);
	regfree(&re);
	return rc == 0 ? 1 : 0;
}

void test_stream_arena_fault_address(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	LIBBPF_OPTS(bpf_prog_stream_read_opts, ropts);
	struct stream *skel;
	int ret, prog_fd;
	char buf[1024];
	char fault_addr[64];

	skel = stream__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stream__open_and_load"))
		return;

	for (int i = 0; i < ARRAY_SIZE(prog_off); i++) {
		struct bpf_program **prog;

		prog = (struct bpf_program **)(((char *)skel) + prog_off[i]);
		prog_fd = bpf_program__fd(*prog);
		ret = bpf_prog_test_run_opts(prog_fd, &opts);
		ASSERT_OK(ret, "ret");
		ASSERT_OK(opts.retval, "retval");

#if !defined(__x86_64__) && !defined(__aarch64__)
		ASSERT_TRUE(1, "Arena fault reporting unsupported, skip.");
		ret = bpf_prog_stream_read(prog_fd, 2, buf, sizeof(buf), &ropts);
		ASSERT_EQ(ret, 0, "stream read");
		continue;
#endif

		ret = bpf_prog_stream_read(prog_fd, BPF_STREAM_STDERR, buf, sizeof(buf), &ropts);
		ASSERT_GT(ret, 0, "stream read");
		ASSERT_LE(ret, 1023, "len for buf");
		buf[ret] = '\0';

		sprintf(fault_addr, "0x%lx", skel->bss->fault_addr);
		ret = match_regex(fault_addr, buf);

		if (!ASSERT_TRUE(ret == 1, "regex match")) {
			fprintf(stderr, "Output from stream:\n%s\n", buf);
			fprintf(stderr, "Fault Addr: 0x%lx\n", skel->bss->fault_addr);
		}
	}

	stream__destroy(skel);
}

void test_stream_syscall(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	LIBBPF_OPTS(bpf_prog_stream_read_opts, ropts);
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

	ASSERT_LT(bpf_prog_stream_read(0, BPF_STREAM_STDOUT, buf, sizeof(buf), &ropts), 0, "error");
	ret = -errno;
	ASSERT_EQ(ret, -EINVAL, "bad prog_fd");

	ASSERT_LT(bpf_prog_stream_read(prog_fd, 0, buf, sizeof(buf), &ropts), 0, "error");
	ret = -errno;
	ASSERT_EQ(ret, -ENOENT, "bad stream id");

	ASSERT_LT(bpf_prog_stream_read(prog_fd, BPF_STREAM_STDOUT, NULL, sizeof(buf), NULL), 0, "error");
	ret = -errno;
	ASSERT_EQ(ret, -EFAULT, "bad stream buf");

	ret = bpf_prog_stream_read(prog_fd, BPF_STREAM_STDOUT, buf, 2, NULL);
	ASSERT_EQ(ret, 2, "bytes");
	ret = bpf_prog_stream_read(prog_fd, BPF_STREAM_STDOUT, buf, 2, NULL);
	ASSERT_EQ(ret, 1, "bytes");
	ret = bpf_prog_stream_read(prog_fd, BPF_STREAM_STDOUT, buf, 1, &ropts);
	ASSERT_EQ(ret, 0, "no bytes stdout");
	ret = bpf_prog_stream_read(prog_fd, BPF_STREAM_STDERR, buf, 1, &ropts);
	ASSERT_EQ(ret, 0, "no bytes stderr");

	stream__destroy(skel);
}
