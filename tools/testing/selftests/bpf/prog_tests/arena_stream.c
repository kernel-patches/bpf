// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <sys/mman.h>

#include "arena_stream.skel.h"

static void test_address(struct bpf_program *prog, unsigned long *fault_addr_p)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	LIBBPF_OPTS(bpf_prog_stream_read_opts, ropts);
	int ret, prog_fd;
	char fault_addr[64];
	char buf[1024];

	prog_fd = bpf_program__fd(prog);

	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(ret, "ret");
	ASSERT_OK(opts.retval, "retval");

	sprintf(fault_addr, "0x%lx", *fault_addr_p);

	ret = bpf_prog_stream_read(prog_fd, BPF_STREAM_STDERR, buf, sizeof(buf), &ropts);
	ASSERT_GT(ret, 0, "stream read");
	ASSERT_LE(ret, 1023, "len for buf");
	buf[ret] = '\0';

	if (!ASSERT_HAS_SUBSTR(buf, fault_addr, "fault_addr")) {
		fprintf(stderr, "Output from stream:\n%s\n", buf);
		fprintf(stderr, "Fault Addr: %s\n", fault_addr);
	}
}

void test_stream_arena_fault_address(void)
{
	struct arena_stream *skel;

#if !defined(__x86_64__) && !defined(__aarch64__)
	printf("%s:SKIP: arena fault reporting not supported\n", __func__);
	test__skip();
	return;
#endif

	skel = arena_stream__open_and_load();
	if (!ASSERT_OK_PTR(skel, "arena_stream__open_and_load"))
		return;

	if (test__start_subtest("read_fault"))
		test_address(skel->progs.stream_arena_read_fault, &skel->bss->fault_addr);
	if (test__start_subtest("write_fault"))
		test_address(skel->progs.stream_arena_write_fault, &skel->bss->fault_addr);

	arena_stream__destroy(skel);
}
