// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <test_progs.h>
#include "syscall.skel.h"

struct args {
	__u64 log_buf;
	__u32 log_size;
	int max_entries;
	int map_fd;
	int prog_fd;
};

void test_syscall(void)
{
	static char verifier_log[8192];
	struct args ctx = {
		.max_entries = 1024,
		.log_buf = (uintptr_t) verifier_log,
		.log_size = sizeof(verifier_log),
	};
	struct bpf_prog_test_run_attr tattr = {
		.ctx_in = &ctx,
		.ctx_size_in = sizeof(ctx),
	};
	struct syscall *skel = NULL;
	__u64 key = 12, value = 0;
	__u32 duration = 0;
	int err;

	skel = syscall__open_and_load();
	if (CHECK(!skel, "skel_load", "syscall skeleton failed\n"))
		goto cleanup;

	tattr.prog_fd = bpf_program__fd(skel->progs.bpf_prog);
	err = bpf_prog_test_run_xattr(&tattr);
	if (CHECK(err || tattr.retval != 1, "test_run sys_bpf",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, tattr.retval, tattr.duration))
		goto cleanup;

	CHECK(ctx.map_fd <= 0, "map_fd", "fd = %d\n", ctx.map_fd);
	CHECK(ctx.prog_fd <= 0, "prog_fd", "fd = %d\n", ctx.prog_fd);
	CHECK(memcmp(verifier_log, "processed", sizeof("processed") - 1) != 0,
	      "verifier_log", "%s\n", verifier_log);

	err = bpf_map_lookup_elem(ctx.map_fd, &key, &value);
	CHECK(err, "map_lookup", "map_lookup failed\n");
	CHECK(value != 34, "invalid_value",
	      "got value %llu expected %u\n", value, 34);
cleanup:
	syscall__destroy(skel);
}
