// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <sys/stat.h>
#include <test_progs.h>
#include "syscall.skel.h"
#include "syscall_fs.skel.h"

struct args {
	__u64 log_buf;
	__u32 log_size;
	int max_entries;
	int map_fd;
	int prog_fd;
	int btf_fd;
};

static void test_syscall_basic(void)
{
	static char verifier_log[8192];
	struct args ctx = {
		.max_entries = 1024,
		.log_buf = (uintptr_t) verifier_log,
		.log_size = sizeof(verifier_log),
	};
	LIBBPF_OPTS(bpf_test_run_opts, tattr,
		.ctx_in = &ctx,
		.ctx_size_in = sizeof(ctx),
	);
	struct syscall *skel = NULL;
	__u64 key = 12, value = 0;
	int err, prog_fd;

	skel = syscall__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.bpf_prog);
	err = bpf_prog_test_run_opts(prog_fd, &tattr);
	ASSERT_EQ(err, 0, "err");
	ASSERT_EQ(tattr.retval, 1, "retval");
	ASSERT_GT(ctx.map_fd, 0, "ctx.map_fd");
	ASSERT_GT(ctx.prog_fd, 0, "ctx.prog_fd");
	ASSERT_OK(memcmp(verifier_log, "processed", sizeof("processed") - 1),
		  "verifier_log");

	err = bpf_map_lookup_elem(ctx.map_fd, &key, &value);
	ASSERT_EQ(err, 0, "map_lookup");
	ASSERT_EQ(value, 34, "map lookup value");
cleanup:
	syscall__destroy(skel);
	if (ctx.prog_fd > 0)
		close(ctx.prog_fd);
	if (ctx.map_fd > 0)
		close(ctx.map_fd);
	if (ctx.btf_fd > 0)
		close(ctx.btf_fd);
}

static void test_syscall_fs(void)
{
	char tmpl[] = "/sys/fs/bpf/syscall_XXXXXX";
	struct stat statbuf = {};
	static char verifier_log[8192];
	struct args ctx = {
		.log_buf = (uintptr_t) verifier_log,
		.log_size = sizeof(verifier_log),
		.prog_fd = 0,
	};
	LIBBPF_OPTS(bpf_test_run_opts, tattr,
		.ctx_in = &ctx,
		.ctx_size_in = sizeof(ctx),
	);
	struct syscall_fs *skel = NULL;
	int err, mkdir_fd, rmdir_fd;
	char *root, *dir, *path;

	/* prepares test directories */
	system("mount -t bpf bpffs /sys/fs/bpf");
	root = mkdtemp(tmpl);
	chmod(root, 0755);

	/* loads prog */
	skel = syscall_fs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		goto cleanup;

	dir = skel->bss->dirname;
	snprintf(dir, sizeof(skel->bss->dirname), "%s/test", root);
	path = skel->bss->pathname;
	snprintf(path, sizeof(skel->bss->pathname), "%s/prog", dir);

	/* tests mkdir */
	mkdir_fd = bpf_program__fd(skel->progs.mkdir_prog);
	err = bpf_prog_test_run_opts(mkdir_fd, &tattr);
	ASSERT_EQ(err, 0, "mkdir_err");
	ASSERT_EQ(tattr.retval, 0, "mkdir_retval");
	ASSERT_OK(stat(dir, &statbuf), "mkdir_success");
	ASSERT_OK(stat(path, &statbuf), "pin_success");

	/* tests rmdir */
	rmdir_fd = bpf_program__fd(skel->progs.rmdir_prog);
	err = bpf_prog_test_run_opts(rmdir_fd, &tattr);
	ASSERT_EQ(err, 0, "rmdir_err");
	ASSERT_EQ(tattr.retval, 0, "rmdir_retval");
	ASSERT_ERR(stat(path, &statbuf), "unlink_success");
	ASSERT_ERR(stat(dir, &statbuf), "rmdir_success");

cleanup:
	syscall_fs__destroy(skel);
	if (ctx.prog_fd > 0)
		close(ctx.prog_fd);
	rmdir(root);
}

void test_syscall(void) {
	if (test__start_subtest("basic"))
		test_syscall_basic();
	if (test__start_subtest("filesystem"))
		test_syscall_fs();
}
