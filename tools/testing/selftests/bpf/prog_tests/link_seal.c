// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 David Windsor */
#include <test_progs.h>
#include "test_link_seal.skel.h"

/* Drop the self-reference held by a sealed link, via a bpf_testmod kfunc, so
 * the link can be freed once its last fd goes away. Without this every run of
 * this test would leak a link and its program until the machine reboots.
 */
static int force_unseal(struct test_link_seal *skel, int link_fd)
{
	struct { int link_fd; } args = { .link_fd = link_fd };
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.unseal_link),
				     &opts);
	if (err)
		return err;
	return opts.retval;
}

/* An unsealed link is still updatable and detachable. */
static void test_unsealed_link(struct test_link_seal *skel)
{
	int link_fd, err;

	link_fd = bpf_link_create(bpf_program__fd(skel->progs.dump_task), 0,
				  BPF_TRACE_ITER, NULL);
	if (!ASSERT_GE(link_fd, 0, "create"))
		return;

	err = bpf_link_update(link_fd, bpf_program__fd(skel->progs.dump_task_alt),
			      NULL);
	ASSERT_OK(err, "update");
	close(link_fd);
}

/* A sealed link rejects update and detach, and survives its last fd. */
static void test_sealed_link(struct test_link_seal *skel)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = BPF_F_LINK_SEALED);
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);
	int link_fd, fd, err, i;
	__u32 id;

	link_fd = bpf_link_create(bpf_program__fd(skel->progs.dump_task), 0,
				  BPF_TRACE_ITER, &opts);
	if (!ASSERT_GE(link_fd, 0, "create_sealed"))
		return;

	err = bpf_link_update(link_fd, bpf_program__fd(skel->progs.dump_task_alt),
			      NULL);
	ASSERT_EQ(err, -EPERM, "update_rejected");

	err = bpf_link_detach(link_fd);
	ASSERT_EQ(err, -EPERM, "detach_rejected");

	err = bpf_link_get_info_by_fd(link_fd, &info, &len);
	if (!ASSERT_OK(err, "get_info"))
		goto cleanup;
	id = info.id;

	/* closing the last fd must not tear the link down */
	close(link_fd);
	link_fd = -1;

	fd = bpf_link_get_fd_by_id(id);
	if (!ASSERT_GE(fd, 0, "alive_after_close"))
		return;

	err = bpf_link_detach(fd);
	ASSERT_EQ(err, -EPERM, "detach_rejected_after_close");

	link_fd = fd;
cleanup:
	if (link_fd < 0)
		return;

	err = force_unseal(skel, link_fd);
	if (!ASSERT_OK(err, "force_unseal")) {
		close(link_fd);
		return;
	}

	memset(&info, 0, sizeof(info));
	len = sizeof(info);
	err = bpf_link_get_info_by_fd(link_fd, &info, &len);
	if (ASSERT_OK(err, "get_info_after_unseal"))
		id = info.id;
	close(link_fd);

	/* the link is freed from a workqueue, so poll for it to disappear */
	for (i = 0; i < 100; i++) {
		fd = bpf_link_get_fd_by_id(id);
		if (fd < 0)
			break;
		close(fd);
		usleep(10000);
	}
	ASSERT_EQ(fd, -ENOENT, "freed_after_unseal");
}

/* Link types that cannot honour BPF_F_LINK_SEALED must reject it rather than
 * quietly handing back an unsealed link.
 */
static void test_seal_unsupported(struct test_link_seal *skel)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = BPF_F_LINK_SEALED);
	const char *syms[1] = { "bpf_fentry_test1" };
	int link_fd;

	opts.kprobe_multi.syms = syms;
	opts.kprobe_multi.cnt = 1;

	link_fd = bpf_link_create(bpf_program__fd(skel->progs.kprobe_multi_prog),
				  0, BPF_TRACE_KPROBE_MULTI, &opts);
	if (!ASSERT_LT(link_fd, 0, "kprobe_multi_seal_rejected")) {
		close(link_fd);
		return;
	}
	/* the central check in link_create() rejects the flag before
	 * kprobe_multi ever sees it
	 */
	ASSERT_EQ(link_fd, -EOPNOTSUPP, "kprobe_multi_seal_err");
}

void test_link_seal(void)
{
	struct test_link_seal *skel;

	skel = test_link_seal__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (test__start_subtest("unsealed"))
		test_unsealed_link(skel);
	if (test__start_subtest("sealed"))
		test_sealed_link(skel);
	if (test__start_subtest("unsupported"))
		test_seal_unsupported(skel);

	test_link_seal__destroy(skel);
}
