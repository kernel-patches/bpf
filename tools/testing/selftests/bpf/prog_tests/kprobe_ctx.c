// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/ptrace.h>
#include "kprobe_ctx.skel.h"

/*
 * x86_64 happens to be one of the architectures that exports the
 * kernel `struct pt_regs` to userspace ABI. For the architectures
 * that don't, users will have to extract `struct pt_regs` from vmlinux
 * BTF in order to use BPF_PROG_TYPE_KPROBE's BPF_PROG_RUN functionality.
 *
 * We choose to only test x86 here to keep the test simple.
 */
void test_kprobe_ctx(void)
{
#ifdef __x86_64__
	struct pt_regs regs = {
		.rdi = 1,
		.rsi = 2,
		.rdx = 3,
		.rcx = 4,
		.r8 = 5,
	};

	LIBBPF_OPTS(bpf_test_run_opts, tattr,
		.ctx_in = &regs,
		.ctx_size_in = sizeof(regs),
	);

	struct kprobe_ctx *skel = NULL;
	int prog_fd;
	int err;

	skel = kprobe_ctx__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	skel->bss->expected_p1 = (void *)1;
	skel->bss->expected_p2 = (void *)2;
	skel->bss->expected_p3 = (void *)3;
	skel->bss->expected_p4 = (void *)4;
	skel->bss->expected_p5 = (void *)5;

	prog_fd = bpf_program__fd(skel->progs.prog);
	err = bpf_prog_test_run_opts(prog_fd, &tattr);
	if (!ASSERT_OK(err, "bpf_prog_test_run"))
		goto cleanup;

	if (!ASSERT_TRUE(skel->bss->ret, "ret"))
		goto cleanup;

	if (!ASSERT_GT(tattr.duration, 0, "duration"))
		goto cleanup;
cleanup:
	kprobe_ctx__destroy(skel);
#endif
}
