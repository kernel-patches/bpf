// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "verifier_unwind.skel.h"
#include "unwind_attach.skel.h"

/*
 * A trampoline that calls the subprog and an extension that replaces it don't
 * keep r3, so only fentry can attach to a subprog that can unwind.
 */
static void attach(int tgt_fd, const char *name, bool ok)
{
	struct unwind_attach *skel;
	struct bpf_program *prog;
	int err;

	skel = unwind_attach__open();
	if (!ASSERT_OK_PTR(skel, "unwind_attach__open"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, name);
	if (!ASSERT_OK_PTR(prog, name))
		goto out;
	bpf_program__set_autoload(prog, true);
	err = bpf_program__set_attach_target(prog, tgt_fd, "global_unwinds");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = unwind_attach__load(skel);
	if (ok)
		ASSERT_OK(err, name);
	else
		ASSERT_ERR(err, name);
out:
	unwind_attach__destroy(skel);
}

void test_unwind_attach(void)
{
#if defined(__x86_64__) || defined(__aarch64__)
	struct verifier_unwind *tgt;
	struct bpf_program *prog;
	int tgt_fd;

	if (!is_jit_enabled()) {
		test__skip();
		return;
	}

	tgt = verifier_unwind__open();
	if (!ASSERT_OK_PTR(tgt, "verifier_unwind__open"))
		return;
	bpf_object__for_each_program(prog, tgt->obj)
		bpf_program__set_autoload(prog, prog == tgt->progs.calls_global_unwinds);
	if (!ASSERT_OK(verifier_unwind__load(tgt), "verifier_unwind__load"))
		goto out;
	tgt_fd = bpf_program__fd(tgt->progs.calls_global_unwinds);

	attach(tgt_fd, "fentry_unwind", true);
	attach(tgt_fd, "fexit_unwind", false);
	attach(tgt_fd, "fmod_ret_unwind", false);
	attach(tgt_fd, "freplace_unwind", false);
out:
	verifier_unwind__destroy(tgt);
#else
	test__skip();
#endif
}
