// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <testing_helpers.h>
#include "arena_fault.skel.h"
#include "arena_fault_noarena.skel.h"

#define ARENA_FAULT_MOD "bpf_test_arena_fault"

static int run_syscall_prog(struct bpf_program *prog, const char *name)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, name))
		return -1;
	if (!ASSERT_OK(opts.retval, name))
		return -1;
	return 0;
}

static void test_wrong_arena(void)
{
	struct arena_fault *fault_skel = NULL;
	struct arena_fault *stash_skel = NULL;

	stash_skel = arena_fault__open_and_load();
	if (!ASSERT_OK_PTR(stash_skel, "open_load_stash"))
		return;

	fault_skel = arena_fault__open_and_load();
	if (!ASSERT_OK_PTR(fault_skel, "open_load_fault"))
		goto out;

	if (run_syscall_prog(stash_skel->progs.stash_and_free, "stash_and_free"))
		goto out;
	run_syscall_prog(fault_skel->progs.fault_stashed_wrong_arena,
			 "fault_stashed_wrong_arena");

out:
	if (stash_skel)
		run_syscall_prog(stash_skel->progs.clear_stashed, "clear_stashed");
	arena_fault__destroy(fault_skel);
	arena_fault__destroy(stash_skel);
}

static void test_no_arena(void)
{
	struct arena_fault_noarena *fault_skel = NULL;
	struct arena_fault *stash_skel = NULL;

	stash_skel = arena_fault__open_and_load();
	if (!ASSERT_OK_PTR(stash_skel, "open_load_stash"))
		return;

	fault_skel = arena_fault_noarena__open_and_load();
	if (!ASSERT_OK_PTR(fault_skel, "open_load_noarena"))
		goto out;

	if (run_syscall_prog(stash_skel->progs.stash_and_free, "stash_and_free"))
		goto out;
	run_syscall_prog(fault_skel->progs.fault_stashed_noarena,
			 "fault_stashed_noarena");

out:
	if (stash_skel)
		run_syscall_prog(stash_skel->progs.clear_stashed, "clear_stashed");
	arena_fault_noarena__destroy(fault_skel);
	arena_fault__destroy(stash_skel);
}

void serial_test_arena_fault(void)
{
#if !defined(__x86_64__) && !defined(__aarch64__)
	test__skip();
	return;
#endif

	if (!ASSERT_OK(load_module(ARENA_FAULT_MOD ".ko",
				   env_verbosity > VERBOSE_NONE),
		       "load " ARENA_FAULT_MOD ".ko"))
		return;

	if (test__start_subtest("wrong_arena"))
		test_wrong_arena();
	if (test__start_subtest("no_arena"))
		test_no_arena();

	unload_module(ARENA_FAULT_MOD, env_verbosity > VERBOSE_NONE);
}
