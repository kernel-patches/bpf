// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <time.h>
#include "kfunc_call_test.skel.h"
#include "test_manual_load.skel.h"

#define READ_SZ 256

/*
 * prog4 is marked SEC("!...") in the source instead of being set
 * imperatively; verify that an explicit bpf_program__set_load_strategy() call
 * before load overrides the declarative default.
 */
static void manual_load_verify_override(void)
{
	struct test_manual_load *skel;
	int err;

	skel = test_manual_load__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	err = bpf_program__set_load_strategy(skel->progs.prog4, BPF_PROG_LOAD_STRATEGY_DISABLED);
	if (!ASSERT_OK(err, "set_load_strategy_disabled"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_strategy(skel->progs.prog4),
		       BPF_PROG_LOAD_STRATEGY_DISABLED, "prog4_load_strategy_overridden"))
		goto cleanup;

	err = test_manual_load__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	/*
	 * prog4 was overridden to DISABLED, so its load_strategy != MANUAL
	 * and load() must reject it
	 */
	if (!ASSERT_EQ(bpf_program__fd(skel->progs.prog4), -ENOENT, "prog4_not_loaded"))
		goto cleanup;

	err = bpf_program__load(skel->progs.prog4);
	ASSERT_EQ(err, -EINVAL, "load_after_override");

cleanup:
	test_manual_load__destroy(skel);
}

/*
 * prog4 is MANUAL via its SEC("!...") marker; verify that
 * bpf_object__prepare() alone -- without ever calling bpf_object__load() --
 * is sufficient for bpf_program__load() to succeed, since BTF
 * loading, map creation, and relocation of MANUAL programs are all
 * completed by prepare() already.
 */
static void manual_load_verify_prepare_only(void)
{
	struct test_manual_load *skel;
	struct bpf_link *link = NULL;
	int err;

	skel = test_manual_load__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	skel->bss->test_pid = getpid();

	err = bpf_object__prepare(skel->obj);
	if (!ASSERT_OK(err, "bpf_object__prepare"))
		goto cleanup;

	err = bpf_program__load(skel->progs.prog4);
	if (!ASSERT_OK(err, "load_after_prepare"))
		goto cleanup;

	if (!ASSERT_GE(bpf_program__fd(skel->progs.prog4), 0, "prog4_fd_after_prepare"))
		goto cleanup;

	link = bpf_program__attach(skel->progs.prog4);
	if (!ASSERT_OK_PTR(link, "attach_after_prepare"))
		goto cleanup;

	usleep(1);

	if (!ASSERT_TRUE(skel->bss->prog4_called, "prog4_called_after_prepare"))
		goto cleanup;

	err = bpf_link__destroy(link);
	link = NULL;
	if (!ASSERT_OK(err, "link_destroy_after_prepare"))
		goto cleanup;

	bpf_program__unload(skel->progs.prog4);
	ASSERT_LT(bpf_program__fd(skel->progs.prog4), 0, "prog4_fd_closed_after_unload");

cleanup:
	if (link)
		bpf_link__destroy(link);
	test_manual_load__destroy(skel);
}

/*
 * prog5 is disabled at parse time; resolve its attach target against
 * module BTF via bpf_program__set_attach_target() before switching it
 * to MANUAL and deferring its load past the bulk bpf_object__load().
 * Regression test for the module BTF fd/array lifetime.
 */
static void manual_load_verify_module_btf(void)
{
	struct test_manual_load *skel;
	struct bpf_link *link;
	int err;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	skel = test_manual_load__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	skel->bss->test_pid = getpid();

	err = bpf_program__set_attach_target(skel->progs.prog5, 0,
					     "bpf_testmod:bpf_testmod_test_read");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto cleanup;

	err = bpf_program__set_load_strategy(skel->progs.prog5, BPF_PROG_LOAD_STRATEGY_MANUAL);
	if (!ASSERT_OK(err, "set_load_strategy_manual"))
		goto cleanup;

	/* keep the other autoload programs out of the way of this load */
	bpf_program__set_load_strategy(skel->progs.prog1, BPF_PROG_LOAD_STRATEGY_DISABLED);
	bpf_program__set_load_strategy(skel->progs.prog2, BPF_PROG_LOAD_STRATEGY_DISABLED);
	bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_DISABLED);

	/*
	 * bulk load: prog5 itself is skipped (MANUAL), but this is where
	 * module BTF gets torn down if not correctly deferred
	 */
	err = test_manual_load__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	/*
	 * deferred load must still succeed: the module BTF fd cached above
	 * by set_attach_target() must still be a valid, open fd here
	 */
	err = bpf_program__load(skel->progs.prog5);
	if (!ASSERT_OK(err, "load_module_btf"))
		goto cleanup;

	link = bpf_program__attach(skel->progs.prog5);
	if (!ASSERT_OK_PTR(link, "attach"))
		goto cleanup;

	ASSERT_OK(trigger_module_test_read(READ_SZ), "trigger_read");
	ASSERT_EQ(skel->bss->prog5_sz, READ_SZ, "prog5_sz");

	bpf_link__destroy(link);

cleanup:
	test_manual_load__destroy(skel);
}

static void manual_load_verify_main_cycle(void)
{
	struct bpf_link *link = NULL;
	struct test_manual_load *skel;
	int err;

	skel = test_manual_load__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	skel->bss->test_pid = getpid();

	/*
	 * the SEC("!...") prefix alone, with no imperative call, must set
	 * prog4's load strategy before it is ever touched below
	 */
	if (!ASSERT_EQ(bpf_program__load_strategy(skel->progs.prog4),
		       BPF_PROG_LOAD_STRATEGY_MANUAL, "prog4_prefix_load_strategy"))
		goto cleanup;

	/* don't load prog1 */
	bpf_program__set_load_strategy(skel->progs.prog1, BPF_PROG_LOAD_STRATEGY_DISABLED);

	/* prog2 is autoload */
	bpf_program__set_load_strategy(skel->progs.prog2, BPF_PROG_LOAD_STRATEGY_AUTO);

	/* prog3 is manually loaded */
	bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_MANUAL);

	err = test_manual_load__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	err = test_manual_load__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	/* trigger the BPF programs */
	usleep(1);

	ASSERT_FALSE(skel->bss->prog1_called, "prog1_called");
	ASSERT_TRUE(skel->bss->prog2_called, "prog2_called");
	ASSERT_FALSE(skel->bss->prog3_called, "prog3_called");
	ASSERT_FALSE(skel->bss->prog4_called, "prog4_called");

	/* prog1 is disabled for load */
	if (!ASSERT_EQ(bpf_program__fd(skel->progs.prog1), -ENOENT, "prog1_not_loaded"))
		goto cleanup;

	err = bpf_program__load(skel->progs.prog1);
	if (!ASSERT_EQ(err, -EINVAL, "load_disabled"))
		goto cleanup;

	/* prog2 is autoload */
	err = bpf_program__load(skel->progs.prog2);
	if (!ASSERT_EQ(err, -EINVAL, "load_autoload"))
		goto cleanup;

	/*
	 * bpf_program__unload() no longer rejects based on load strategy:
	 * calling it on prog2 (AUTO, currently loaded and attached) performs
	 * a full, irreversible unload instead of returning an error
	 */
	bpf_program__unload(skel->progs.prog2);
	ASSERT_LT(bpf_program__fd(skel->progs.prog2), 0, "prog2_fd_closed_after_unload");

	/* load prog3 */
	err = bpf_program__load(skel->progs.prog3);
	if (!ASSERT_OK(err, "load"))
		goto cleanup;

	/* attach prog3 */
	link = bpf_program__attach(skel->progs.prog3);
	if (!ASSERT_OK_PTR(link, "attach"))
		goto cleanup;

	usleep(1);

	if (!ASSERT_TRUE(skel->bss->prog3_called, "prog3_called"))
		goto cleanup;

	/*
	 * detach prog3 explicitly: its link is kept in a local variable, not in
	 * skel->links, so test_manual_load__destroy() has nothing to detach
	 */
	err = bpf_link__destroy(link);
	link = NULL;
	if (!ASSERT_OK(err, "link_destroy"))
		goto cleanup;

	/* reset the call flag after detach */
	skel->bss->prog3_called = false;

	usleep(1);

	ASSERT_FALSE(skel->bss->prog3_called, "prog3_called");

	/* unload prog3; MANUAL strategy means its data is retained for reload */
	bpf_program__unload(skel->progs.prog3);

	/* reload prog3 */
	err = bpf_program__load(skel->progs.prog3);
	if (!ASSERT_OK(err, "load_reload"))
		goto cleanup;

	/* reattach prog3 */
	link = bpf_program__attach(skel->progs.prog3);
	if (!ASSERT_OK_PTR(link, "reattach"))
		goto cleanup;

	usleep(1);

	if (!ASSERT_TRUE(skel->bss->prog3_called, "prog3_called_reattach"))
		goto cleanup;

	err = bpf_link__destroy(link);
	link = NULL;
	if (!ASSERT_OK(err, "link_destroy_reattach"))
		goto cleanup;

	/* reset the call flag after detach */
	skel->bss->prog3_called = false;

	usleep(1);

	ASSERT_FALSE(skel->bss->prog3_called, "prog3_called");

	/*
	 * run prog4 (declaratively marked) through the same manual
	 * load/attach/trigger/detach/unload cycle as prog3
	 */
	err = bpf_program__load(skel->progs.prog4);
	if (!ASSERT_OK(err, "prog4_load"))
		goto cleanup;

	link = bpf_program__attach(skel->progs.prog4);
	if (!ASSERT_OK_PTR(link, "prog4_attach"))
		goto cleanup;

	usleep(1);

	if (!ASSERT_TRUE(skel->bss->prog4_called, "prog4_called"))
		goto cleanup;

	err = bpf_link__destroy(link);
	link = NULL;
	if (!ASSERT_OK(err, "prog4_link_destroy"))
		goto cleanup;

	bpf_program__unload(skel->progs.prog4);

	test_manual_load__destroy(skel);
	return;

cleanup:
	if (link)
		bpf_link__destroy(link);
	test_manual_load__destroy(skel);
}

/*
 * A MANUAL program that calls a kfunc of a module: the module BTF fd sits in
 * a slot of the fd_array of the object, which has to survive the bulk
 * bpf_object__load() for the deferred bpf_program__load() to work.
 */
static void manual_load_verify_module_kfunc(void)
{
	struct bpf_program *prog, *p;
	struct kfunc_call_test *skel;
	int err;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	skel = kfunc_call_test__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	prog = skel->progs.kfunc_call_test1;
	err = bpf_program__set_load_strategy(prog, BPF_PROG_LOAD_STRATEGY_MANUAL);
	if (!ASSERT_OK(err, "set_load_strategy"))
		goto out;

	/* keep the other programs out of the way of this load */
	bpf_object__for_each_program(p, skel->obj) {
		if (p != prog)
			bpf_program__set_load_strategy(p, BPF_PROG_LOAD_STRATEGY_DISABLED);
	}

	/* the bulk load skips the program, but this is where the fd_array could go */
	err = kfunc_call_test__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto out;
	if (!ASSERT_LT(bpf_program__fd(prog), 0, "not_loaded"))
		goto out;

	err = bpf_program__load(prog);
	if (ASSERT_OK(err, "load")) {
		ASSERT_GE(bpf_program__fd(prog), 0, "prog_fd");
		bpf_program__unload(prog);
		ASSERT_LT(bpf_program__fd(prog), 0, "unloaded");
	}
out:
	kfunc_call_test__destroy(skel);
}

void test_manual_load(void)
{
	if (test__start_subtest("main_cycle"))
		manual_load_verify_main_cycle();

	if (test__start_subtest("verify_override"))
		manual_load_verify_override();

	if (test__start_subtest("verify_prepare_only"))
		manual_load_verify_prepare_only();

	if (test__start_subtest("verify_module_btf"))
		manual_load_verify_module_btf();

	if (test__start_subtest("verify_module_kfunc"))
		manual_load_verify_module_kfunc();
}
