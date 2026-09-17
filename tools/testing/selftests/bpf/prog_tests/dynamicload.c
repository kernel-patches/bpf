// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <time.h>
#include "test_dynamicload.skel.h"

#define READ_SZ 456

/*
 * prog4 is marked SEC("!...") in the source instead of being set
 * imperatively; verify that an explicit bpf_program__set_load_strategy() call
 * before load overrides the declarative default.
 */
static void dynamicload_verify_override(void)
{
	struct test_dynamicload *skel;
	int err;

	skel = test_dynamicload__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	err = bpf_program__set_load_strategy(skel->progs.prog4, BPF_PROG_LOAD_STRATEGY_DISABLED);
	if (!ASSERT_OK(err, "set_load_strategy_disabled"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_strategy(skel->progs.prog4),
		       BPF_PROG_LOAD_STRATEGY_DISABLED, "prog4_load_strategy_overridden"))
		goto cleanup;

	/* keep the other autoload programs out of the way of this load */
	bpf_program__set_load_strategy(skel->progs.prog1, BPF_PROG_LOAD_STRATEGY_DISABLED);
	bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_DISABLED);

	err = test_dynamicload__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	/* prog4 was never loaded, so it cannot be loaded manually either */
	err = bpf_program__load_manually(skel->progs.prog4);
	ASSERT_ERR(err, "load_manually_after_override");

cleanup:
	test_dynamicload__destroy(skel);
}

/*
 * prog4 is MANUAL via its SEC("!...") marker; verify that
 * bpf_object__prepare() alone -- without ever calling bpf_object__load() --
 * is sufficient for bpf_program__load_manually() to succeed, since BTF
 * loading, map creation, and relocation of MANUAL programs are all
 * completed by prepare() already.
 */
static void dynamicload_verify_prepare_only(void)
{
	struct test_dynamicload *skel;
	struct bpf_link *link;
	int err;

	skel = test_dynamicload__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	err = bpf_object__prepare(skel->obj);
	if (!ASSERT_OK(err, "bpf_object__prepare"))
		goto cleanup;

	err = bpf_program__load_manually(skel->progs.prog4);
	if (!ASSERT_OK(err, "load_manually_after_prepare"))
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
	if (!ASSERT_OK(err, "link_destroy_after_prepare"))
		goto cleanup;

	err = bpf_program__unload_manually(skel->progs.prog4);
	ASSERT_OK(err, "unload_manually_after_prepare");

cleanup:
	test_dynamicload__destroy(skel);
}

/*
 * prog5 is disabled at parse time; resolve its attach target against
 * module BTF via bpf_program__set_attach_target() before switching it
 * to MANUAL and deferring its load past the bulk bpf_object__load().
 * Regression test for the module BTF fd/array lifetime bug: without
 * deferring the module BTF fd/array close for MANUAL programs, the fd
 * cached in prog->attach_btf_obj_fd is closed by the bulk load's
 * cleanup before this deferred load runs, causing a deterministic
 * -EINVAL.
 */
static void dynamicload_verify_module_btf(void)
{
	struct test_dynamicload *skel;
	struct bpf_link *link;
	int err;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	skel = test_dynamicload__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

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
	err = test_dynamicload__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	/*
	 * deferred load must still succeed: the module BTF fd cached above
	 * by set_attach_target() must still be a valid, open fd here
	 */
	err = bpf_program__load_manually(skel->progs.prog5);
	if (!ASSERT_OK(err, "load_manually_module_btf"))
		goto cleanup;

	link = bpf_program__attach(skel->progs.prog5);
	if (!ASSERT_OK_PTR(link, "attach"))
		goto cleanup;

	ASSERT_OK(trigger_module_test_read(READ_SZ), "trigger_read");
	ASSERT_EQ(skel->bss->prog5_sz, READ_SZ, "prog5_sz");

	bpf_link__destroy(link);

cleanup:
	test_dynamicload__destroy(skel);
}

void test_dynamicload(void)
{
	struct bpf_link *link;
	struct test_dynamicload *skel;
	int err;

	skel = test_dynamicload__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	/*
	 * the SEC("!...") prefix alone, with no imperative call, must set
	 * prog4's load strategy before it is ever touched below
	 */
	if (!ASSERT_EQ(bpf_program__load_strategy(skel->progs.prog4),
		       BPF_PROG_LOAD_STRATEGY_MANUAL, "prog4_prefix_load_strategy"))
		goto cleanup;
	if (!ASSERT_FALSE(bpf_program__autoattach(skel->progs.prog4), "prog4_autoattach"))
		goto cleanup;

	/* don't load prog1 */
	bpf_program__set_load_strategy(skel->progs.prog1, BPF_PROG_LOAD_STRATEGY_DISABLED);

	/* prog2 is autoload */
	bpf_program__set_load_strategy(skel->progs.prog2, BPF_PROG_LOAD_STRATEGY_AUTO);

	/* prog3 is manually loaded */
	bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_MANUAL);

	err = test_dynamicload__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	err = test_dynamicload__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	/* trigger the BPF programs */
	usleep(1);

	ASSERT_FALSE(skel->bss->prog1_called, "prog1_called");
	ASSERT_TRUE(skel->bss->prog2_called, "prog2_called");
	ASSERT_FALSE(skel->bss->prog3_called, "prog3_called");
	ASSERT_FALSE(skel->bss->prog4_called, "prog4_called");

	/* prog1 is disabled for load */
	err = bpf_program__load_manually(skel->progs.prog1);
	if (!ASSERT_ERR(err, "load_manually_disabled"))
		goto cleanup;

	/* prog1 is disabled for load */
	err = bpf_program__unload_manually(skel->progs.prog1);
	if (!ASSERT_ERR(err, "unload_manually_disabled"))
		goto cleanup;

	/* prog2 is autoload */
	err = bpf_program__load_manually(skel->progs.prog2);
	if (!ASSERT_ERR(err, "load_manually_autoload"))
		goto cleanup;

	/* prog2 is autoload */
	err = bpf_program__unload_manually(skel->progs.prog2);
	if (!ASSERT_ERR(err, "unload_manually_autoload"))
		goto cleanup;

	/* reset the call flags */
	skel->bss->prog2_called = false;
	skel->bss->prog3_called = false;

	usleep(1);

	ASSERT_FALSE(skel->bss->prog1_called, "prog1_called");
	ASSERT_TRUE(skel->bss->prog2_called, "prog2_called");
	ASSERT_FALSE(skel->bss->prog3_called, "prog3_called");

	/* load prog3 */
	err = bpf_program__load_manually(skel->progs.prog3);
	if (!ASSERT_OK(err, "load_manually"))
		goto cleanup;

	/* attach prog3 */
	link = bpf_program__attach(skel->progs.prog3);
	if (!ASSERT_OK_PTR(link, "attach"))
		goto cleanup;

	usleep(1);

	if (!ASSERT_TRUE(skel->bss->prog3_called, "prog3_called"))
		goto cleanup;

	/* detach prog3 as test_dynamicload__destroy doesn't detach manually loaded programs */
	err = bpf_link__destroy(link);
	if (!ASSERT_OK(err, "link_destroy"))
		goto cleanup;

	/* reset the call flags after detach */
	skel->bss->prog2_called = false;
	skel->bss->prog3_called = false;

	usleep(1);

	ASSERT_TRUE(skel->bss->prog2_called, "prog2_called");
	ASSERT_FALSE(skel->bss->prog3_called, "prog3_called");

	/* unload prog3 */
	err = bpf_program__unload_manually(skel->progs.prog3);
	if (!ASSERT_OK(err, "unload_manually"))
		goto cleanup;

	/* reload prog3 */
	err = bpf_program__load_manually(skel->progs.prog3);
	if (!ASSERT_OK(err, "load_manually_reload"))
		goto cleanup;

	/* reattach prog3 */
	link = bpf_program__attach(skel->progs.prog3);
	if (!ASSERT_OK_PTR(link, "reattach"))
		goto cleanup;

	usleep(1);

	if (!ASSERT_TRUE(skel->bss->prog3_called, "prog3_called_reattach"))
		goto cleanup;

	/* detach prog3 as test_dynamicload__destroy doesn't detach manually loaded programs */
	err = bpf_link__destroy(link);
	if (!ASSERT_OK(err, "link_destroy_reattach"))
		goto cleanup;

	/*
	 * verify regular unload for manually loaded program,
	 * unload prog3 as a regular program
	 */
	bpf_program__unload(skel->progs.prog3);

	/* reset the call flags after unload */
	skel->bss->prog2_called = false;
	skel->bss->prog3_called = false;

	usleep(1);

	ASSERT_TRUE(skel->bss->prog2_called, "prog2_called");
	ASSERT_FALSE(skel->bss->prog3_called, "prog3_called");

	/* reloading prog3 must fail as it was unloaded as a regular program */
	err = bpf_program__load_manually(skel->progs.prog3);
	ASSERT_ERR(err, "load_manually_after_regular_unload");

	/*
	 * run prog4 (declaratively marked) through the same manual
	 * load/attach/trigger/detach/unload cycle as prog3
	 */
	err = bpf_program__load_manually(skel->progs.prog4);
	if (!ASSERT_OK(err, "prog4_load_manually"))
		goto cleanup;

	link = bpf_program__attach(skel->progs.prog4);
	if (!ASSERT_OK_PTR(link, "prog4_attach"))
		goto cleanup;

	usleep(1);

	if (!ASSERT_TRUE(skel->bss->prog4_called, "prog4_called"))
		goto cleanup;

	err = bpf_link__destroy(link);
	if (!ASSERT_OK(err, "prog4_link_destroy"))
		goto cleanup;

	err = bpf_program__unload_manually(skel->progs.prog4);
	ASSERT_OK(err, "prog4_unload_manually");

	test_dynamicload__destroy(skel);

	/* separate scenario: imperative override of the declarative marker */
	dynamicload_verify_override();

	/* separate scenario: prepare()-only is sufficient for manual load */
	dynamicload_verify_prepare_only();

	/* separate scenario: deferred manual load with a module BTF attach target */
	dynamicload_verify_module_btf();
	return;

cleanup:
	test_dynamicload__destroy(skel);
}

