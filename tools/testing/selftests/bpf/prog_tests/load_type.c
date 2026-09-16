// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <time.h>
#include "test_load_type.skel.h"

void test_load_type(void)
{
	struct bpf_link *link = NULL;
	struct test_load_type *skel;
	int err;

	skel = test_load_type__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	/* don't load prog1 */
	err = bpf_program__set_load_strategy(skel->progs.prog1, BPF_PROG_LOAD_STRATEGY_DISABLED);
	if (!ASSERT_OK(err, "set_load_strategy_disabled_prog1"))
		goto cleanup;

	/* load and attach prog2 */
	err = bpf_program__set_load_strategy(skel->progs.prog2, BPF_PROG_LOAD_STRATEGY_AUTO);
	if (!ASSERT_OK(err, "set_load_strategy_auto_prog2"))
		goto cleanup;
	if (!ASSERT_TRUE(bpf_program__autoload(skel->progs.prog2), "prog2_autoload"))
		goto cleanup;

	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_MANUAL);
	if (!ASSERT_OK(err, "set_load_strategy_manual"))
		goto cleanup;
	if (!ASSERT_EQ(bpf_program__load_strategy(skel->progs.prog3), BPF_PROG_LOAD_STRATEGY_MANUAL,
		       "prog3_load_strategy"))
		goto cleanup;

	/*
	 * bpf_program__set_autoload() is a thin forwarder to
	 * set_load_strategy(), restricted to AUTO/DISABLED to preserve its
	 * original bool on/off meaning; it does change the load strategy of
	 * a program that isn't currently BPF_PROG_LOAD_STRATEGY_AUTO.
	 */
	err = bpf_program__set_autoload(skel->progs.prog3, false);
	if (!ASSERT_OK(err, "set_autoload_false"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_strategy(skel->progs.prog3),
		       BPF_PROG_LOAD_STRATEGY_DISABLED, "prog3_load_strategy_after_false"))
		goto cleanup;

	err = bpf_program__set_autoload(skel->progs.prog3, true);
	if (!ASSERT_OK(err, "set_autoload_true"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_strategy(skel->progs.prog3), BPF_PROG_LOAD_STRATEGY_AUTO,
		       "prog3_load_strategy_after_true"))
		goto cleanup;

	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_MANUAL);
	if (!ASSERT_OK(err, "set_load_strategy_manual_enum"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_strategy(skel->progs.prog3), BPF_PROG_LOAD_STRATEGY_MANUAL,
		       "prog3_load_strategy_after_manual_enum"))
		goto cleanup;

	/*
	 * leaving MANUAL for AUTO must restore autoattach (regression test for
	 * the autoattach residue bug: set_load_strategy(MANUAL) clears autoattach, and
	 * nothing used to restore it on exit)
	 */
	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_AUTO);
	if (!ASSERT_OK(err, "set_load_strategy_auto"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_strategy(skel->progs.prog3), BPF_PROG_LOAD_STRATEGY_AUTO,
		       "prog3_load_strategy_auto"))
		goto cleanup;

	if (!ASSERT_TRUE(bpf_program__autoattach(skel->progs.prog3), "prog3_autoattach_restored"))
		goto cleanup;

	/*
	 * confirm the restore also holds across a MANUAL -> DISABLED -> AUTO
	 * round-trip: AUTO and DISABLED share one guard keyed off the source
	 * strategy being MANUAL, so autoattach is already restored at the
	 * MANUAL -> DISABLED step, not by a separate DISABLED -> AUTO one
	 */
	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_MANUAL);
	if (!ASSERT_OK(err, "set_load_strategy_manual_again"))
		goto cleanup;

	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_DISABLED);
	if (!ASSERT_OK(err, "set_load_strategy_disabled"))
		goto cleanup;

	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_AUTO);
	if (!ASSERT_OK(err, "set_load_strategy_auto_via_disabled"))
		goto cleanup;

	if (!ASSERT_TRUE(bpf_program__autoattach(skel->progs.prog3),
			 "prog3_autoattach_restored_via_disabled"))
		goto cleanup;

	/*
	 * discriminate the restore from a hard-coded `true`: force autoattach
	 * to false before entering MANUAL, then confirm AUTO restores it back
	 * to false rather than unconditionally re-enabling it
	 */
	err = bpf_program__set_autoattach(skel->progs.prog3, false);
	if (!ASSERT_OK(err, "set_autoattach_false"))
		goto cleanup;

	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_MANUAL);
	if (!ASSERT_OK(err, "set_load_strategy_manual_for_false_restore"))
		goto cleanup;

	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_AUTO);
	if (!ASSERT_OK(err, "set_load_strategy_auto_for_false_restore"))
		goto cleanup;

	if (!ASSERT_FALSE(bpf_program__autoattach(skel->progs.prog3),
			  "prog3_autoattach_restored_false"))
		goto cleanup;

	/* restore autoattach to true for the rest of the test */
	err = bpf_program__set_autoattach(skel->progs.prog3, true);
	if (!ASSERT_OK(err, "set_autoattach_true_again"))
		goto cleanup;

	/* an out-of-range load strategy is rejected */
	err = bpf_program__set_load_strategy(skel->progs.prog3, (enum bpf_prog_load_strategy)999);
	if (!ASSERT_ERR(err, "set_load_strategy_invalid"))
		goto cleanup;

	/* change the strategy back to BPF_PROG_LOAD_STRATEGY_MANUAL for the rest of the test */
	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_MANUAL);
	if (!ASSERT_OK(err, "set_load_strategy_manual_final"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_strategy(skel->progs.prog3), BPF_PROG_LOAD_STRATEGY_MANUAL,
		       "prog3_load_strategy_final"))
		goto cleanup;

	err = test_load_type__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	if (!ASSERT_TRUE(bpf_program__autoattach(skel->progs.prog2), "prog2_autoattach"))
		goto cleanup;
	if (!ASSERT_FALSE(bpf_program__autoattach(skel->progs.prog3), "prog3_autoattach"))
		goto cleanup;

	/* loaded program strategy cannot be changed */
	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_DISABLED);
	ASSERT_ERR(err, "set_load_strategy_after_load");

	err = test_load_type__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	usleep(1);

	ASSERT_FALSE(skel->bss->prog1_called, "prog1_called");
	ASSERT_TRUE(skel->bss->prog2_called, "prog2_called");
	ASSERT_FALSE(skel->bss->prog3_called, "prog3_called");

	err = bpf_program__load(skel->progs.prog3);
	if (!ASSERT_OK(err, "load_manually"))
		goto cleanup;

	/* attach prog3 */
	link = bpf_program__attach(skel->progs.prog3);
	if (!ASSERT_OK_PTR(link, "attach"))
		goto cleanup;

	usleep(1);

	if (!ASSERT_TRUE(skel->bss->prog3_called, "prog3_called_again"))
		goto cleanup;

	/* detach prog3 as test_load_type__destroy doesn't detach manually loaded programs */
	err = bpf_link__destroy(link);
	ASSERT_OK(err, "link_destroy");
	link = NULL;

cleanup:
	if (link)
		bpf_link__destroy(link);
	test_load_type__destroy(skel);
}
