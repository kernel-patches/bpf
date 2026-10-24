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
	 * original bool on/off meaning;
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

	/* changing the load strategy leaves autoattach alone */
	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_AUTO);
	if (!ASSERT_OK(err, "set_load_strategy_auto"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_strategy(skel->progs.prog3), BPF_PROG_LOAD_STRATEGY_AUTO,
		       "prog3_load_strategy_auto"))
		goto cleanup;

	if (!ASSERT_TRUE(bpf_program__autoattach(skel->progs.prog3), "prog3_autoattach_default"))
		goto cleanup;

	bpf_program__set_autoattach(skel->progs.prog3, false);

	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_MANUAL);
	if (!ASSERT_OK(err, "set_load_strategy_manual_again"))
		goto cleanup;

	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_AUTO);
	if (!ASSERT_OK(err, "set_load_strategy_auto_again"))
		goto cleanup;

	if (!ASSERT_FALSE(bpf_program__autoattach(skel->progs.prog3), "prog3_autoattach_kept"))
		goto cleanup;

	/* restore autoattach to true for the rest of the test */
	bpf_program__set_autoattach(skel->progs.prog3, true);

	/* an out-of-range load strategy is rejected */
	err = bpf_program__set_load_strategy(skel->progs.prog3, (enum bpf_prog_load_strategy)999);
	if (!ASSERT_EQ(err, -EINVAL, "set_load_strategy_invalid"))
		goto cleanup;

	/* change the strategy back to BPF_PROG_LOAD_STRATEGY_MANUAL for the rest of the test */
	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_MANUAL);
	if (!ASSERT_OK(err, "set_load_strategy_manual_final"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_strategy(skel->progs.prog3), BPF_PROG_LOAD_STRATEGY_MANUAL,
		       "prog3_load_strategy_final"))
		goto cleanup;

	/* Test post loaded behaviors */
	err = test_load_type__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	/* Post load we cannot update a program's strategy */
	err = bpf_program__set_load_strategy(skel->progs.prog3, BPF_PROG_LOAD_STRATEGY_DISABLED);
	ASSERT_EQ(err, -EINVAL, "set_load_strategy_after_load");

	err = test_load_type__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	usleep(1);

	/* Post load only AUTOLOAD program is expected to run */
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

	/* Post explicit load and attach, MANUAL program is also expected to run */
	if (!ASSERT_TRUE(skel->bss->prog3_called, "prog3_called_again"))
		goto cleanup;

	/*
	 * detach prog3 explicitly: its link is kept in a local variable, not in
	 * skel->links, so test_load_type__destroy() has nothing to detach
	 */
	err = bpf_link__destroy(link);
	ASSERT_OK(err, "link_destroy");
	link = NULL;

cleanup:
	if (link)
		bpf_link__destroy(link);
	test_load_type__destroy(skel);
}
