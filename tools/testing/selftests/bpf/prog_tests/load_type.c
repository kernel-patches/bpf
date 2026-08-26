// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <time.h>
#include "test_load_type.skel.h"

void test_load_type(void)
{
	struct bpf_link *link;
	struct test_load_type *skel;
	int err;

	skel = test_load_type__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	/* don't load prog1 */
	bpf_program__set_load_type(skel->progs.prog1, BPF_PROG_LOAD_TYPE_DISABLED);

	/* load and attach prog2 */
	bpf_program__set_load_type(skel->progs.prog2, BPF_PROG_LOAD_TYPE_AUTO);
	if (!ASSERT_TRUE(bpf_program__autoload(skel->progs.prog2), "prog2_autoload"))
		goto cleanup;

	err = bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DYNAMIC);
	if (!ASSERT_OK(err, "set_load_type_dynamic"))
		goto cleanup;
	if (!ASSERT_EQ(bpf_program__load_type(skel->progs.prog3), BPF_PROG_LOAD_TYPE_DYNAMIC,
		       "prog3_load_type"))
		goto cleanup;

	/* bpf_program__set_autoload() is a thin forwarder to set_load_type(),
	 * restricted to AUTO/DISABLED to preserve its original bool on/off
	 * meaning; it does change the load type of a program that isn't
	 * currently BPF_PROG_LOAD_TYPE_AUTO.
	 */
	err = bpf_program__set_autoload(skel->progs.prog3, false);
	if (!ASSERT_OK(err, "set_autoload_false"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_type(skel->progs.prog3), BPF_PROG_LOAD_TYPE_DISABLED,
		       "prog3_load_type_after_false"))
		goto cleanup;

	err = bpf_program__set_autoload(skel->progs.prog3, true);
	if (!ASSERT_OK(err, "set_autoload_true"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_type(skel->progs.prog3), BPF_PROG_LOAD_TYPE_AUTO,
		       "prog3_load_type_after_true"))
		goto cleanup;

	/* set_autoload() only accepts AUTO/DISABLED, to preserve its original
	 * on/off meaning; DYNAMIC must go through set_load_type()
	 */
	err = bpf_program__set_autoload(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DYNAMIC);
	if (!ASSERT_ERR(err, "set_autoload_dynamic_rejected"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_type(skel->progs.prog3), BPF_PROG_LOAD_TYPE_AUTO,
		       "prog3_load_type_unchanged_after_rejected_autoload"))
		goto cleanup;

	err = bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DYNAMIC);
	if (!ASSERT_OK(err, "set_load_type_dynamic_enum"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_type(skel->progs.prog3), BPF_PROG_LOAD_TYPE_DYNAMIC,
		       "prog3_load_type_after_dynamic_enum"))
		goto cleanup;

	/* leaving DYNAMIC for AUTO must restore autoattach (regression test for
	 * the autoattach residue bug: set_dynamicload() clears autoattach, and
	 * nothing used to restore it on exit)
	 */
	err = bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_AUTO);
	if (!ASSERT_OK(err, "set_load_type_auto"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_type(skel->progs.prog3), BPF_PROG_LOAD_TYPE_AUTO,
		       "prog3_load_type_auto"))
		goto cleanup;

	if (!ASSERT_TRUE(bpf_program__autoattach(skel->progs.prog3), "prog3_autoattach_restored"))
		goto cleanup;

	/* the same residue can relay through DISABLED and resurface on a later
	 * DISABLED -> AUTO transition, so the fix must cover both exit edges
	 */
	err = bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DYNAMIC);
	if (!ASSERT_OK(err, "set_load_type_dynamic_again"))
		goto cleanup;

	err = bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DISABLED);
	if (!ASSERT_OK(err, "set_load_type_disabled"))
		goto cleanup;

	err = bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_AUTO);
	if (!ASSERT_OK(err, "set_load_type_auto_via_disabled"))
		goto cleanup;

	if (!ASSERT_TRUE(bpf_program__autoattach(skel->progs.prog3),
			 "prog3_autoattach_restored_via_disabled"))
		goto cleanup;

	/* an out-of-range load type is rejected */
	err = bpf_program__set_load_type(skel->progs.prog3, (enum bpf_prog_load_type)999);
	if (!ASSERT_ERR(err, "set_load_type_invalid"))
		goto cleanup;

	/* change the type back to BPF_PROG_LOAD_TYPE_DYNAMIC for the rest of the test */
	err = bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DYNAMIC);
	if (!ASSERT_OK(err, "set_load_type_dynamic_final"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_type(skel->progs.prog3), BPF_PROG_LOAD_TYPE_DYNAMIC,
		       "prog3_load_type_final"))
		goto cleanup;

	err = test_load_type__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	if (!ASSERT_TRUE(bpf_program__autoattach(skel->progs.prog2), "prog2_autoattach"))
		goto cleanup;
	if (!ASSERT_FALSE(bpf_program__autoattach(skel->progs.prog3), "prog3_autoattach"))
		goto cleanup;

	/* loaded program type cannot be changed */
	err = bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DISABLED);
	ASSERT_ERR(err, "set_load_type_after_load");

	err = test_load_type__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	usleep(1);

	ASSERT_FALSE(skel->bss->prog1_called, "prog1_called");
	ASSERT_TRUE(skel->bss->prog2_called, "prog2_called");
	ASSERT_FALSE(skel->bss->prog3_called, "prog3_called");

	err = bpf_program__load_dynamically(skel->progs.prog3, 0);
	if (!ASSERT_OK(err, "load_dynamically_1"))
		goto cleanup;

	err = bpf_program__load_dynamically(skel->progs.prog3, 0);
	if (!ASSERT_OK(err, "load_dynamically_2"))
		goto cleanup;

	/* attach prog3 */
	link = bpf_program__attach(skel->progs.prog3);
	if (!ASSERT_OK_PTR(link, "attach"))
		goto cleanup;

	usleep(1);

	if (!ASSERT_TRUE(skel->bss->prog3_called, "prog3_called_again"))
		goto cleanup;

	/* detach prog3 as test_load_type__destroy doesn't detach dynamically loaded programs */
	err = bpf_link__destroy(link);
	ASSERT_OK(err, "link_destroy");

cleanup:
	test_load_type__destroy(skel);
}
