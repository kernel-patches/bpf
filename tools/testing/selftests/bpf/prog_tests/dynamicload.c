// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <time.h>
#include "test_dynamicload.skel.h"

/* prog4 is tagged __load_dynamic in the source instead of being set
 * imperatively; verify that an explicit bpf_program__set_load_type() call
 * before load overrides the tag's declarative default.
 */
static void dynamicload_verify_override(void)
{
	struct test_dynamicload *skel;
	int err;

	skel = test_dynamicload__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	err = bpf_program__set_load_type(skel->progs.prog4, BPF_PROG_LOAD_TYPE_DISABLED);
	if (!ASSERT_OK(err, "set_load_type_disabled"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_program__load_type(skel->progs.prog4), BPF_PROG_LOAD_TYPE_DISABLED,
		       "prog4_load_type_overridden"))
		goto cleanup;

	/* keep the other dynamic-load-only programs out of the way of this load */
	bpf_program__set_load_type(skel->progs.prog1, BPF_PROG_LOAD_TYPE_DISABLED);
	bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DISABLED);

	err = test_dynamicload__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	/* prog4 was never loaded, so it cannot be loaded dynamically either */
	err = bpf_program__load_dynamically(skel->progs.prog4, 0);
	ASSERT_ERR(err, "load_dynamically_after_override");

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

	/* the __load_dynamic tag alone, with no imperative call, must set
	 * prog4's load type before it is ever touched below
	 */
	if (!ASSERT_EQ(bpf_program__load_type(skel->progs.prog4), BPF_PROG_LOAD_TYPE_DYNAMIC,
		       "prog4_tag_load_type"))
		goto cleanup;
	if (!ASSERT_FALSE(bpf_program__autoattach(skel->progs.prog4), "prog4_autoattach"))
		goto cleanup;

	/* don't load prog1 */
	bpf_program__set_load_type(skel->progs.prog1, BPF_PROG_LOAD_TYPE_DISABLED);

	/* prog2 is autoload */
	bpf_program__set_load_type(skel->progs.prog2, BPF_PROG_LOAD_TYPE_AUTO);

	/* prog3 is dynamically loaded */
	bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DYNAMIC);

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
	err = bpf_program__load_dynamically(skel->progs.prog1, 0);
	if (!ASSERT_ERR(err, "load_dynamically_disabled"))
		goto cleanup;

	/* prog1 is disabled for load */
	err = bpf_program__unload_dynamically(skel->progs.prog1);
	if (!ASSERT_ERR(err, "unload_dynamically_disabled"))
		goto cleanup;

	/* prog2 is autoload */
	err = bpf_program__load_dynamically(skel->progs.prog2, 0);
	if (!ASSERT_ERR(err, "load_dynamically_autoload"))
		goto cleanup;

	/* prog2 is autoload */
	err = bpf_program__unload_dynamically(skel->progs.prog2);
	if (!ASSERT_ERR(err, "unload_dynamically_autoload"))
		goto cleanup;

	/* reset the call flags */
	skel->bss->prog2_called = false;
	skel->bss->prog3_called = false;

	usleep(1);

	ASSERT_FALSE(skel->bss->prog1_called, "prog1_called");
	ASSERT_TRUE(skel->bss->prog2_called, "prog2_called");
	ASSERT_FALSE(skel->bss->prog3_called, "prog3_called");

	/* load prog3 */
	err = bpf_program__load_dynamically(skel->progs.prog3, 0);
	if (!ASSERT_OK(err, "load_dynamically"))
		goto cleanup;

	/* attach prog3 */
	link = bpf_program__attach(skel->progs.prog3);
	if (!ASSERT_OK_PTR(link, "attach"))
		goto cleanup;

	usleep(1);

	if (!ASSERT_TRUE(skel->bss->prog3_called, "prog3_called"))
		goto cleanup;

	/* detach prog3 as test_dynamicload__destroy doesn't detach dynamically loaded programs */
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
	err = bpf_program__unload_dynamically(skel->progs.prog3);
	if (!ASSERT_OK(err, "unload_dynamically"))
		goto cleanup;

	/* reload prog3 */
	err = bpf_program__load_dynamically(skel->progs.prog3, 0);
	if (!ASSERT_OK(err, "load_dynamically_reload"))
		goto cleanup;

	/* reattach prog3 */
	link = bpf_program__attach(skel->progs.prog3);
	if (!ASSERT_OK_PTR(link, "reattach"))
		goto cleanup;

	usleep(1);

	if (!ASSERT_TRUE(skel->bss->prog3_called, "prog3_called_reattach"))
		goto cleanup;

	/* detach prog3 as test_dynamicload__destroy doesn't detach dynamically loaded programs */
	err = bpf_link__destroy(link);
	if (!ASSERT_OK(err, "link_destroy_reattach"))
		goto cleanup;

	/* verify regular unload for dynamically loaded program,
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
	err = bpf_program__load_dynamically(skel->progs.prog3, 0);
	ASSERT_ERR(err, "load_dynamically_after_regular_unload");

	/* run prog4 (declaratively tagged) through the same dynamic
	 * load/attach/trigger/detach/unload cycle as prog3
	 */
	err = bpf_program__load_dynamically(skel->progs.prog4, 0);
	if (!ASSERT_OK(err, "prog4_load_dynamically"))
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

	err = bpf_program__unload_dynamically(skel->progs.prog4);
	ASSERT_OK(err, "prog4_unload_dynamically");

	test_dynamicload__destroy(skel);

	/* separate scenario: imperative override of the declarative tag */
	dynamicload_verify_override();
	return;

cleanup:
	test_dynamicload__destroy(skel);
}

