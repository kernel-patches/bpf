// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <time.h>
#include "test_dynamicload.skel.h"

void test_dynamicload(void)
{
	struct bpf_link *link;
	struct test_dynamicload *skel;
	int err;

	skel = test_dynamicload__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

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

cleanup:
	test_dynamicload__destroy(skel);
}
