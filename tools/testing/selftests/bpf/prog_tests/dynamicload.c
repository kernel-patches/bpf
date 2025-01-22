// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <time.h>
#include "test_dynamicload.skel.h"

void test_dynamicload(void)
{
	int duration = 0, err;
	struct bpf_link *link;
	struct test_dynamicload *skel;

	skel = test_dynamicload__open();
	if (CHECK(!skel, "skel_open", "failed to open skeleton\n"))
		goto cleanup;

	/* don't load prog1 */
	bpf_program__set_load_type(skel->progs.prog1, BPF_PROG_LOAD_TYPE_DISABLED);

	/* prog2 is autoload */
	bpf_program__set_load_type(skel->progs.prog2, BPF_PROG_LOAD_TYPE_AUTO);

	/* prog3 is dynamically loaded */
	bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DYNAMIC);

	err = test_dynamicload__load(skel);
	if (CHECK(err, "skel_load", "failed to load skeleton: %d\n", err))
		goto cleanup;

	err = test_dynamicload__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	/* trigger the BPF programs */
	usleep(1);

	CHECK(skel->bss->prog1_called, "prog1", "called?!\n");
	CHECK(!skel->bss->prog2_called, "prog2", "not called\n");
	CHECK(skel->bss->prog3_called, "prog3", "called?!\n");

	/* prog1 is disabled for load */
	err = bpf_program__load_dynamically(skel->progs.prog1, 0);
	if (CHECK(!err, "load_dynamically", "disabled program loaded?!\n"))
		goto cleanup;

	/* prog1 is disabled for load */
	err = bpf_program__unload_dynamically(skel->progs.prog1);
	if (CHECK(!err, "load_dynamically", "disabled program unloaded?!\n"))
		goto cleanup;

	/* prog2 is autoload */
	err = bpf_program__load_dynamically(skel->progs.prog1, 0);
	if (CHECK(!err, "load_dynamically", "autoload loaded dynamically?!\n"))
		goto cleanup;

	/* prog2 is autoload */
	err = bpf_program__unload_dynamically(skel->progs.prog1);
	if (CHECK(!err, "load_dynamically", "autoload unloaded dynamically?!\n"))
		goto cleanup;

	/* reset the call flags */
	skel->bss->prog2_called = false;
	skel->bss->prog3_called = false;

	usleep(1);

	CHECK(skel->bss->prog1_called, "prog1", "called?!\n");
	CHECK(!skel->bss->prog2_called, "prog2", "not called\n");
	CHECK(skel->bss->prog3_called, "prog3", "called?!\n");

	/* load prog3 */
	err = bpf_program__load_dynamically(skel->progs.prog3, 0);
	if (CHECK(err, "load_dynamically", "dynamic loading failed: %d\n", err))
		goto cleanup;

	/* attach prog3 */
	link = bpf_program__attach(skel->progs.prog3);
	if (CHECK(libbpf_get_error(link), "attach", "attaching failed: %ld\n",
		  libbpf_get_error(link)))
		goto cleanup;

	usleep(1);

	CHECK(!skel->bss->prog3_called, "prog3", "not called\n");

	/* detach prog3 as test_dynamicload__destroy doesn't detach dynamically loaded programs */
	err = bpf_link__destroy(link);
	if (CHECK(err, "link__destroy", "link destroy failed: %d\n", err))
		goto cleanup;

	/* reset the call flags after detach */
	skel->bss->prog2_called = false;
	skel->bss->prog3_called = false;

	usleep(1);

	CHECK(!skel->bss->prog2_called, "prog2", "not called\n");
	CHECK(skel->bss->prog3_called, "prog3", "called?!\n");

	/* unload prog3 */
	err = bpf_program__unload_dynamically(skel->progs.prog3);
	if (CHECK(err, "unload_dynamically", "unload dynamically failed: %d\n", err))
		goto cleanup;

	/* reload prog3 */
	err = bpf_program__load_dynamically(skel->progs.prog3, 0);
	if (CHECK(err, "load_dynamically", "dynamic reloading failed: %d\n", err))
		goto cleanup;

	/* reattach prog3 */
	link = bpf_program__attach(skel->progs.prog3);
	if (CHECK(libbpf_get_error(link), "attach", "reattaching failed: %d\n", err))
		goto cleanup;

	usleep(1);

	CHECK(!skel->bss->prog3_called, "prog3", "not called\n");

	/* detach prog3 as test_dynamicload__destroy doesn't detach dynamically loaded programs */
	err = bpf_link__destroy(link);
	if (CHECK(err, "link__destroy", "link destroy failed: %d\n", err))
		goto cleanup;

	/* verify regular unload for dynamically loaded program,
	 * unload prog3 as a regular program
	 */
	bpf_program__unload(skel->progs.prog3);

	/* reset the call flags after unload */
	skel->bss->prog2_called = false;
	skel->bss->prog3_called = false;

	usleep(1);

	CHECK(!skel->bss->prog2_called, "prog2", "not called\n");
	CHECK(skel->bss->prog3_called, "prog3", "called?!\n");

	/* reloading prog3 must fail as it was unloaded as a regular program */
	err = bpf_program__load_dynamically(skel->progs.prog3, 0);
	if (CHECK(!err, "load_dynamically", "dynamic reloading succeeded?! %d\n", err))
		goto cleanup;

cleanup:
	test_dynamicload__destroy(skel);
}
