// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <time.h>
#include "test_load_type.skel.h"

void test_load_type(void)
{
	int duration = 0, err;
	struct bpf_link *link;
	struct test_load_type *skel;

	skel = test_load_type__open();
	if (CHECK(!skel, "skel_open", "failed to open skeleton\n"))
		goto cleanup;

	/* don't load prog1 */
	bpf_program__set_load_type(skel->progs.prog1, BPF_PROG_LOAD_TYPE_DISABLED);

	/* load and attach prog2 */
	bpf_program__set_load_type(skel->progs.prog2, BPF_PROG_LOAD_TYPE_AUTO);
	CHECK(!bpf_program__autoload(skel->progs.prog2), "prog2", "not autoload?!\n");

	err = bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DYNAMIC);
	if (CHECK(err, "set_load_type", "set_load_type(DYNAMIC) failed: %d\n", err))
		goto cleanup;
	CHECK(bpf_program__load_type(skel->progs.prog3) != BPF_PROG_LOAD_TYPE_DYNAMIC,
		"prog3", "didn't set type?!\n");

	/* bpf_program__set_autoload(program, false) doesn't have effect if the program
	 * type is not BPF_PROG_LOAD_TYPE_AUTO
	 */
	err = bpf_program__set_autoload(skel->progs.prog3, false);
	if (CHECK(err, "set_autoload", "set_autoload(false) failed: %d\n", err))
		goto cleanup;

	CHECK(bpf_program__load_type(skel->progs.prog3) != BPF_PROG_LOAD_TYPE_DYNAMIC,
		"prog3", "changed type?!\n");

	err = bpf_program__set_autoload(skel->progs.prog3, true);
	if (CHECK(err, "set_autoload", "set_autoload(true) failed: %d\n", err))
		goto cleanup;

	CHECK(bpf_program__load_type(skel->progs.prog3) != BPF_PROG_LOAD_TYPE_AUTO,
		"prog3", "didn't change type to auto?!\n");

	/* change the type back to BPF_PROG_LOAD_TYPE_DYNAMIC */
	err = bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DYNAMIC);
	if (CHECK(err, "set_load_type", "changing from AUTO to DYNAMIC failed: %d\n", err))
		goto cleanup;

	CHECK(bpf_program__load_type(skel->progs.prog3) != BPF_PROG_LOAD_TYPE_DYNAMIC,
		"prog3", "didn't change type from autoload to dynamic?!\n");

	err = test_load_type__load(skel);
	if (CHECK(err, "skel_load", "failed to load skeleton: %d\n", err))
		goto cleanup;

	CHECK(!bpf_program__autoattach(skel->progs.prog2), "prog2", "not autoattach?!\n");
	CHECK(bpf_program__autoattach(skel->progs.prog3), "prog3", "autoattach?!\n");

	/* loaded program type cannot be changed */
	err = bpf_program__set_load_type(skel->progs.prog3, BPF_PROG_LOAD_TYPE_DISABLED);
	CHECK(!err, "prog3", "changed type after load?!\n");

	err = test_load_type__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	usleep(1);

	CHECK(skel->bss->prog1_called, "prog1", "called?!\n");
	CHECK(!skel->bss->prog2_called, "prog2", "not called\n");
	CHECK(skel->bss->prog3_called, "prog3", "called?!\n");

	err = bpf_program__load_dynamically(skel->progs.prog3, 0);
	if (CHECK(err, "load_dynamically", "load dynamically failed: %d\n", err))
		goto cleanup;

	err = bpf_program__load_dynamically(skel->progs.prog3, 0);
	if (CHECK(err, "load_dynamically", "load dynamically failed: %d\n", err))
		goto cleanup;

	/* attach prog3 */
	link = bpf_program__attach(skel->progs.prog3);
	if (CHECK(libbpf_get_error(link), "attach", "attaching failed: %ld\n",
		  libbpf_get_error(link)))
		goto cleanup;

	usleep(1);

	CHECK(!skel->bss->prog3_called, "prog3", "not called?!\n");

	/* detach prog3 as test_load_type__destroy doesn't detach dynamically loaded programs */
	err = bpf_link__destroy(link);
	if (CHECK(err, "link__destroy", "link destroy failed: %d\n", err))
		goto cleanup;

cleanup:
	test_load_type__destroy(skel);
}
