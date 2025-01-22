// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <time.h>
#include "test_load_type.skel.h"

void test_load_type(void)
{
	int duration = 0, err;
	struct test_load_type *skel;

	skel = test_load_type__open();
	if (CHECK(!skel, "skel_open", "failed to open skeleton\n"))
		goto cleanup;

	/* don't load prog1 */
	bpf_program__set_load_type(skel->progs.prog1, BPF_PROG_LOAD_TYPE_DISABLED);

	/* load and attach prog2 */
	bpf_program__set_load_type(skel->progs.prog2, BPF_PROG_LOAD_TYPE_AUTO);
	CHECK(!bpf_program__autoload(skel->progs.prog2), "prog2", "not autoload?!\n");

	err = test_load_type__load(skel);
	if (CHECK(err, "skel_load", "failed to load skeleton: %d\n", err))
		goto cleanup;

	CHECK(!bpf_program__autoattach(skel->progs.prog2), "prog2", "not autoattach?!\n");

	err = test_load_type__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	usleep(1);

	CHECK(skel->bss->prog1_called, "prog1", "called?!\n");
	CHECK(!skel->bss->prog2_called, "prog2", "not called\n");

cleanup:
	test_load_type__destroy(skel);
}
