// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025, Oracle and/or its affiliates. */

#include <test_progs.h>
#include <sys/stat.h>

#include "kloc.skel.h"

void test_kloc(void)
{
	int err = 0, duration = 0;
	struct kloc *skel;
	struct stat sb;

	/* If CONFIG_DEBUG_INFO_BTF_EXTRA=m , ensure vmlinux BTF extra is
	 * loaded.
	 */
	system("modprobe btf_extra");

	/* Kernel may not have been compiled with extra BTF info or pahole
	 * may not have support.
	 */
	if (stat("/sys/kernel/btf_extra/vmlinux", &sb) != 0)
		test__skip();

	skel = kloc__open_and_load();
	if (CHECK(!skel, "skel_load", "skeleton failed: %d\n", err))
		goto cleanup;

	skel->bss->test_pid = getpid();

	err = kloc__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto cleanup;
	/* trigger bpf syscall to trigger kloc */
	(void) bpf_obj_get("/sys/fs/bpf/noexist");

	ASSERT_GT(skel->bss->kloc_triggered, 0, "verify kloc was triggered");

	/* this is a conditional since it is possible the size parameter
	 * is not available at the inline site.
	 *
	 * Expected size here is that from bpf_obj_get_opts(); see
	 * tools/lib/bpf/bpf.c.
	 */
	if (skel->bss->kloc_size > 0)
		ASSERT_EQ(skel->bss->kloc_size, offsetofend(union bpf_attr, path_fd), "verify kloc size set");

cleanup:
	kloc__destroy(skel);
}
