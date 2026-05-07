// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */

#include <test_progs.h>
#include <time.h>
#include "test_vmlinux.skel.h"

#define MY_TV_NSEC 1337

static void nsleep()
{
	struct timespec ts = { .tv_nsec = MY_TV_NSEC };

	(void)syscall(__NR_nanosleep, &ts, NULL);
}

static void enable_hrtimer_progs(struct test_vmlinux *skel)
{
	bool has_user_helper;

	has_user_helper = libbpf_find_vmlinux_btf_id("hrtimer_start_range_ns_user",
						    BPF_TRACE_FENTRY) > 0;
	if (has_user_helper) {
		bpf_program__set_autoload(skel->progs.handle__kprobe_user, true);
		bpf_program__set_autoload(skel->progs.handle__fentry_user, true);
	} else {
		bpf_program__set_autoload(skel->progs.handle__kprobe, true);
		bpf_program__set_autoload(skel->progs.handle__fentry, true);
	}
}

void test_vmlinux(void)
{
	int err;
	struct test_vmlinux* skel;
	struct test_vmlinux__bss *bss;

	skel = test_vmlinux__open();
	if (!ASSERT_OK_PTR(skel, "test_vmlinux__open"))
		return;

	enable_hrtimer_progs(skel);

	err = test_vmlinux__load(skel);
	if (!ASSERT_OK(err, "test_vmlinux__load"))
		goto cleanup;

	bss = skel->bss;

	err = test_vmlinux__attach(skel);
	if (!ASSERT_OK(err, "test_vmlinux__attach"))
		goto cleanup;

	/* trigger everything */
	nsleep();

	ASSERT_TRUE(bss->tp_called, "tp");
	ASSERT_TRUE(bss->raw_tp_called, "raw_tp");
	ASSERT_TRUE(bss->tp_btf_called, "tp_btf");
	ASSERT_TRUE(bss->kprobe_called, "kprobe");
	ASSERT_TRUE(bss->fentry_called, "fentry");

cleanup:
	test_vmlinux__destroy(skel);
}
