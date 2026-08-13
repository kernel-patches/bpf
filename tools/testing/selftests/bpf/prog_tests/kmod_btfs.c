// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "kmod_btfs.skel.h"
#include "kmod_btfs_nonexist.skel.h"
#include "kmod_btfs_mix.skel.h"

static void kmod_btfs_pass(void)
{
	struct kmod_btfs *kmod_btfs_skel;

	kmod_btfs_skel = kmod_btfs__open_and_load();
	if (!ASSERT_OK_PTR(kmod_btfs_skel, "kmod_btfs__open_and_load"))
		return;

	kmod_btfs__destroy(kmod_btfs_skel);
}

static void kmod_btfs_nonexist(void)
{
	struct kmod_btfs_nonexist *kmod_btfs_nonexist_skel;

	kmod_btfs_nonexist_skel = kmod_btfs_nonexist__open_and_load();
	ASSERT_NULL(kmod_btfs_nonexist_skel, "kmod_btfs_nonexist__open_and_load");
}

static void kmod_btfs_mix(void)
{
	struct kmod_btfs_mix *kmod_btfs_mix_skel;

	kmod_btfs_mix_skel = kmod_btfs_mix__open_and_load();
	if (!ASSERT_OK_PTR(kmod_btfs_mix_skel, "kmod_btfs_mix__open_and_load"))
		return;

	kmod_btfs_mix__destroy(kmod_btfs_mix_skel);
}

void test_kmod_btfs(void)
{
	if (!env.has_testmod) {
		test__skip();
		return;
	}

	if (test__start_subtest("kmod_btfs_pass"))
		kmod_btfs_pass();

	if (test__start_subtest("kmod_btfs_nonexist"))
		kmod_btfs_nonexist();

	if (test__start_subtest("kmod_btfs_mix"))
		kmod_btfs_mix();
}
