// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include "arena_slab.skel.h"

void test_arena_slab(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct arena_slab *skel;
	int ret;

	skel = arena_slab__open_and_load();
	if (!ASSERT_OK_PTR(skel, "arena_slab__open_and_load"))
		return;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arena_slab_alloc), &opts);
	ASSERT_OK(ret, "alloc_run");
	ASSERT_OK(opts.retval, "alloc_retval");
	ASSERT_EQ(skel->bss->alloc_failed, 0, "no alloc failures");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arena_slab_free), &opts);
	ASSERT_OK(ret, "free_run");
	ASSERT_OK(opts.retval, "free_retval");
	ASSERT_EQ(skel->bss->free_done, 1, "free completed");

	/* Realloc to make sure freed objects can be returned again. */
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arena_slab_alloc), &opts);
	ASSERT_OK(ret, "realloc_run");
	ASSERT_EQ(skel->bss->alloc_failed, 0, "no alloc failures after free");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arena_slab_free), &opts);
	ASSERT_OK(ret, "free_run_2");

	/*
	 * defer_free() corruption repro. Allocates CORRUPT_N PAGE_SIZE
	 * objects, then with local IRQs disabled frees each one and
	 * immediately overwrites its freepointer slot. With IRQs off the
	 * irq_work IPI raised by defer_free() is deferred; multiple
	 * defer_free()d objects chain onto the per-cpu llist via the
	 * poisoned freepointer slots. After local_irq_restore() the IPI
	 * fires and free_deferred_objects() walks the corrupted llist,
	 * oopsing on a pre-fix kernel. The spin_trylock __slab_free()
	 * fix keeps the freed objects out of any in-object llist, so the
	 * test completes cleanly.
	 */
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arena_slab_defer_corrupt), &opts);
	ASSERT_OK(ret, "defer_corrupt_run");
	ASSERT_OK(opts.retval, "defer_corrupt_retval");
	ASSERT_EQ(skel->bss->corrupt_alloc_failed, 0, "no alloc failures in defer_corrupt");
	ASSERT_EQ(skel->bss->corrupt_done, 1, "defer_corrupt completed");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arena_slab_leak), &opts);
	ASSERT_OK(ret, "leak_run");
	ASSERT_OK(opts.retval, "leak_retval");
	ASSERT_EQ(skel->bss->leak_alloc_failed, 0, "no alloc failures in leak");
	ASSERT_EQ(skel->bss->leak_done, 1, "leak completed");

	arena_slab__destroy(skel);
}
