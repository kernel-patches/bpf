// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "arena_slab_freeptr_stale_pcs.skel.h"

void test_arena_slab_freeptr_stale_pcs(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct arena_slab_freeptr_stale_pcs *skel;
	int ret;

	skel = arena_slab_freeptr_stale_pcs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "arena_slab_freeptr_stale_pcs__open_and_load"))
		return;

	ret = bpf_prog_test_run_opts(
		bpf_program__fd(skel->progs.arena_slab_freeptr_stale_pcs),
		&opts);
	ASSERT_OK(ret, "arena_slab_freeptr_stale_pcs_run");
	ASSERT_OK(opts.retval, "arena_slab_freeptr_stale_pcs_retval");
	ASSERT_EQ(skel->bss->alloc_failed, 0, "initial allocs");
	ASSERT_EQ(skel->bss->drain_failed, 0, "drain sheaf allocs");
	ASSERT_EQ(skel->bss->cycle_alloc_failed, 0, "self-cycle alloc");
	ASSERT_EQ(skel->bss->cycle_alloc_mismatch, 0, "cycle returned victim");
	ASSERT_EQ(skel->bss->stale_alloc_null, 1, "stale sheaf alloc rejected");
	ASSERT_EQ(skel->bss->done, 1, "stale pcs trigger completed");

	arena_slab_freeptr_stale_pcs__destroy(skel);
}
