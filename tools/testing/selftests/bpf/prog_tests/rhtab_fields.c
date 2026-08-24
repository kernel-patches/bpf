// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Co., Ltd. */

#include <unistd.h>
#include <test_progs.h>
#include "rhtab_fields.skel.h"

#define RECYCLE_LOOPS 2000
#define LK_MAGIC 0x52484142

/* Userspace view of the BPF value types (layouts must match the progs). */
struct lock_kptr_val_user {
	__u32 lock;
	__u32 pad;
	__u64 tsk;
	__u32 magic;
	__u32 pad2;
};

static __u64 read_counter(struct rhtab_fields *skel, u32 idx)
{
	__u64 vals[libbpf_num_possible_cpus()];
	__u64 sum = 0;
	int i, err;

	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.counters), &idx, vals);
	if (!ASSERT_OK(err, "lookup_counter"))
		return 0;
	for (i = 0; i < libbpf_num_possible_cpus(); i++)
		sum += vals[i];
	return sum;
}

/* Returns the program retval; asserts the test_run itself succeeded. */
static int run_prog(struct rhtab_fields *skel, const char *name)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_program *prog;
	int err;

	prog = bpf_object__find_program_by_name(skel->obj, name);
	if (!ASSERT_OK_PTR(prog, name))
		return -1;
	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
	if (!ASSERT_OK(err, name))
		return -1;
	return topts.retval;
}

static void recycle_loop(struct rhtab_fields *skel, int map_fd,
			 const char *init, const char *del,
			 const char *upd, const char *probe)
{
	u64 zero = 0;
	u32 key = 0;
	int i;

	for (i = 0; i < RECYCLE_LOOPS; i++) {
		if (run_prog(skel, init) != 0) {
			/* Element may be gone; recreate and retry once. */
			if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, &zero, BPF_ANY),
				       "recreate_elem"))
				return;
			if (!ASSERT_OK(run_prog(skel, init), init))
				return;
		}
		if (!ASSERT_OK(run_prog(skel, del), del))
			return;
		if (!ASSERT_OK(run_prog(skel, upd), upd))
			return;
		if (!ASSERT_OK(run_prog(skel, probe), probe))
			return;
	}
}

static void subtest_lock_kptr(struct rhtab_fields *skel)
{
	struct lock_kptr_val_user val = {};
	struct lock_kptr_val_user out = {};
	u64 nonnull_before;
	u32 key = 0;
	int map_fd;

	map_fd = bpf_map__fd(skel->maps.lkmap);

	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, &val, BPF_ANY),
		       "create_elem"))
		return;

	/* Spin lock must be usable from the syscall path (BPF_F_LOCK). */
	val.magic = LK_MAGIC;
	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, &val, BPF_F_LOCK),
		       "locked_update"))
		return;
	if (!ASSERT_OK(bpf_map_lookup_elem_flags(map_fd, &key, &out, BPF_F_LOCK),
		       "locked_lookup"))
		return;
	ASSERT_EQ(out.magic, LK_MAGIC, "locked_lookup_magic");

	/*
	 * Delete/re-insert recycle cycles: the referenced kptr must be
	 * inherited on recycled elements (zeroing it would leak the
	 * reference) and the plain magic bytes must round-trip every time.
	 */
	nonnull_before = read_counter(skel, 1);
	recycle_loop(skel, map_fd, "lk_init", "lk_del", "lk_upd", "lk_probe");
	ASSERT_GT(read_counter(skel, 1), nonnull_before, "recycle_xchg_non_null");
	ASSERT_EQ(read_counter(skel, 3), RECYCLE_LOOPS, "recycle_magic_roundtrip");

	/* The spin lock must still work after many recycles. */
	val.magic = LK_MAGIC + 1;
	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, &val, BPF_F_LOCK),
		       "post_recycle_locked_update"))
		return;
	memset(&out, 0, sizeof(out));
	if (!ASSERT_OK(bpf_map_lookup_elem_flags(map_fd, &key, &out, BPF_F_LOCK),
		       "post_recycle_locked_lookup"))
		return;
	ASSERT_EQ(out.magic, LK_MAGIC + 1, "post_recycle_locked_magic");
}

static void subtest_timer(struct rhtab_fields *skel)
{
	u64 zero = 0;
	u32 key = 0;
	int fired, map_fd;

	map_fd = bpf_map__fd(skel->maps.tmap);
	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, &zero, BPF_ANY),
		       "create_elem"))
		return;

	if (!ASSERT_OK(run_prog(skel, "arm_timer"), "arm_timer_first"))
		return;
	usleep(300000);
	if (!ASSERT_GT(skel->bss->timer_fired, 0, "timer_fired_first"))
		return;

	/* Deleting the element must cancel the timer. */
	fired = skel->bss->timer_fired;
	if (!ASSERT_OK(bpf_map_delete_elem(map_fd, &key), "delete_elem"))
		return;
	usleep(300000);
	ASSERT_EQ(skel->bss->timer_fired, fired, "timer_cancelled_after_delete");

	/*
	 * Re-insert (may recycle the freed element): the timer field must be
	 * re-initialized so a fresh timer can be armed again.
	 */
	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, &zero, BPF_ANY),
		       "recreate_elem"))
		return;
	if (!ASSERT_OK(run_prog(skel, "arm_timer"), "arm_timer_second"))
		return;
	usleep(300000);
	ASSERT_GT(skel->bss->timer_fired, fired, "timer_fired_second");
}

static void subtest_kptr_untrusted(struct rhtab_fields *skel)
{
	u64 nonnull_before;
	u64 zero = 0;
	u32 key = 0;
	int map_fd;

	map_fd = bpf_map__fd(skel->maps.umap);
	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, &zero, BPF_ANY),
		       "create_elem"))
		return;

	/* The untrusted kptr must survive the recycle like a referenced one. */
	nonnull_before = read_counter(skel, 5);
	recycle_loop(skel, map_fd, "u_init", "u_del", "u_upd", "u_probe");
	ASSERT_GT(read_counter(skel, 5), nonnull_before, "recycle_unref_non_null");
}

static void subtest_kptr_percpu(struct rhtab_fields *skel)
{
	u64 nonnull_before;
	u64 zero = 0;
	u32 key = 0;
	int map_fd;

	map_fd = bpf_map__fd(skel->maps.pcmap);
	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, &zero, BPF_ANY),
		       "create_elem"))
		return;

	/* The per-cpu kptr reference must survive the recycle (no leak). */
	nonnull_before = read_counter(skel, 7);
	recycle_loop(skel, map_fd, "pc_init", "pc_del", "pc_upd", "pc_probe");
	ASSERT_GT(read_counter(skel, 7), nonnull_before, "recycle_pcpu_non_null");
}

void test_rhtab_fields(void)
{
	struct rhtab_fields *skel;

	skel = rhtab_fields__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (test__start_subtest("lock_kptr"))
		subtest_lock_kptr(skel);
	if (test__start_subtest("timer"))
		subtest_timer(skel);
	if (test__start_subtest("kptr_untrusted"))
		subtest_kptr_untrusted(skel);
	if (test__start_subtest("kptr_percpu"))
		subtest_kptr_percpu(skel);

	rhtab_fields__destroy(skel);
}
