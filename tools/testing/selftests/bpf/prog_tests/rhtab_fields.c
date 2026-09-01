// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Co., Ltd. */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <test_progs.h>
#include "rhtab_fields.skel.h"
#include "rhtab_fields_common.h"

#define RECYCLE_LOOPS 2000

/* Userspace view of the lkmap value. The BPF side owns the real layout;
 * the spin lock and the kptr are special fields that value copies skip,
 * so only the plain bytes actually matter here.
 */
struct lock_kptr_val_user {
	__u32 lock;
	__u32 pad;
	__u64 tsk;
	__u32 magic;
	__u32 pad2;
};

_Static_assert(sizeof(struct lock_kptr_val_user) == 24, "lkmap layout drift");
_Static_assert(offsetof(struct lock_kptr_val_user, magic) == 16,
	       "lkmap magic offset drift");

/*
 * Zeroed value buffer shared by every create/update issued from userspace.
 * The update syscall copies map->value_size bytes from this buffer (special
 * fields among them), so a short stack variable would be read past its end;
 * BSS is zero-filled and 64 bytes cover every map in the skeleton. Each
 * caller re-checks the size to keep that true as maps are added.
 */
static __u8 zero_val[64];

/* Cached CPU count and scratch buffer for percpu counter summation. */
static __u64 *cpu_vals;
static int ncpu;

static __u64 read_counter(struct rhtab_fields *skel, __u32 idx)
{
	__u64 sum = 0;
	int i, err;

	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.counters), &idx,
				  cpu_vals);
	if (!ASSERT_OK(err, "lookup_counter"))
		return 0;
	for (i = 0; i < ncpu; i++)
		sum += cpu_vals[i];
	return sum;
}

/*
 * Run @name through BPF_PROG_TEST_RUN. Returns 0 on success and reports the
 * program retval through @retval, so callers can tell a syscall failure,
 * a prog that exited nonzero, and a prog that exited 0 apart.
 */
static int run_prog(struct rhtab_fields *skel, const char *name, int *retval)
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
	if (retval)
		*retval = topts.retval;
	return 0;
}

/* run_prog() plus the assertion that the program exited 0. */
static int run_prog_ok(struct rhtab_fields *skel, const char *name)
{
	int retval = -1;

	if (!ASSERT_OK(run_prog(skel, name, &retval), name))
		return -1;
	if (!ASSERT_EQ(retval, 0, name))
		return -1;
	return 0;
}

/* Create one element filled with zero_val in @map. */
static int create_zero_elem(struct bpf_map *map, const char *name)
{
	__u32 key = 0;
	int fd;

	if (!ASSERT_LE(bpf_map__value_size(map), sizeof(zero_val),
		       "value_size_fits"))
		return -1;
	fd = bpf_map__fd(map);
	return bpf_map_update_elem(fd, &key, zero_val, BPF_ANY);
}

static void recycle_loop(struct rhtab_fields *skel, int map_fd,
			 const char *init, const char *del,
			 const char *upd, const char *probe,
			 int *retries)
{
	__u32 key = 0;
	int i;

	for (i = 0; i < RECYCLE_LOOPS; i++) {
		if (run_prog_ok(skel, init) != 0) {
			/* init fails only if the element is missing, which
			 * must not happen in this single-threaded loop. Count
			 * it so a rhtab bug cannot be absorbed silently; the
			 * caller asserts the count is zero.
			 */
			(*retries)++;
			if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key,
							   zero_val, BPF_ANY),
				       "recreate_elem"))
				return;
			if (run_prog_ok(skel, init) != 0)
				return;
		}
		if (run_prog_ok(skel, del) != 0)
			return;
		if (run_prog_ok(skel, upd) != 0)
			return;
		if (run_prog_ok(skel, probe) != 0)
			return;
	}
}

static void subtest_lock_kptr(struct rhtab_fields *skel)
{
	struct lock_kptr_val_user val = {};
	struct lock_kptr_val_user out = {};
	__u64 nonnull_before, total;
	int map_fd, retries = 0;
	__u32 key = 0;

	map_fd = bpf_map__fd(skel->maps.lkmap);

	if (!ASSERT_OK(create_zero_elem(skel->maps.lkmap, "create_elem"),
		       "create_elem"))
		return;

	/* The spin lock must be usable from the syscall path (BPF_F_LOCK). */
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
	 * Every iteration runs exactly one probe, so the two probe counters
	 * must add up to the loop count; the magic check must hold on every
	 * single probe.
	 */
	nonnull_before = read_counter(skel, 1);
	recycle_loop(skel, map_fd, "lk_init", "lk_del", "lk_upd", "lk_probe",
		     &retries);
	ASSERT_EQ(retries, 0, "no_unexpected_recreate");
	ASSERT_EQ(read_counter(skel, 0), RECYCLE_LOOPS, "lk_init_count");
	total = read_counter(skel, 1) + read_counter(skel, 2);
	ASSERT_EQ(total, RECYCLE_LOOPS, "lk_probe_count");
	ASSERT_EQ(read_counter(skel, 3), RECYCLE_LOOPS,
		  "recycle_magic_roundtrip");
	ASSERT_GT(read_counter(skel, 1), nonnull_before,
		  "recycle_xchg_non_null");

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
	int fired, map_fd;
	__u32 key = 0;

	map_fd = bpf_map__fd(skel->maps.tmap);

	if (!ASSERT_OK(create_zero_elem(skel->maps.tmap, "create_elem"),
		       "create_elem"))
		return;

	/* 1. A short-delay timer must fire. */
	skel->data->timer_delay_ns = 50000;
	if (run_prog_ok(skel, "arm_timer") != 0)
		return;
	usleep(300000);
	if (!ASSERT_GT(skel->bss->timer_fired, 0, "timer_fired_first"))
		return;

	/*
	 * 2. The real cancellation test: arm a long-delay timer on a freshly
	 * recycled element and delete the element while the timer is still
	 * pending. If the delete failed to cancel it, the callback would run
	 * before the sleep below ends. The element must be deleted and
	 * recreated between arms: bpf_timer_init() returns -EBUSY on an
	 * element whose timer has not been cancelled and freed yet.
	 */
	fired = skel->bss->timer_fired;
	if (!ASSERT_OK(bpf_map_delete_elem(map_fd, &key),
		       "delete_before_rearm"))
		return;
	if (!ASSERT_OK(create_zero_elem(skel->maps.tmap, "recreate_elem"),
		       "recreate_before_rearm"))
		return;
	skel->data->timer_delay_ns = 200000000;
	if (run_prog_ok(skel, "arm_timer") != 0)
		return;
	if (!ASSERT_OK(bpf_map_delete_elem(map_fd, &key),
		       "delete_cancels_timer"))
		return;
	usleep(300000);
	ASSERT_EQ(skel->bss->timer_fired, fired, "timer_cancelled_after_delete");

	/* 3. A recycled element can arm and fire a fresh timer again. */
	skel->data->timer_delay_ns = 50000;
	if (!ASSERT_OK(create_zero_elem(skel->maps.tmap, "recreate_elem"),
		       "recreate_second"))
		return;
	if (run_prog_ok(skel, "arm_timer") != 0)
		return;
	usleep(300000);
	ASSERT_GT(skel->bss->timer_fired, fired, "timer_fired_second");
}

struct kptr_recycle_case {
	const char *name;
	struct bpf_map **map;
	const char *init;
	const char *del;
	const char *upd;
	const char *probe;
	__u32 init_idx;    /* counter bumped on every successful init */
	__u32 nonnull_idx; /* counter bumped when the kptr was inherited */
	__u32 null_idx;    /* counter bumped when the kptr was not inherited */
	__u32 marker_idx;  /* percpu data roundtrip counter, 0 if none */
};

static void subtest_kptr_recycle(struct rhtab_fields *skel,
				 const struct kptr_recycle_case *c)
{
	__u64 nonnull_before, total;
	struct bpf_map *map;
	int map_fd, retries = 0;

	map = *c->map;
	map_fd = bpf_map__fd(map);

	if (!ASSERT_OK(create_zero_elem(map, "create_elem"), "create_elem"))
		return;

	/* The kptr must survive the recycle without leaking its reference,
	 * exactly like the referenced kptr in the lkmap subtest.
	 */
	nonnull_before = read_counter(skel, c->nonnull_idx);
	recycle_loop(skel, map_fd, c->init, c->del, c->upd, c->probe,
		     &retries);
	ASSERT_EQ(retries, 0, "no_unexpected_recreate");
	ASSERT_EQ(read_counter(skel, c->init_idx), RECYCLE_LOOPS,
		  "init_count");
	total = read_counter(skel, c->nonnull_idx) +
		read_counter(skel, c->null_idx);
	ASSERT_EQ(total, RECYCLE_LOOPS, "probe_count");
	ASSERT_GT(read_counter(skel, c->nonnull_idx), nonnull_before,
		  "recycle_non_null");
	/* The marker read is CPU-local, so assert at least one hit. */
	if (c->marker_idx)
		ASSERT_GT(read_counter(skel, c->marker_idx), 0,
			  "recycle_data_roundtrip");
}

static void subtest_kptr_recycles(struct rhtab_fields *skel)
{
	const struct kptr_recycle_case cases[] = {
		{ .name = "kptr_untrusted", .map = &skel->maps.umap,
		  .init = "u_init", .del = "u_del", .upd = "u_upd",
		  .probe = "u_probe", .init_idx = 4, .nonnull_idx = 5,
		  .null_idx = 6 },
		{ .name = "kptr_percpu", .map = &skel->maps.pcmap,
		  .init = "pc_init", .del = "pc_del", .upd = "pc_upd",
		  .probe = "pc_probe", .init_idx = 7, .nonnull_idx = 8,
		  .null_idx = 9, .marker_idx = 10 },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		if (test__start_subtest(cases[i].name))
			subtest_kptr_recycle(skel, &cases[i]);
	}
}

void test_rhtab_fields(void)
{
	struct rhtab_fields *skel;

	ncpu = libbpf_num_possible_cpus();
	if (!ASSERT_GT(ncpu, 0, "num_possible_cpus"))
		return;
	cpu_vals = calloc(ncpu, sizeof(*cpu_vals));
	if (!ASSERT_OK_PTR(cpu_vals, "calloc_cpu_vals"))
		return;

	skel = rhtab_fields__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load")) {
		free(cpu_vals);
		return;
	}

	if (test__start_subtest("lock_kptr"))
		subtest_lock_kptr(skel);
	if (test__start_subtest("timer"))
		subtest_timer(skel);
	subtest_kptr_recycles(skel);

	rhtab_fields__destroy(skel);
	free(cpu_vals);
}
