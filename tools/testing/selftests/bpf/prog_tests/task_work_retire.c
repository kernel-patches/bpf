// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Corporation. */
#include <test_progs.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "task_work_retire.skel.h"

#define REUSE_ROUNDS 32
#define COMPLETION_WAIT_NS 2000000000ULL
#define COMPLETION_WAIT_ITERS 2000

struct retire_value {
	__u64 data;
	struct bpf_task_work tw;
};

static bool run_prog(struct bpf_program *prog, int expected)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	return ASSERT_OK(err, "test_run") &&
	       ASSERT_EQ((__s32)opts.retval, expected, "retval");
}

static __u64 completed(struct task_work_retire *skel)
{
	return __atomic_load_n(&skel->bss->completed, __ATOMIC_ACQUIRE);
}

static bool wait_completed(struct task_work_retire *skel, __u64 expected)
{
	__u64 deadline = get_time_ns() + COMPLETION_WAIT_NS;
	__u64 count;
	int i;

	for (i = 0; i < COMPLETION_WAIT_ITERS; i++) {
		/* irq_work may enqueue task work after test_run returned. */
		syscall(__NR_gettid); /* Give TWA_RESUME another return to user mode. */
		count = completed(skel);
		if (count >= expected)
			return ASSERT_EQ(count, expected, "completed");
		if (get_time_ns() >= deadline)
			break;
		usleep(1000);
	}
	return ASSERT_EQ(completed(skel), expected, "callback_timeout");
}

static struct task_work_retire *open_test(enum bpf_map_type type, __u32 flags,
					  bool use_signal)
{
	struct task_work_retire *skel;
	int err;

	skel = task_work_retire__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return NULL;
	err = bpf_map__set_type(skel->maps.values, type);
	if (!ASSERT_OK(err, "map_type"))
		goto fail;
	err = bpf_map__set_map_flags(skel->maps.values, flags);
	if (!ASSERT_OK(err, "map_flags"))
		goto fail;
	/* A full LRU map evicts the target in prealloc_lru_pop() before the
	 * BPF_EXIST lookup, so keep one spare slot for the update cases.
	 */
	if (type == BPF_MAP_TYPE_LRU_HASH) {
		err = bpf_map__set_max_entries(skel->maps.values, 2);
		if (!ASSERT_OK(err, "map_max_entries"))
			goto fail;
	}
	if (!ASSERT_OK(task_work_retire__load(skel), "load"))
		goto fail;
	/* __open() already exposes the skeleton BSS mapping; writing after
	 * load keeps the mode next to the other post-load setup.
	 */
	skel->bss->use_signal = use_signal;
	return skel;
fail:
	task_work_retire__destroy(skel);
	return NULL;
}

static bool insert_value(struct task_work_retire *skel)
{
	struct retire_value value = {};
	int key = 0;

	return ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.values),
					   &key, &value, BPF_ANY), "insert");
}

static void retired_value(enum bpf_map_type type, bool use_signal, bool replace)
{
	struct task_work_retire *skel;
	struct bpf_program *mutate;
	int i;

	skel = open_test(type, BPF_F_NO_PREALLOC, use_signal);
	if (!skel)
		return;
	mutate = replace ? skel->progs.update_then_schedule :
			   skel->progs.delete_then_schedule;
	if (!insert_value(skel))
		goto out;

	for (i = 0; i < REUSE_ROUNDS; i++) {
		/* First round has no ctx; later rounds have an idle ctx. */
		if (!run_prog(mutate, -ENOENT) ||
		    !ASSERT_OK(skel->bss->mutation_err, "mutation") ||
		    !ASSERT_EQ(completed(skel), i, "retired_not_called"))
			goto out;
		if (!replace && !insert_value(skel))
			goto out;
		if (!run_prog(skel->progs.schedule_live, 0) ||
		    !wait_completed(skel, i + 1))
			goto out;
	}
out:
	task_work_retire__destroy(skel);
}

static void live_update(enum bpf_map_type type, __u32 flags, bool use_signal)
{
	struct task_work_retire *skel;

	skel = open_test(type, flags, use_signal);
	if (!skel)
		return;
	if (!insert_value(skel) || !run_prog(skel->progs.schedule_live, 0) ||
	    !wait_completed(skel, 1))
		goto out;
	if (!run_prog(skel->progs.update_then_schedule, 0) ||
	    !ASSERT_OK(skel->bss->mutation_err, "update"))
		goto out;
	wait_completed(skel, 2);
out:
	task_work_retire__destroy(skel);
}

static void uref_reopen(enum bpf_map_type type, __u32 flags, bool used)
{
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	struct task_work_retire *skel;
	int map_fd, null_fd = -1, reopened_fd = -1;
	int err;

	skel = open_test(type, flags, false);
	if (!skel)
		return;
	if (!insert_value(skel))
		goto out;
	if (used && (!run_prog(skel->progs.schedule_live, 0) ||
		     !wait_completed(skel, 1)))
		goto out;
	map_fd = bpf_map__fd(skel->maps.values);
	err = bpf_map_get_info_by_fd(map_fd, &info, &info_len);
	if (!ASSERT_OK(err, "map_info"))
		goto out;
	null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (!ASSERT_GE(null_fd, 0, "open_dev_null"))
		goto out;
	/*
	 * Drop the sole map FD, retaining only program references. Reserve
	 * its number so skeleton cleanup cannot close an unrelated new FD.
	 */
	if (!ASSERT_EQ(dup3(null_fd, map_fd, O_CLOEXEC), map_fd, "drop_uref"))
		goto out;
	/* Leave the unused case uninitialized until after reopening. */
	if (used && !run_prog(skel->progs.schedule_live, -EBUSY))
		goto out;
	reopened_fd = bpf_map_get_fd_by_id(info.id);
	if (!ASSERT_GE(reopened_fd, 0, "reopen_by_id"))
		goto out;
	if (!ASSERT_EQ(dup3(reopened_fd, map_fd, O_CLOEXEC), map_fd, "restore_map_fd"))
		goto out;
	if (!run_prog(skel->progs.schedule_live, 0))
		goto out;
	wait_completed(skel, used ? 2 : 1);
out:
	if (reopened_fd >= 0)
		close(reopened_fd);
	if (null_fd >= 0)
		close(null_fd);
	task_work_retire__destroy(skel);
}

void test_task_work_retire(void)
{
	static const struct {
		const char *name;
		enum bpf_map_type type;
		__u32 flags;
	} maps[] = {
		{ "hash", BPF_MAP_TYPE_HASH, BPF_F_NO_PREALLOC },
		{ "rhash", BPF_MAP_TYPE_RHASH, BPF_F_NO_PREALLOC },
		{ "array", BPF_MAP_TYPE_ARRAY, 0 },
		{ "prealloc_hash", BPF_MAP_TYPE_HASH, 0 },
		{ "lru", BPF_MAP_TYPE_LRU_HASH, 0 },
	};
	char name[80];
	int signal, i, used;

	for (signal = 0; signal < 2; signal++) {
		snprintf(name, sizeof(name), "hash_delete_%s", signal ? "signal" : "resume");
		if (test__start_subtest(name))
			retired_value(BPF_MAP_TYPE_HASH, signal, false);
		snprintf(name, sizeof(name), "rhash_delete_%s", signal ? "signal" : "resume");
		if (test__start_subtest(name))
			retired_value(BPF_MAP_TYPE_RHASH, signal, false);
		snprintf(name, sizeof(name), "hash_replace_%s", signal ? "signal" : "resume");
		if (test__start_subtest(name))
			retired_value(BPF_MAP_TYPE_HASH, signal, true);
		snprintf(name, sizeof(name), "rhash_update_%s", signal ? "signal" : "resume");
		if (test__start_subtest(name))
			live_update(BPF_MAP_TYPE_RHASH, BPF_F_NO_PREALLOC, signal);
		snprintf(name, sizeof(name), "array_update_%s", signal ? "signal" : "resume");
		if (test__start_subtest(name))
			live_update(BPF_MAP_TYPE_ARRAY, 0, signal);
		snprintf(name, sizeof(name), "prealloc_hash_update_%s",
			 signal ? "signal" : "resume");
		if (test__start_subtest(name))
			live_update(BPF_MAP_TYPE_HASH, 0, signal);
		snprintf(name, sizeof(name), "lru_update_%s", signal ? "signal" : "resume");
		if (test__start_subtest(name))
			live_update(BPF_MAP_TYPE_LRU_HASH, 0, signal);
	}
	for (i = 0; i < ARRAY_SIZE(maps); i++) {
		for (used = 0; used < 2; used++) {
			snprintf(name, sizeof(name), "%s_uref_reopen_%s", maps[i].name,
				 used ? "used" : "unused");
			if (test__start_subtest(name))
				uref_reopen(maps[i].type, maps[i].flags, used);
		}
	}
}
