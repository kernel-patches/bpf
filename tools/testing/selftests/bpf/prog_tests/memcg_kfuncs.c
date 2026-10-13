// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "cgroup_helpers.h"
#include "memcg_kfuncs.skel.h"
#include "memcg_kfuncs_failure.skel.h"

#define CG_PATH		"/memcg_kfuncs"

/* From mm/internal.h, not exposed in BTF. */
#define MAX_SWAPPINESS		200
#define SWAPPINESS_ANON_ONLY	(MAX_SWAPPINESS + 1)

/* bpf_proactive_reclaim() clamps the request to MEMCG_CHARGE_BATCH pages. */
#define MEMCG_CHARGE_BATCH	64

#define ANON_SIZE		(4 * 1024 * 1024)
#define USAGE_SLACK		(1 * 1024 * 1024)
#define PAGECACHE_SIZE		(32 * 1024 * 1024)
#define HIGH_HEADROOM		(1 * 1024 * 1024)
#define RECLAIM_RETRIES		16

static long page_size;

static int run_prog(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
		return -1;
	if (!ASSERT_EQ(opts.retval, 0, "retval"))
		return -1;
	return 0;
}

static int read_memcg_ulong(const char *file, unsigned long *val)
{
	char buf[64];

	if (read_cgroup_file(CG_PATH, file, buf, sizeof(buf)))
		return -1;
	*val = strtoul(buf, NULL, 10);
	return 0;
}

static int read_memory_event(const char *key, unsigned long *val)
{
	char buf[512], name[64], *line, *saveptr;
	unsigned long v;

	if (read_cgroup_file(CG_PATH, "memory.events", buf, sizeof(buf)))
		return -1;

	for (line = strtok_r(buf, "\n", &saveptr); line;
	     line = strtok_r(NULL, "\n", &saveptr)) {
		if (sscanf(line, "%63s %lu", name, &v) != 2)
			continue;
		if (!strcmp(name, key)) {
			*val = v;
			return 0;
		}
	}
	return -1;
}

static int alloc_pagecache_or_skip(size_t size)
{
	int fd;

	fd = alloc_pagecache(size);
	if (fd == -EOPNOTSUPP) {
		fprintf(stderr, "%s:SKIP:no disk-backed O_TMPFILE in cwd\n", __func__);
		test__skip();
		return -1;
	}
	ASSERT_OK_FD(fd, "alloc_pagecache");
	return fd;
}

static void test_usage(struct memcg_kfuncs *skel)
{
	unsigned long before, after, lo, hi;
	void *map;

	map = mmap(NULL, ANON_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (!ASSERT_NEQ(map, MAP_FAILED, "mmap anon"))
		return;
	memset(map, 1, ANON_SIZE);

	if (!ASSERT_OK(read_memcg_ulong("memory.current", &before), "read before"))
		goto out;
	if (run_prog(skel->progs.memcg_query))
		goto out;
	if (!ASSERT_OK(read_memcg_ulong("memory.current", &after), "read after"))
		goto out;

	/*
	 * bpf_mem_cgroup_usage() and memory.current read the same counter,
	 * but the cgroup may still be charged or uncharged in between.
	 */
	lo = (before < after ? before : after) - USAGE_SLACK;
	hi = (before < after ? after : before) + USAGE_SLACK;
	ASSERT_GE(skel->bss->usage, ANON_SIZE, "usage covers anon");
	ASSERT_GE(skel->bss->usage, lo, "usage lower bound");
	ASSERT_LE(skel->bss->usage, hi, "usage upper bound");
out:
	munmap(map, ANON_SIZE);
}

static void test_invalid_idx(struct memcg_kfuncs *skel)
{
	if (run_prog(skel->progs.memcg_query))
		return;

	ASSERT_EQ(skel->bss->bad_memory_event, -1UL, "bad memory event");
	ASSERT_EQ(skel->bss->bad_vm_event, -1UL, "bad vm event");
	ASSERT_EQ(skel->bss->bad_page_state, -1UL, "bad page state");
	ASSERT_EQ(skel->bss->neg_memory_event, -1UL, "negative memory event");
	ASSERT_EQ(skel->bss->neg_vm_event, -1UL, "negative vm event");
}

static void test_memory_events(struct memcg_kfuncs *skel)
{
	unsigned long cur, val;
	char buf[64];
	int fd;

	if (!ASSERT_OK(read_memcg_ulong("memory.current", &cur), "memory.current"))
		return;

	/*
	 * Push the cgroup over memory.high to raise MEMCG_HIGH. Every charge
	 * above the limit reclaims, so only overshoot it slightly.
	 */
	snprintf(buf, sizeof(buf), "%lu", cur + HIGH_HEADROOM);
	if (!ASSERT_OK(write_cgroup_file(CG_PATH, "memory.high", buf), "set memory.high"))
		return;
	fd = alloc_pagecache_or_skip(2 * HIGH_HEADROOM);
	write_cgroup_file(CG_PATH, "memory.high", "max");
	if (fd < 0)
		return;

	if (run_prog(skel->progs.memcg_query))
		goto out;

	ASSERT_GT(skel->bss->ev_high, 0, "high event raised");

	if (ASSERT_OK(read_memory_event("low", &val), "read low"))
		ASSERT_EQ(skel->bss->ev_low, val, "low");
	if (ASSERT_OK(read_memory_event("high", &val), "read high"))
		ASSERT_EQ(skel->bss->ev_high, val, "high");
	if (ASSERT_OK(read_memory_event("max", &val), "read max"))
		ASSERT_EQ(skel->bss->ev_max, val, "max");
	if (ASSERT_OK(read_memory_event("oom", &val), "read oom"))
		ASSERT_EQ(skel->bss->ev_oom, val, "oom");
	if (ASSERT_OK(read_memory_event("oom_kill", &val), "read oom_kill"))
		ASSERT_EQ(skel->bss->ev_oom_kill, val, "oom_kill");
out:
	close(fd);
}

static void test_root_memcg(struct memcg_kfuncs *skel)
{
	if (run_prog(skel->progs.root_memcg_query))
		return;

	ASSERT_GT(skel->bss->root_usage, 0, "root usage");
}

static long do_reclaim(struct memcg_kfuncs *skel, unsigned long size,
		       int swappiness)
{
	skel->bss->reclaim_size = size;
	skel->bss->reclaim_swappiness = swappiness;
	skel->bss->reclaim_ret = 0;
	if (run_prog(skel->progs.memcg_reclaim))
		return LONG_MIN;
	return skel->bss->reclaim_ret;
}

static void test_reclaim_args(struct memcg_kfuncs *skel)
{
	ASSERT_EQ(do_reclaim(skel, 0, -1), -EINVAL, "size 0");
	ASSERT_EQ(do_reclaim(skel, page_size - 1, -1), -EINVAL, "size < PAGE_SIZE");
	ASSERT_EQ(do_reclaim(skel, page_size, -2), -EINVAL, "swappiness -2");
	ASSERT_EQ(do_reclaim(skel, page_size, SWAPPINESS_ANON_ONLY + 1), -EINVAL,
		  "swappiness too large");

	ASSERT_GE(do_reclaim(skel, page_size, -1), 0, "swappiness -1");
	ASSERT_GE(do_reclaim(skel, page_size, 0), 0, "swappiness 0");
	ASSERT_GE(do_reclaim(skel, page_size, MAX_SWAPPINESS), 0, "swappiness max");
	ASSERT_GE(do_reclaim(skel, page_size, SWAPPINESS_ANON_ONLY), 0,
		  "swappiness anon only");
}

static void test_reclaim(struct memcg_kfuncs *skel)
{
	long ret = 0;
	int fd, i;

	fd = alloc_pagecache_or_skip(PAGECACHE_SIZE);
	if (fd < 0)
		return;

	/*
	 * Ask for more than one batch. The kfunc clamps the request, but
	 * reclaim may overshoot its target, so don't bound the result.
	 */
	for (i = 0; i < RECLAIM_RETRIES && ret <= 0; i++)
		ret = do_reclaim(skel, 4 * MEMCG_CHARGE_BATCH * page_size, 0);

	ASSERT_GT(ret, 0, "reclaimed");
	ASSERT_EQ(ret % page_size, 0, "reclaim page aligned");

	close(fd);
}

void test_memcg_kfuncs(void)
{
	struct memcg_kfuncs *skel = NULL;
	unsigned long cur;
	int cgroup_fd;

	page_size = sysconf(_SC_PAGESIZE);

	cgroup_fd = cgroup_setup_and_join(CG_PATH);
	if (!ASSERT_OK_FD(cgroup_fd, "cgroup_setup_and_join"))
		return;

	if (read_memcg_ulong("memory.current", &cur)) {
		fprintf(stderr, "%s:SKIP:no memory controller\n", __func__);
		test__skip();
		goto out;
	}

	skel = memcg_kfuncs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "memcg_kfuncs__open_and_load"))
		goto out;

	skel->bss->cgid = get_cgroup_id(CG_PATH);
	if (!ASSERT_NEQ(skel->bss->cgid, 0, "get_cgroup_id"))
		goto out;

	if (test__start_subtest("usage"))
		test_usage(skel);
	if (test__start_subtest("invalid_idx"))
		test_invalid_idx(skel);
	if (test__start_subtest("memory_events"))
		test_memory_events(skel);
	if (test__start_subtest("root_memcg"))
		test_root_memcg(skel);
	if (test__start_subtest("reclaim_args"))
		test_reclaim_args(skel);
	if (test__start_subtest("reclaim"))
		test_reclaim(skel);

out:
	memcg_kfuncs__destroy(skel);
	close(cgroup_fd);
	cleanup_cgroup_environment();
}

void test_memcg_kfuncs_failure(void)
{
	RUN_TESTS(memcg_kfuncs_failure);
}
