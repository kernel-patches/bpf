// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Compare the memcg BPF kfuncs with memory.stat over a cgroup subtree whose
 * charge is scattered across many CPUs.
 *
 * One child per leaf faults a region on K different CPUs and holds it, then the
 * subtree is read by a SEC("iter.s/cgroup") program and from memory.stat.  The
 * two readers must return the same values, which checks the readers.  The flush
 * is checked by two invariants: each leaf's anon covers the charge it holds, and
 * the root's equals the sum of the leaves'.  Comparing the readers cannot check
 * the flush, because a flush clears the pending-update count the next one is
 * gated on, so the second reader returns what the first one left.
 *
 * The comparison is exact, which needs the subtree quiesced: only this test's
 * children charge it, and they block once their memory is faulted in.  Global
 * reclaim would move the numbers and the test would report a mismatch.
 * file, shmem and file_mapped are 0 under this workload; they are compared to
 * keep the field set complete, not because the workload produces them.
 */
#define _GNU_SOURCE

#include <linux/limits.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "kselftest.h"
#include "cgroup_util.h"
#include "memcg_stat_cross_cpu.h"
#include "memcg_stat_cross_cpu.skel.h"

#define SUBTREE_NAME		"mcg_xcpu"

#define MEMCG_CHARGE_BATCH	64

#define FLUSH_MARGIN		4

#define CHARGE_WAIT_RETRIES	100

static char root[PATH_MAX];
static char *subtree_root;
static long page_size;

/* Values parsed from memory.stat / memory.current, in bytes. */
struct file_snap {
	long anon, file, shmem, file_mapped, pgfault;
	long current;
};

struct cg_node {
	char path[PATH_MAX];
	unsigned long long id;
	bool is_leaf;			/* holds a charge of its own */
	struct memcg_stat_snapshot bpf;	/* read through the kfuncs */
	struct file_snap file;		/* read from memory.stat */
};

static struct cg_node *nodes;	/* DFS order: a parent precedes its children */
static int n_nodes;
static int n_leaves;

/* ---- CPUs this test may run on ----------------------------------------- */

static cpu_set_t allowed_cpus;
static int n_cpu;

static int nth_cpu(int n)
{
	int i, seen = 0;

	for (i = 0; i < CPU_SETSIZE; i++) {
		if (!CPU_ISSET(i, &allowed_cpus))
			continue;
		if (seen++ == n % n_cpu)
			return i;
	}
	return -1;
}

static int pin_cpu(int cpu)
{
	cpu_set_t set;

	if (cpu < 0)
		return -1;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

/* ---- tree construction -------------------------------------------------- */

static int add_node(const char *path, bool is_leaf)
{
	struct cg_node *n = &nodes[n_nodes];

	if (cg_create(path))
		return -1;

	strncpy(n->path, path, sizeof(n->path) - 1);
	n->id = cg_get_id(path);
	n->is_leaf = is_leaf;
	if (is_leaf)
		n_leaves++;
	n_nodes++;
	return 0;
}

/* Create # @levels more levels below @path.
 * Only the last level is charged.
 */
static int build_children(const char *path, int fanout, int levels)
{
	char child[PATH_MAX];
	int i;

	if (levels == 0)
		return 0;

	/* Enable memory on this interior node so its children get a memcg. */
	if (cg_write(path, "cgroup.subtree_control", "+memory"))
		return -1;

	for (i = 0; i < fanout; i++) {
		snprintf(child, sizeof(child), "%s/c%d", path, i);
		if (add_node(child, levels == 1))
			return -1;
		if (build_children(child, fanout, levels - 1))
			return -1;
	}
	return 0;
}

static size_t tree_capacity(int fanout, int depth)
{
	size_t total = 1, level = 1;
	int d;

	for (d = 0; d < depth; d++) {
		level *= fanout;
		total += level;
	}
	return total;
}

static int build_tree(int fanout, int depth, int *root_fd)
{
	n_nodes = 0;
	n_leaves = 0;
	nodes = calloc(tree_capacity(fanout, depth), sizeof(*nodes));
	if (!nodes)
		return -1;

	if (add_node(subtree_root, depth == 0))
		return -1;

	*root_fd = open(subtree_root, O_RDONLY);
	if (*root_fd < 0)
		return -1;

	return build_children(subtree_root, fanout, depth);
}

/*
 * Remove in reverse creation order, so a child always goes before its parent.
 * cg_destroy() kills the charging children; reap them afterwards.
 */
static void destroy_tree(void)
{
	int i;

	if (!nodes)
		return;

	for (i = n_nodes - 1; i >= 0; i--)
		cg_destroy(nodes[i].path);
	free(nodes);
	nodes = NULL;

	while (waitpid(-1, NULL, 0) > 0)
		;
}

/* ---- cross-CPU charge (one child per leaf) ------------------------------ */

struct charge_args {
	size_t bytes;	/* anon this leaf holds */
	int base;	/* index of the first CPU to fault on */
	int k;		/* CPUs to spread the charge over */
};

static int charge_leaf(const char *cgroup, void *arg)
{
	const struct charge_args *ca = arg;
	int ppid = getppid();
	size_t per, off;
	char *buf;
	int j;

	buf = malloc(ca->bytes);
	if (!buf) {
		fprintf(stderr, "malloc() failed\n");
		return -1;
	}

	/* Whole pages, or several slices would share one page and one CPU. */
	per = ca->bytes / ca->k / page_size * page_size;

	for (j = 0; j < ca->k; j++) {
		off = (size_t)j * per;
		if (pin_cpu(nth_cpu(ca->base + j))) {
			free(buf);
			return -1;
		}
		cg_touch_pages(buf + off,
			       j == ca->k - 1 ? ca->bytes - off : per);
	}

	while (getppid() == ppid)
		sleep(1);

	free(buf);
	return 0;
}

static size_t leaf_charge(size_t want, int k)
{
	long online = sysconf(_SC_NPROCESSORS_ONLN);
	size_t floor;

	floor = (size_t)FLUSH_MARGIN * MEMCG_CHARGE_BATCH * online *
		page_size / n_leaves;
	if (want < floor)
		want = floor;
	if (want < (size_t)k * page_size)
		want = (size_t)k * page_size;

	return (want + page_size - 1) / page_size * page_size;
}

static int start_chargers(int k, size_t bytes)
{
	struct charge_args ca = { .bytes = bytes, .k = k };
	long prev, cur;
	int i, retries;

	for (i = 0; i < n_nodes; i++) {
		if (!nodes[i].is_leaf)
			continue;
		if (cg_run_nowait(nodes[i].path, charge_leaf, &ca) < 0) {
			ksft_print_msg("cannot start a charger on %s\n",
				       nodes[i].path);
			return -1;
		}
		ca.base += k;
	}

	for (i = 0; i < n_nodes; i++) {
		if (!nodes[i].is_leaf)
			continue;
		/*
		 * Wait for the charge to both cover the region and stop
		 * moving.
		 */
		prev = -1;
		for (retries = CHARGE_WAIT_RETRIES; retries; retries--) {
			cur = cg_read_long(nodes[i].path, "memory.current");
			if (cur >= (long)bytes && cur == prev)
				break;
			prev = cur;
			usleep(DEFAULT_WAIT_INTERVAL_US / 10);
		}
		if (!retries) {
			ksft_print_msg("%s never reached its charge\n",
				       nodes[i].path);
			return -1;
		}
	}
	return 0;
}

/* ---- the two readers ---------------------------------------------------- */

/*
 * Collect what the kfuncs report.  The program flushes at the first cgroup it
 * sees, the subtree root in DESCENDANTS_PRE order.
 */
static int read_bpf(int root_fd)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct memcg_stat_cross_cpu *skel = NULL;
	union bpf_iter_link_info linfo = {};
	struct bpf_link *link = NULL;
	int ret = -1, i, mfd, fd;
	char buf[4096];
	ssize_t r;

	skel = memcg_stat_cross_cpu__open();
	if (!skel) {
		ksft_print_msg("skel open failed\n");
		return -1;
	}
	if (bpf_map__set_max_entries(skel->maps.results, n_nodes + 8)) {
		ksft_print_msg("set max_entries failed\n");
		goto out;
	}
	if (memcg_stat_cross_cpu__load(skel)) {
		ksft_print_msg("skel load failed\n");
		goto out;
	}

	linfo.cgroup.cgroup_fd = root_fd;
	linfo.cgroup.order = BPF_CGROUP_ITER_DESCENDANTS_PRE;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.cgroup_memcg_stat_cross_cpu,
					&opts);
	if (!link) {
		ksft_print_msg("attach iter failed\n");
		goto out;
	}

	fd = bpf_iter_create(bpf_link__fd(link));
	if (fd < 0) {
		ksft_print_msg("bpf_iter_create failed\n");
		goto out;
	}
	while ((r = read(fd, buf, sizeof(buf))) > 0)
		;
	close(fd);
	if (r) {
		ksft_print_msg("bpf walk failed\n");
		goto out;
	}

	mfd = bpf_map__fd(skel->maps.results);
	for (i = 0; i < n_nodes; i++)
		if (bpf_map_lookup_elem(mfd, &nodes[i].id, &nodes[i].bpf)) {
			ksft_print_msg("no map entry for %s\n", nodes[i].path);
			goto out;
		}
	ret = 0;
out:
	bpf_link__destroy(link);
	memcg_stat_cross_cpu__destroy(skel);
	return ret;
}

/* Read the same numbers from cgroupfs, on the same tree, right afterwards. */
static int read_files(void)
{
	int i;

	for (i = 0; i < n_nodes; i++) {
		const char *path = nodes[i].path;
		struct file_snap *f = &nodes[i].file;

		f->anon = cg_read_key_long(path, "memory.stat", "anon ");
		f->file = cg_read_key_long(path, "memory.stat", "file ");
		f->shmem = cg_read_key_long(path, "memory.stat", "shmem ");
		f->file_mapped = cg_read_key_long(path, "memory.stat",
						  "file_mapped ");
		f->pgfault = cg_read_key_long(path, "memory.stat", "pgfault ");
		f->current = cg_read_long(path, "memory.current");

		if (f->anon < 0 || f->file < 0 || f->shmem < 0 ||
		    f->file_mapped < 0 || f->pgfault < 0 || f->current < 0) {
			ksft_print_msg("reading the stats of %s failed\n", path);
			return -1;
		}
	}
	return 0;
}

/* ---- comparison --------------------------------------------------------- */

static void dump_node(const struct cg_node *n)
{
	ksft_print_msg("%s bpf : anon=%llu file=%llu shmem=%llu fmapped=%llu pgfault=%llu\n",
		       n->path, n->bpf.anon, n->bpf.file, n->bpf.shmem,
		       n->bpf.file_mapped, n->bpf.pgfault);
	ksft_print_msg("%s file: anon=%ld file=%ld shmem=%ld fmapped=%ld pgfault=%ld\n",
		       n->path, n->file.anon, n->file.file, n->file.shmem,
		       n->file.file_mapped, n->file.pgfault);
}

/* The subtree is quiesced, so the two readers must agree exactly. */
#define STAT_TOLERANCE_PCT	0

static int check_tree(size_t charged)
{
	unsigned long long root_anon = 0, leaf_anon = 0;
	int i, bad = 0;

	for (i = 0; i < n_nodes; i++) {
		const struct cg_node *n = &nodes[i];
		const struct memcg_stat_snapshot *b = &n->bpf;

		if (!values_close(b->anon, n->file.anon, STAT_TOLERANCE_PCT) ||
		    !values_close(b->file, n->file.file, STAT_TOLERANCE_PCT) ||
		    !values_close(b->shmem, n->file.shmem, STAT_TOLERANCE_PCT) ||
		    !values_close(b->file_mapped, n->file.file_mapped,
				  STAT_TOLERANCE_PCT) ||
		    !values_close(b->pgfault, n->file.pgfault,
				  STAT_TOLERANCE_PCT)) {
			ksft_print_msg("kfuncs disagree with memory.stat\n");
			dump_node(n);
			bad++;
		}

		/*
		 * Usage is a live page_counter read, not a flushed statistic,
		 * so it is only a bound.
		 */
		if (b->anon > b->usage_pages * (unsigned long long)page_size ||
		    n->file.anon > n->file.current) {
			ksft_print_msg("%s: anon above usage: bpf %llu/%llu file %ld/%ld\n",
				       n->path, b->anon,
				       b->usage_pages * (unsigned long long)page_size,
				       n->file.anon, n->file.current);
			bad++;
		}

		if (n->is_leaf) {
			if (b->anon < charged) {
				ksft_print_msg("%s: flushed anon %llu, charged %zu\n",
					       n->path, b->anon, charged);
				bad++;
			}
			leaf_anon += b->anon;
		}
		if (i == 0)
			root_anon = b->anon;
	}

	if (root_anon != leaf_anon) {
		ksft_print_msg("subtree root anon %llu, sum of the leaves %llu\n",
			       root_anon, leaf_anon);
		bad++;
	}
	return bad ? -1 : 0;
}

/*
 * memory.max is never set, so the counter must read PAGE_COUNTER_MAX.  That is
 * LONG_MAX on a 32-bit kernel and LONG_MAX / PAGE_SIZE elsewhere, and the width
 * of a userspace long does not tell us which, so accept either.
 */
static int check_unlimited(void)
{
	unsigned long long max64 = (unsigned long long)INT64_MAX / page_size;
	unsigned long long max32 = INT32_MAX;

	if (cg_read_strcmp(nodes[0].path, "memory.max", "max\n"))
		return 0;

	if (nodes[0].bpf.max_pages != max64 && nodes[0].bpf.max_pages != max32) {
		ksft_print_msg("memory.max reads max, kfunc reports %llu pages\n",
			       nodes[0].bpf.max_pages);
		return -1;
	}
	return 0;
}

/* ---- one case ----------------------------------------------------------- */

struct testcase {
	const char *name;
	int fanout;
	int depth;
	int cpus_per_leaf;	/* K, or 0 for every CPU */
	size_t resident_bytes;	/* anon per leaf, raised if too small */
};

static int run_case(const struct testcase *tc)
{
	int root_fd = -1, ret = KSFT_FAIL, k;
	size_t charged;

	if (build_tree(tc->fanout, tc->depth, &root_fd)) {
		ksft_print_msg("cannot build the tree\n");
		goto out;
	}

	k = tc->cpus_per_leaf;
	if (k <= 0 || k > n_cpu)
		k = n_cpu;
	charged = leaf_charge(tc->resident_bytes, k);

	ksft_print_msg("%s: %d cgroups, %d leaves, %d/%d cpus, %zuKB per leaf\n",
		       tc->name, n_nodes, n_leaves, k, n_cpu, charged >> 10);

	if (start_chargers(k, charged))
		goto out;

	/* kfuncs first: their flush is the one that has work to do */
	if (read_bpf(root_fd) || read_files())
		goto out;

	if (!check_tree(charged) && !check_unlimited())
		ret = KSFT_PASS;
out:
	if (root_fd >= 0)
		close(root_fd);
	destroy_tree();
	return ret;
}

static const struct testcase cases[] = {
	/* name, fanout, depth, K, anon per leaf */
	{ "single_cpu_small_tree", 4, 2, 1, 2 << 20 },
	{ "cross_cpu_small_tree", 4, 2, 0, 2 << 20 },
	{ "single_cpu_large_tree", 10, 3, 1, 256 << 10 },
	{ "cross_cpu_large_tree", 10, 3, 0, 256 << 10 },
};

static bool memcg_kfuncs_available(void)
{
	struct btf *btf;
	bool ok;

	btf = btf__load_vmlinux_btf();
	if (!btf)
		return false;
	ok = btf__find_by_name_kind(btf, "bpf_get_mem_cgroup", BTF_KIND_FUNC) > 0;
	btf__free(btf);
	return ok;
}

int main(int argc, char **argv)
{
	int i;

	ksft_print_header();

	/* Feature gate first: a read-only BTF probe, no privilege needed. */
	if (!memcg_kfuncs_available())
		ksft_exit_skip("memcg BPF kfuncs are not available\n");

	if (cg_find_unified_root(root, sizeof(root), NULL))
		ksft_exit_skip("cgroup v2 isn't mounted\n");

	if (cg_read_strstr(root, "cgroup.controllers", "memory"))
		ksft_exit_skip("memory controller isn't available\n");

	if (cg_read_strstr(root, "cgroup.subtree_control", "memory"))
		if (cg_write(root, "cgroup.subtree_control", "+memory"))
			ksft_exit_skip("Failed to set memory controller\n");

	CPU_ZERO(&allowed_cpus);
	if (sched_getaffinity(0, sizeof(allowed_cpus), &allowed_cpus))
		ksft_exit_skip("cannot read CPU affinity\n");
	n_cpu = CPU_COUNT(&allowed_cpus);
	if (n_cpu <= 0)
		ksft_exit_skip("no CPU to run on\n");

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		page_size = BUF_SIZE;

	subtree_root = cg_name(root, SUBTREE_NAME);
	if (!subtree_root)
		ksft_exit_skip("cannot build subtree root path\n");

	/* Set the plan only once nothing can skip the whole run any more. */
	ksft_set_plan(ARRAY_SIZE(cases));

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		switch (run_case(&cases[i])) {
		case KSFT_PASS:
			ksft_test_result_pass("%s\n", cases[i].name);
			break;
		default:
			ksft_test_result_fail("%s\n", cases[i].name);
			break;
		}
	}

	free(subtree_root);
	ksft_finished();
}
