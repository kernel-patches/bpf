// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * memcg_stat_cross_cpu
 * ====================
 * A memory-cgroup statistics correctness test.  It compares the memcg
 * statistics read through the BPF memcg kfuncs against what userspace reads
 * from memory.stat, over a whole cgroup tree that has been charged across many
 * CPUs.  Where a plain kfunc smoke test only checks that a single cgroup's
 * values are non-zero, this test checks the values are actually correct and
 * that a cross-CPU rstat flush aggregates every per-CPU slice.
 *
 * The BPF reader and the file reader are run in two separate rounds, each on
 * its own freshly built and charged tree:
 *
 *   round 1: build the subtree; fork one process per leaf that charges the leaf
 *            across K CPUs and then blocks holding the charge; walk the tree
 *            with a SEC("iter.s/cgroup") program that flushes and reads each
 *            cgroup via the memcg kfuncs into a hash map; record one snapshot
 *            per node; clean the tree.
 *   round 2: build and charge an identical tree the same way, then read every
 *            cgroup's memory.stat / memory.current from userspace.
 *
 * The correctness is ensured as follows: each leaf was charged a known amount
 * of anon spread over K CPUs, so the flushed anon must be at least that amount,
 * and the subtree root's recursive anon must equal the sum of the leaves' anon.
 *
 * The charging children are CPU-pinning and there is one per leaf.
 */
#define _GNU_SOURCE

#include <linux/limits.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "kselftest.h"
#include "cgroup_util.h"
#include "memcg_stat_cross_cpu.h"
#include "memcg_stat_cross_cpu.skel.h"

#define SUBTREE_NAME "mcg_xcpu"

static char root[PATH_MAX];	/* cgroup2 mount root */
static char *subtree_root;	/* <root>/mcg_xcpu, from cg_name() */

struct cg_node {
	char path[PATH_MAX];
	__u64 id;
	bool is_leaf;
};

/* Field subset parsed from memory.stat / memory.current. */
struct file_snap {
	__u64 anon, file, shmem, file_mapped, pgfault;
	__u64 current;		/* memory.current, bytes */
	__u64 max;		/* memory.max, bytes (valid unless max_is_max) */
	bool max_is_max;
};

static long page_size;

/* ---- allowed CPU set --------------------------------------------------- */

static int *cpu_list; /* ids of the CPUs this process may run on */
static int n_cpu; /* number of such CPUs */

/*
 * Collect the CPUs the test is allowed to run on.
 * Bounded by CPU_SETSIZE (1024).
 */
static int collect_cpus(void)
{
	cpu_set_t set;
	int i, want, n = 0;

	CPU_ZERO(&set);
	if (sched_getaffinity(0, sizeof(set), &set))
		return -1;
	want = CPU_COUNT(&set);
	if (want <= 0)
		return -1;
	cpu_list = calloc(want, sizeof(*cpu_list));
	if (!cpu_list)
		return -1;
	for (i = 0; i < CPU_SETSIZE && n < want; i++)
		if (CPU_ISSET(i, &set))
			cpu_list[n++] = i;
	n_cpu = n;
	return 0;
}

/* Pin the calling task to a single CPU. */
static int pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

/* ---- tree construction ------------------------------------------------- */

static struct cg_node *nodes;
static int n_nodes;
static int n_leaves;

static int add_node(const char *path, bool is_leaf, int *keep_fd)
{
	if (cg_create(path))
		return -1;
	if (keep_fd) {
		*keep_fd = open(path, O_RDONLY);
		if (*keep_fd < 0)
			return -1;
	}

	strncpy(nodes[n_nodes].path, path, sizeof(nodes[n_nodes].path) - 1);
	nodes[n_nodes].path[sizeof(nodes[n_nodes].path) - 1] = '\0';
	nodes[n_nodes].id = cg_get_id(path);
	nodes[n_nodes].is_leaf = is_leaf;
	if (is_leaf)
		n_leaves++;
	n_nodes++;
	return 0;
}

/* Recursively create children of @path. @path must already exist and be recorded. */
static int build_children(const char *path, int fanout, int depth)
{
	char child[PATH_MAX];
	int i;

	if (depth == 0)
		return 0;

	/* Enable memory on this interior node so its children get a memcg. */
	if (cg_write(path, "cgroup.subtree_control", "+memory"))
		return -1;

	for (i = 0; i < fanout; i++) {
		snprintf(child, sizeof(child), "%s/c%d", path, i);
		if (add_node(child, depth == 1, NULL))
			return -1;
		if (build_children(child, fanout, depth - 1))
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

/* The tree is arranged in the DFS order within an array */
static int build_tree(int fanout, int depth, int *root_fd)
{
	n_nodes = 0;
	n_leaves = 0;
	nodes = calloc(tree_capacity(fanout, depth), sizeof(*nodes));
	if (!nodes)
		return -1;

	if (add_node(subtree_root, depth == 0, root_fd))
		return -1;
	return build_children(subtree_root, fanout, depth);
}

/* ---- cross-CPU charge (one pinning child per leaf) --------------------- */

static pid_t *charger_pids;
static int n_chargers;
/* parent pid, for the children's PR_SET_PDEATHSIG race check */
static pid_t test_pid;
static int charge_ready[2] = { -1, -1 };	/* child -> parent "ready" barrier */
static int charge_ctrl[2] = { -1, -1 };	/* parent -> child "exit" (close to signal) */

/*
 * One charging child, dedicated to a single leaf and spread over K CPUs.  It
 * joins its leaf, maps a resident anon region, then faults the region in K
 * slices, each on a different CPU, so this leaf's rstat ends up dirty on K
 * per-cpu trees.  The region stays mapped, so the charge persists while the
 * parent reads.  After signalling readiness the child blocks (holding the
 * charge) until the parent closes the control pipe.  Never returns.
 *
 * @base is this child's starting index into cpu_list; its K CPUs are
 * (base + 0..K-1) mod n_cpu.
 */
static void charger_child(const struct cg_node *leaf, int base, int k,
			  size_t resident_bytes)
{
	size_t per, off;
	char *region;
	char c;
	int j;

	/*
	 * If the parent dies without running the cleanup that closes the control
	 * pipe -- e.g. a CI timeout SIGKILLs the whole test -- ask the kernel to
	 * SIGKILL this child too, so it can never hang as an orphan holding a
	 * charge.
	 */
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (getppid() != test_pid)
		_exit(0);

	close(charge_ready[0]);
	close(charge_ctrl[1]);

	if (cg_enter_current(leaf->path))
		_exit(1);

	region = mmap(NULL, resident_bytes, PROT_READ | PROT_WRITE,
		      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (region == MAP_FAILED)
		_exit(2);

	/*
	 * Fault the region in K slices, each on a different CPU, so the charge
	 * for this leaf is scattered across K per-cpu rstat trees.  A correct
	 * flush must gather all K slices.
	 */
	per = resident_bytes / k;
	for (j = 0; j < k; j++) {
		off = (size_t)j * per;
		if (pin_cpu(cpu_list[(base + j) % n_cpu]))
			_exit(3);
		memset(region + off, 1,
		       (j == k - 1) ? resident_bytes - off : per);
	}

	/* Ready: the charge is in place and spread across K CPUs. */
	if (write(charge_ready[1], "x", 1) != 1)
		_exit(4);
	close(charge_ready[1]);

	/* Hold the charge (region stays mapped) until the parent tells
	 * us to exit by closing the control pipe.
	 */
	while (read(charge_ctrl[0], &c, 1) > 0)
		;

	munmap(region, resident_bytes);
	_exit(0);
}

/*
 * Fork one charging child per leaf, each spread over K CPUs.  Returns 0 once
 * every child has charged its leaf and is holding the charge, so the tree is
 * under a steady, quiesced load.  On failure the caller's cleanup path calls
 * stop_chargers().
 */
static int start_chargers(int cpus_per_leaf, size_t resident_bytes)
{
	int k_eff, i, h = 0;

	k_eff = (cpus_per_leaf > 0 && cpus_per_leaf <= n_cpu) ? cpus_per_leaf :
								n_cpu;

	if (pipe(charge_ready) || pipe(charge_ctrl)) {
		ksft_print_msg("pipe: %s\n", strerror(errno));
		return -1;
	}

	charger_pids = calloc(n_leaves, sizeof(*charger_pids));
	if (!charger_pids) {
		ksft_print_msg("calloc charger_pids failed\n");
		return -1;
	}

	/* recorded before the fork so each child can PR_SET_PDEATHSIG against us */
	test_pid = getpid();

	for (i = 0; i < n_nodes; i++) {
		pid_t pid;

		if (!nodes[i].is_leaf)
			continue;

		pid = fork();
		if (pid < 0) {
			ksft_print_msg("fork charger: %s\n", strerror(errno));
			return -1;
		}
		if (pid == 0)
			charger_child(&nodes[i], h * k_eff, k_eff,
				      resident_bytes);

		charger_pids[n_chargers++] = pid;
		h++;
	}

	/* parent: keeps only the ready-read end and the ctrl-write end */
	close(charge_ready[1]);
	charge_ready[1] = -1;
	close(charge_ctrl[0]);
	charge_ctrl[0] = -1;

	/* wait until every child has charged its leaf and is holding it */
	for (i = 0; i < n_chargers; i++) {
		char c;
		ssize_t r = read(charge_ready[0], &c, 1);

		if (r != 1) {
			ksft_print_msg("charger exited before ready (setup failed?)\n");
			return -1;
		}
	}
	return 0;
}

static void stop_chargers(void)
{
	int i, status;

	/* closing the ctrl write end unblocks every child -> they munmap + exit */
	if (charge_ctrl[1] >= 0) {
		close(charge_ctrl[1]);
		charge_ctrl[1] = -1;
	}
	if (charge_ctrl[0] >= 0) {
		close(charge_ctrl[0]);
		charge_ctrl[0] = -1;
	}
	if (charge_ready[0] >= 0) {
		close(charge_ready[0]);
		charge_ready[0] = -1;
	}
	if (charge_ready[1] >= 0) {
		close(charge_ready[1]);
		charge_ready[1] = -1;
	}

	for (i = 0; i < n_chargers; i++) {
		if (!charger_pids || charger_pids[i] <= 0)
			continue;
		if (waitpid(charger_pids[i], &status, 0) == charger_pids[i] &&
		    (!WIFEXITED(status) || WEXITSTATUS(status) != 0))
			ksft_print_msg("charger %d exited abnormally (status=0x%x)\n",
				       charger_pids[i], status);
	}

	free(charger_pids);
	charger_pids = NULL;
	n_chargers = 0;
}

/* ---- file (traditional) reader ----------------------------------------- */

static void parse_stat(char *buf, struct file_snap *o)
{
	char *save, *line;

	for (line = strtok_r(buf, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		unsigned long long val;
		char name[64];

		if (sscanf(line, "%63s %llu", name, &val) != 2)
			continue;
		if (!strcmp(name, "anon"))
			o->anon = val;
		else if (!strcmp(name, "file"))
			o->file = val;
		else if (!strcmp(name, "shmem"))
			o->shmem = val;
		else if (!strcmp(name, "file_mapped"))
			o->file_mapped = val;
		else if (!strcmp(name, "pgfault"))
			o->pgfault = val;
	}
}

static int file_read_node(const char *path, struct file_snap *o)
{
	char buf[8192];

	memset(o, 0, sizeof(*o));

	if (cg_read(path, "memory.stat", buf, sizeof(buf)))
		return -1;
	parse_stat(buf, o);

	if (!cg_read(path, "memory.current", buf, sizeof(buf)))
		o->current = strtoull(buf, NULL, 10);
	if (!cg_read(path, "memory.max", buf, sizeof(buf))) {
		if (!strncmp(buf, "max", 3))
			o->max_is_max = true;
		else
			o->max = strtoull(buf, NULL, 10);
	}
	return 0;
}

/* ---- BPF reader -------------------------------------------------------- */

static int bpf_walk_once(struct bpf_link *link)
{
	char buf[4096];
	ssize_t r;
	int fd;

	fd = bpf_iter_create(bpf_link__fd(link));
	if (fd < 0)
		return -1;
	while ((r = read(fd, buf, sizeof(buf))) > 0)
		;
	close(fd);
	return r == 0 ? 0 : -1;
}

/* ---- correctness comparison -------------------------------------------- */

static bool close_enough(__u64 a, __u64 b, __u64 tol)
{
	return (a > b ? a - b : b - a) <= tol;
}

/* Dump one node's bpf-vs-file stats; called when a mismatch is detected. */
static void dump_node(int i, const struct memcg_stat_snapshot *b,
		      const struct file_snap *f)
{
	ksft_print_msg("node %d bpf : anon=%llu file=%llu shmem=%llu fmapped=%llu pgfault=%llu\n",
		       i, b->anon, b->file, b->shmem, b->file_mapped, b->pgfault);
	ksft_print_msg("node %d file: anon=%llu file=%llu shmem=%llu fmapped=%llu pgfault=%llu\n",
		       i, f->anon, f->file, f->shmem, f->file_mapped, f->pgfault);
}

/*
 * Compare the BPF kfunc snapshots (round 1) against the memory.stat values
 * (round 2), node by node.  The two rounds are independent, equivalently
 * charged trees, so the flushed stats are compared within a small tolerance
 * that absorbs per-round overhead (i.e., a charging child's own stack pages).
 * A wrong unit, enum or field in the kfunc path would miss by far more.
 *
 * Two per-round checks verify the flush itself: each leaf was charged
 * resident_bytes of anon spread over K CPUs, so its flushed anon must be at
 * least that; and the root's recursive anon must equal the sum of the leaves'
 * anon (rstat propagated the charge up the tree).
 *
 * Returns 0 if every check passes, -1 otherwise.
 */
static int check_correctness(const struct memcg_stat_snapshot *bpf,
			     const struct file_snap *file, const bool *is_leaf,
			     int n, size_t resident_bytes)
{
	__u64 stat_tol = 64 * page_size;
	__u64 pgf_tol = 1024;
	__u64 broot = 0, bsum = 0, froot = 0, fsum = 0;
	int i, mism = 0, flush_bad = 0;

	for (i = 0; i < n; i++) {
		const struct memcg_stat_snapshot *b = &bpf[i];
		const struct file_snap *f = &file[i];
		__u64 bcur = b->usage_pages * page_size;

		/* kfunc path (round 1) compared with memory.stat path (round 2) */
		if (!close_enough(b->anon, f->anon, stat_tol) ||
		    !close_enough(b->file, f->file, stat_tol) ||
		    !close_enough(b->shmem, f->shmem, stat_tol) ||
		    !close_enough(b->file_mapped, f->file_mapped, stat_tol) ||
		    !close_enough(b->pgfault, f->pgfault, pgf_tol)) {
			mism++;
			dump_node(i, b, f);
		}

		/* memory.current is live (no flush) and must bound the flushed anon */
		if (b->anon == 0 || b->anon > bcur) {
			flush_bad++;
			ksft_print_msg("node %d: anon=%llu exceeds current=%llu\n",
				       i, b->anon, bcur);
		}

		/* each leaf's flush must have gathered the full cross-CPU charge */
		if (is_leaf[i]) {
			if (b->anon < resident_bytes || f->anon < resident_bytes) {
				flush_bad++;
				ksft_print_msg("node %d: short flush bpf=%llu file=%llu\n",
					       i, b->anon, f->anon);
			}
			bsum += b->anon;
			fsum += f->anon;
		}
		if (i == 0) { /* nodes[0] == subtree_root */
			broot = b->anon;
			froot = f->anon;
		}
	}

	if (mism) {
		ksft_print_msg("bpf (round 1) disagrees with memory.stat (round 2)\n");
		return -1;
	}
	if (flush_bad) {
		ksft_print_msg("flush did not aggregate the cross-cpu charge\n");
		return -1;
	}
	if (broot != bsum || froot != fsum) {
		ksft_print_msg("root anon != sum of leaf anon: bpf %llu/%llu file %llu/%llu\n",
			       broot, bsum, froot, fsum);
		return -1;
	}
	if (bsum == 0) {
		ksft_print_msg("tree carries no anon\n");
		return -1;
	}
	return 0;
}

/* ---- one case ---------------------------------------------------------- */

struct testcase {
	const char *name;
	int fanout;
	int depth;
	int cpus_per_leaf; /* K: CPUs each leaf is charged on; 0 = all CPUs */
	size_t resident_bytes; /* anon charged per leaf */
};

/*
 * Remove the subtree in reverse creation order.  Nodes are recorded in DFS
 * order (a parent precedes all its descendants), so iterating backwards
 * removes every child before its parent.
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
}

/*
 * Round 1: build and charge a fresh tree, walk it with the BPF iterator (which
 * flushes and reads each cgroup via the memcg kfuncs), and capture one snapshot
 * per node into @snap.  @is_leaf records the tree shape so the later comparison
 * can run after the tree is gone.  Returns the node count, or -1 on failure.
 * The tree is always torn down before returning.
 */
static int capture_bpf_round(const struct testcase *tc,
			     struct memcg_stat_snapshot *snap, bool *is_leaf)
{
	struct memcg_stat_cross_cpu *skel = NULL;
	struct bpf_link *link = NULL;
	int root_fd = -1, ret = -1, i, mfd;

	if (build_tree(tc->fanout, tc->depth, &root_fd)) {
		ksft_print_msg("build tree (bpf) failed\n");
		goto out;
	}
	if (start_chargers(tc->cpus_per_leaf, tc->resident_bytes))
		goto out;

	skel = memcg_stat_cross_cpu__open();
	if (!skel) {
		ksft_print_msg("skel open failed\n");
		goto out;
	}
	if (bpf_map__set_max_entries(skel->maps.results, n_nodes + 8)) {
		ksft_print_msg("set max_entries failed\n");
		goto out;
	}
	if (memcg_stat_cross_cpu__load(skel)) {
		ksft_print_msg("skel load failed\n");
		goto out;
	}

	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo = {};

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

	/* bpf walk through the cgroup tree and fetch result */
	if (bpf_walk_once(link)) {
		ksft_print_msg("bpf walk failed\n");
		goto out;
	}

	mfd = bpf_map__fd(skel->maps.results);
	for (i = 0; i < n_nodes; i++) {
		/* Save the position for the leaf, used for later correctness check */
		is_leaf[i] = nodes[i].is_leaf;
		if (bpf_map_lookup_elem(mfd, &nodes[i].id, &snap[i])) {
			ksft_print_msg("map lookup failed for node %d\n", i);
			goto out;
		}
	}
	ret = n_nodes;
out:
	bpf_link__destroy(link);
	memcg_stat_cross_cpu__destroy(skel);
	if (root_fd >= 0)
		close(root_fd);
	stop_chargers();
	destroy_tree();
	return ret;
}

/*
 * Round 2: build and charge an identical fresh tree, then read every cgroup via
 * memory.stat / memory.current.  The tree is reset after bpf read, so each
 * read does a real rstat flush.  Returns the node count, or -1 on failure.
 * The tree is always clear before returning.
 */
static int capture_file_round(const struct testcase *tc, struct file_snap *snap)
{
	int root_fd = -1, ret = -1, i;

	if (build_tree(tc->fanout, tc->depth, &root_fd)) {
		ksft_print_msg("build tree (file) failed\n");
		goto out;
	}
	if (start_chargers(tc->cpus_per_leaf, tc->resident_bytes))
		goto out;

	for (i = 0; i < n_nodes; i++)
		if (file_read_node(nodes[i].path, &snap[i])) {
			ksft_print_msg("file read failed for node %d\n", i);
			goto out;
		}
	ret = n_nodes;
out:
	if (root_fd >= 0)
		close(root_fd);
	stop_chargers();
	destroy_tree();
	return ret;
}

static int run_case(const struct testcase *tc)
{
	struct memcg_stat_snapshot *bpf = NULL;
	struct file_snap *file = NULL;
	bool *is_leaf = NULL;
	size_t cap = tree_capacity(tc->fanout, tc->depth);
	int nb, nf, ret = KSFT_FAIL;

	bpf = calloc(cap, sizeof(*bpf));
	file = calloc(cap, sizeof(*file));
	is_leaf = calloc(cap, sizeof(*is_leaf));
	if (!bpf || !file || !is_leaf) {
		ksft_print_msg("calloc failed\n");
		goto out;
	}

	ksft_print_msg("%s: fanout=%d depth=%d cpus=%d/%d resident=%zuKB/leaf\n",
		       tc->name, tc->fanout, tc->depth, n_cpu, tc->cpus_per_leaf,
		       tc->resident_bytes >> 10);

	/* round 1: BPF reader flushes and reads its own charged tree */
	nb = capture_bpf_round(tc, bpf, is_leaf);
	if (nb < 0)
		goto out;

	/* round 2: file reader flushes and reads a fresh, equivalent tree */
	nf = capture_file_round(tc, file);
	if (nf < 0)
		goto out;

	if (nb != nf) {
		ksft_print_msg("node count differs between rounds: %d vs %d\n",
			       nb, nf);
		goto out;
	}

	if (!check_correctness(bpf, file, is_leaf, nb, tc->resident_bytes))
		ret = KSFT_PASS;
out:
	free(bpf);
	free(file);
	free(is_leaf);
	return ret;
}

static const struct testcase cases[] = {
	/* name, fan, depth, K, resident anon */
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
	ksft_set_plan(ARRAY_SIZE(cases));

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

	if (collect_cpus())
		ksft_exit_skip("cannot read CPU affinity\n");

	page_size = sysconf(_SC_PAGESIZE);
	subtree_root = cg_name(root, SUBTREE_NAME);
	if (!subtree_root)
		ksft_exit_skip("cannot build subtree root path\n");

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		switch (run_case(&cases[i])) {
		case KSFT_PASS:
			ksft_test_result_pass("%s\n", cases[i].name);
			break;
		case KSFT_SKIP:
			ksft_test_result_skip("%s\n", cases[i].name);
			break;
		default:
			ksft_test_result_fail("%s\n", cases[i].name);
			break;
		}
	}

	free(cpu_list);
	cpu_list = NULL;
	n_cpu = 0;

	ksft_finished();
}
