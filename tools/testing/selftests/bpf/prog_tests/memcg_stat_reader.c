// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

/*
 * memcg_stat_reader
 * =================
 * Read memory-cgroup statistics for a whole synthetic cgroup subtree TWO ways
 * and compare them:
 *
 *   (A) traditional: open+read+parse memory.stat / memory.current / memory.max
 *       for every cgroup, in userspace;
 *   (B) BPF: a single SEC("iter.s/cgroup") program walked over the subtree in
 *       DESCENDANTS_PRE order, calling the memcg kfuncs per cgroup and stashing
 *       the results in a hash map keyed by cgroup id, drained once afterwards.
 *
 * The test (a) asserts the BPF path agrees with the file path for a checked
 * field subset (correctness) and (b) reports the wall-clock cost of each path
 * reading the full ~memory.stat field set, across cgroup trees of increasing
 * size and load.
 *
 * The pass/fail result depends only on the correctness checks; the timing table
 * is an informational diagnostic captured like any other test output, i.e. shown
 * only under -v (or when the test fails), never on a normal PASS.
 */
#include <test_progs.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "cgroup_helpers.h"
#include "memcg_stat_reader.h"
#include "memcg_stat_reader.skel.h"

#define SUBTREE_ROOT	"/mcg_stat"

#define WARMUP_ITERS	3

struct cg_node {
	char rel[128];
	__u64 id;
	bool is_leaf;
};

/* Field subset the BPF prog reads matched against memory.stat by hand. */
struct file_snap {
	__u64 anon, file, shmem, file_mapped, pgfault;
	__u64 current;		/* memory.current, bytes */
	__u64 max;		/* memory.max, bytes (valid unless max_is_max) */
	__u64 full_sum;
	__u32 full_fields;
	bool max_is_max;
};

struct timing {
	double avg_us;		/* average per full-tree pass */
	double ro_avg_us;	/* BPF read()-only average (no map drain); 0 for file */
	int nodes_seen;		/* entries produced (BPF) */
	__u32 fields;		/* fields/cgroup touched (informational) */
};

static volatile __u64 sink;	/* keep the optimizer from eliding reads */
static long page_size;

static long long now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

/* ---- tree construction ------------------------------------------------- */

static struct cg_node *nodes;
static int n_nodes;
static int n_leaves;

static int add_node(const char *rel, bool is_leaf, int *keep_fd)
{
	int fd;

	fd = create_and_get_cgroup(rel);
	if (fd < 0)
		return -1;
	if (keep_fd)
		*keep_fd = fd;
	else
		close(fd);

	strncpy(nodes[n_nodes].rel, rel, sizeof(nodes[n_nodes].rel) - 1);
	nodes[n_nodes].rel[sizeof(nodes[n_nodes].rel) - 1] = '\0';
	nodes[n_nodes].id = get_cgroup_id(rel);
	nodes[n_nodes].is_leaf = is_leaf;
	if (is_leaf)
		n_leaves++;
	n_nodes++;
	return 0;
}

/* Recursively create children of @rel. @rel must already exist and be recorded. */
static int build_children(const char *rel, int fanout, int depth)
{
	/* size 128 should be enough for file path with max depth 3 is the test*/
	char child[128];
	int i;

	if (depth == 0)
		return 0;

	/* Enable memory on this interior node so its children get memory. */
	if (enable_controllers(rel, "memory"))
		return -1;

	for (i = 0; i < fanout; i++) {
		snprintf(child, sizeof(child), "%s/c%d", rel, i);
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

static int build_tree(int fanout, int depth, int *root_fd)
{
	n_nodes = 0;
	n_leaves = 0;
	nodes = calloc(tree_capacity(fanout, depth), sizeof(*nodes));
	if (!nodes)
		return -1;

	/* special handle for the leaf (0 depth) */
	if (add_node(SUBTREE_ROOT, depth == 0, root_fd))
		return -1;
	return build_children(SUBTREE_ROOT, fanout, depth);
}

/* ---- charging ---------------------------------------------------------- */

/*
 * A forked child walks the leaves, joining each and faulting in a private anon
 * region so the charge lands on that leaf, then keeps every region mapped and
 * blocks.  Interior nodes accumulate the charge hierarchically.  The child is
 * left stopped (blocked on the control pipe) so the stats are static while the
 * parent measures.
 */
static pid_t charger_pid = -1;
static int charger_ctrl[2] = { -1, -1 };

static int start_charger(size_t charge_bytes, int charge_fraction)
{
	int ready[2];
	pid_t pid;
	int i, mod;
	char c;

	if (!ASSERT_OK(pipe(ready), "pipe ready"))
		return -1;
	if (!ASSERT_OK(pipe(charger_ctrl), "pipe ctrl")) {
		close(ready[0]);
		close(ready[1]);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		ASSERT_GE(pid, 0, "fork charger");
		close(ready[0]);
		close(ready[1]);
		close(charger_ctrl[0]);
		close(charger_ctrl[1]);
		charger_ctrl[0] = charger_ctrl[1] = -1;
		return -1;
	}

	if (pid == 0) {
		/* child (assert only in the parent so it isn't printed twice) */
		int leaf_idx = 0;

		close(ready[0]);
		close(charger_ctrl[1]);

		mod = charge_fraction > 0 ? charge_fraction : 1;
		for (i = 0; i < n_nodes; i++) {
			void *p;

			if (!nodes[i].is_leaf)
				continue;
			if ((leaf_idx++ % mod) != 0)
				continue;
			/*
			 * cgroup_helpers builds paths from getpid(); in this
			 * forked child that differs from the parent that built
			 * the tree, so use the _parent (getppid()) variant to
			 * resolve the leaf under the parent's work dir.
			 */
			if (join_parent_cgroup(nodes[i].rel))
				_exit(1);
			p = mmap(NULL, charge_bytes, PROT_READ | PROT_WRITE,
				 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			if (p == MAP_FAILED)
				_exit(2);
			memset(p, 1, charge_bytes);
			/* keep p mapped so the charge persists */
		}
		/* signal ready, then block until the parent closes the pipe */
		if (write(ready[1], "x", 1) != 1)
			_exit(3);
		while (read(charger_ctrl[0], &c, 1) > 0)
			;
		_exit(0);
	}

	/* parent */
	charger_pid = pid;
	close(ready[1]);
	close(charger_ctrl[0]);
	charger_ctrl[0] = -1;

	/* wait until the child has charged every leaf */
	if (!ASSERT_EQ(read(ready[0], &c, 1), 1, "charger ready")) {
		close(ready[0]);
		return -1;
	}
	close(ready[0]);
	return 0;
}

static void stop_charger(void)
{
	int status;

	if (charger_ctrl[1] >= 0) {
		close(charger_ctrl[1]);	/* unblock the child -> it exits */
		charger_ctrl[1] = -1;
	}
	if (charger_pid > 0) {
		if (waitpid(charger_pid, &status, 0) == charger_pid &&
		    (!WIFEXITED(status) || WEXITSTATUS(status) != 0))
			fprintf(stderr,
				"charger child exited abnormally (status=0x%x)\n",
				status);
		charger_pid = -1;
	}
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
		o->full_sum += val;
		o->full_fields++;
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

static int file_read_node(const char *rel, struct file_snap *o)
{
	char buf[8192];

	memset(o, 0, sizeof(*o));

	if (read_cgroup_file(rel, "memory.stat", buf, sizeof(buf)))
		return -1;
	parse_stat(buf, o);

	if (!read_cgroup_file(rel, "memory.current", buf, sizeof(buf)))
		o->current = strtoull(buf, NULL, 10);
	if (!read_cgroup_file(rel, "memory.max", buf, sizeof(buf))) {
		if (!strncmp(buf, "max", 3))
			o->max_is_max = true;
		else
			o->max = strtoull(buf, NULL, 10);
	}
	return 0;
}

static void time_file(int iters, struct timing *res)
{
	long long total = 0;
	struct file_snap s;
	int it, i;

	for (it = 0; it < WARMUP_ITERS; it++)
		for (i = 0; i < n_nodes; i++)
			file_read_node(nodes[i].rel, &s);

	for (it = 0; it < iters; it++) {
		long long t0 = now_ns();

		for (i = 0; i < n_nodes; i++) {
			file_read_node(nodes[i].rel, &s);
			sink += s.anon + s.full_sum;
		}
		total += now_ns() - t0;
	}
	res->avg_us = (double)total / iters / 1000.0;
	res->fields = s.full_fields;
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

static int drain_map(int mfd, struct memcg_stat_snapshot *out, int max)
{
	__u64 key = 0, next;
	int n = 0, err;

	err = bpf_map_get_next_key(mfd, NULL, &next);
	while (err == 0) {
		if (n < max && !bpf_map_lookup_elem(mfd, &next, &out[n])) {
			sink += out[n].anon + out[n].full_sum;
			n++;
		}
		key = next;
		err = bpf_map_get_next_key(mfd, &key, &next);
	}
	return n;
}

static void time_bpf(struct bpf_link *link, struct memcg_stat_reader *skel,
		     int iters, struct timing *res)
{
	struct memcg_stat_snapshot *tmp;
	long long total = 0, ro_total = 0;
	int mfd = bpf_map__fd(skel->maps.results);
	int it, got = 0;

	tmp = calloc(n_nodes + 8, sizeof(*tmp));
	if (!ASSERT_OK_PTR(tmp, "calloc tmp"))
		return;

	skel->bss->collect_full = 1;

	for (it = 0; it < WARMUP_ITERS; it++) {
		bpf_walk_once(link);
		drain_map(mfd, tmp, n_nodes + 8);
	}

	for (it = 0; it < iters; it++) {
		long long t0, t1, t2;

		t0 = now_ns();
		bpf_walk_once(link);
		t1 = now_ns();
		got = drain_map(mfd, tmp, n_nodes + 8);
		t2 = now_ns();

		total += t2 - t0;
		ro_total += t1 - t0;
	}

	res->avg_us = (double)total / iters / 1000.0;
	res->ro_avg_us = (double)ro_total / iters / 1000.0;
	res->nodes_seen = got;
	res->fields = tmp[0].full_fields;
	free(tmp);
}

/* ---- correctness ------------------------------------------------------- */

static void check_correctness(struct bpf_link *link,
			      struct memcg_stat_reader *skel)
{
	int mfd = bpf_map__fd(skel->maps.results);
	__u64 total_anon = 0, worst_cur_drift = 0;
	__u64 anon_tol = 4 * page_size;
	int i, anon_mism = 0, missing = 0;

	skel->bss->collect_full = 0;
	if (!ASSERT_OK(bpf_walk_once(link), "bpf walk"))
		return;

	for (i = 0; i < n_nodes; i++) {
		struct memcg_stat_snapshot b;
		__u64 cur, drift;
		struct file_snap f;

		if (bpf_map_lookup_elem(mfd, &nodes[i].id, &b)) {
			missing++;
			continue;
		}
		if (file_read_node(nodes[i].rel, &f)) {
			missing++;
			continue;
		}
		total_anon += b.anon;

		/*
		 * anon (NR_ANON_MAPPED) is rstat-flushed and, with the charger
		 * stopped, deterministic: BPF and memory.stat must agree.  The
		 * tolerance is far tighter than a units error (bytes vs pages
		 * differ by PAGE_SIZE), so a wrong-unit/wrong-field bug trips it.
		 */
		if ((b.anon > f.anon ? b.anon - f.anon : f.anon - b.anon) > anon_tol) {
			anon_mism++;
			if (anon_mism <= 5)
				fprintf(stderr,
					"anon mismatch %s: bpf=%llu file=%llu\n",
					nodes[i].rel, b.anon, f.anon);
		}

		/*
		 * memory.current is the LIVE page_counter.  Both sides read the
		 * same counter, but the BPF values are captured in one fast walk
		 * while the files are read across the whole (much longer) loop,
		 * so any difference is time skew on a moving counter, not a BPF
		 * bug -- track it as informational only.
		 */
		cur = b.usage_pages * page_size;
		drift = cur > f.current ? cur - f.current : f.current - cur;
		if (drift > worst_cur_drift)
			worst_cur_drift = drift;
	}

	ASSERT_EQ(missing, 0, "all cgroups present in map");
	ASSERT_EQ(anon_mism, 0, "bpf vs file anon (rstat-flushed)");
	ASSERT_GT(total_anon, 0, "tree charged some anon");
	printf("max memory.current drift bpf-vs-file: %llu bytes (live counter, read across the walk window)\n",
	       worst_cur_drift);
}

/* ---- one case ---------------------------------------------------------- */

struct testcase {
	const char *name;
	int fanout;
	int depth;
	size_t charge_bytes;
	int charge_fraction;	/* charge every Nth leaf; 1 = all */
	int iters;
};

static void run_case(const struct testcase *tc)
{
	struct timing f = {}, b = {};
	struct memcg_stat_reader *skel = NULL;
	struct bpf_link *link = NULL;
	int root_fd = -1;
	int charged;

	if (!ASSERT_OK(build_tree(tc->fanout, tc->depth, &root_fd), "build tree"))
		goto out;

	if (start_charger(tc->charge_bytes, tc->charge_fraction))
		goto out;

	skel = memcg_stat_reader__open();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		goto out;
	if (!ASSERT_OK(bpf_map__set_max_entries(skel->maps.results, n_nodes + 8),
		       "set max_entries"))
		goto out;
	if (!ASSERT_OK(memcg_stat_reader__load(skel), "skel load"))
		goto out;

	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo = {};

	linfo.cgroup.cgroup_fd = root_fd;
	linfo.cgroup.order = BPF_CGROUP_ITER_DESCENDANTS_PRE;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.cgroup_memcg_stat_reader,
					&opts);
	if (!ASSERT_OK_PTR(link, "attach iter"))
		goto out;

	check_correctness(link, skel);

	time_file(tc->iters, &f);
	time_bpf(link, skel, tc->iters, &b);

	charged = tc->charge_fraction > 0 ?
		  (n_leaves + tc->charge_fraction - 1) / tc->charge_fraction :
		  n_leaves;

	/*
	 * Informational timing diagnostic: captured like any test output, so it
	 * is shown under -v or on failure but not on a normal PASS.  The pass/fail
	 * verdict is decided solely by the correctness checks, never by these
	 * numbers.
	 */
	printf("\n==== memcg_stat_reader: %s ====\n", tc->name);
	printf("tree: nodes=%d leaves=%d charged_leaves=%d fanout=%d depth=%d charge=%zuKB/leaf iters=%d\n",
	       n_nodes, n_leaves, charged, tc->fanout, tc->depth,
	       tc->charge_bytes >> 10, tc->iters);
	printf("all times in us (average per full-tree pass, full memory.stat field set); ro = bpf read()-only (no map drain)\n");
	printf("file_avg=%.1f  bpf_avg=%.1f  bpf_ro=%.1f  speedup(file/bpf)=%.2fx\n",
	       f.avg_us, b.avg_us, b.ro_avg_us,
	       b.avg_us > 0 ? f.avg_us / b.avg_us : 0.0);
	printf("per-cgroup: file avg=%.0f ns  bpf avg=%.0f ns\n",
	       f.avg_us * 1000.0 / n_nodes, b.avg_us * 1000.0 / n_nodes);
	printf("fields/cgroup: bpf=%u | file stat lines=%u\n", b.fields, f.fields);
	printf("bpf entries produced: %d (expected %d)\n", b.nodes_seen, n_nodes);

	ASSERT_EQ(b.nodes_seen, n_nodes, "bpf visited whole subtree");

out:
	bpf_link__destroy(link);
	memcg_stat_reader__destroy(skel);
	if (root_fd >= 0)
		close(root_fd);
	stop_charger();		/* reap charger so leaves become empty */

	/*
	 * Remove the subtree in reverse creation order.  Nodes are recorded in
	 * DFS pre-order (a parent precedes all its descendants), so iterating
	 * backwards removes every child before its parent.
	 */
	if (nodes) {
		int i;

		for (i = n_nodes - 1; i >= 0; i--)
			remove_cgroup(nodes[i].rel);
		free(nodes);
		nodes = NULL;
	}
}

static const struct testcase cases[] = {
	{ "small",       4, 2, 256 << 10, 1,  200 },
	{ "medium",     10, 2, 256 << 10, 1,   50 },
	{ "large",      10, 3, 256 << 10, 1,   10 },
	{ "large_sparse", 10, 3, 256 << 10, 8, 10 },
};

/*
 * The memcg kfuncs the BPF program relies on (bpf_get_mem_cgroup et al.) are
 * built only with CONFIG_MEMCG (mm/bpf_memcontrol.c).  On a kernel without it
 * they are absent from vmlinux BTF and the program fails to load, so probe for
 * one of them and skip cleanly rather than reporting a spurious failure.
 */
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

void test_memcg_stat_reader(void)
{
	int i;

	if (!memcg_kfuncs_available()) {
		test__skip();
		return;
	}

	page_size = sysconf(_SC_PAGESIZE);

	if (!ASSERT_OK(setup_cgroup_environment(), "setup cgroup env"))
		return;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		if (!test__start_subtest(cases[i].name))
			continue;
		run_case(&cases[i]);
	}

	cleanup_cgroup_environment();
}
