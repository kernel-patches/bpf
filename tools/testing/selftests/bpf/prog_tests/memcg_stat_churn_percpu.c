// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * memcg_stat_churn_percpu
 * =======================
 * A CPU-spread variant of memcg_stat_churn.  It measures the same two whole-tree
 * memcg-stat readers -- the traditional per-cgroup memory.stat parse and a single
 * SEC("iter.s/cgroup") BPF walk -- under continuous allocation churn, but this
 * time each churned cgroup is deliberately dirtied on MANY CPUs at once:
 *
 *   - Build a synthetic cgroup subtree (fanout x depth), same as the reader.
 *   - Reserve one CPU for the reader and pin the reader (this parent) to it, so
 *     the timed reads run on a churn-free CPU and are not preempted by the load
 *     (measuring on a contended CPU swamps a short walk with scheduler latency).
 *   - Fork one "churner" process per hot leaf (tc->churn_leaves; 0 = all leaves,
 *     spread evenly across the tree).  Each churner joins its leaf and then, in a
 *     loop, migrates its own affinity round-robin across K CPUs
 *     (tc->cpus_per_leaf; 0 = all churner CPUs) doing one mmap()+memset()+
 *     munmap() on each.  The charge/uncharge happens on whatever CPU the task is
 *     currently running on, so cycling the affinity queues this leaf's rstat
 *     dirty on all K CPUs; those per-cpu entries persist until flushed, so
 *     between two reads the leaf ends up dirty on all K CPUs.
 *   - While the churn runs, the parent repeatedly SAMPLES both readers exactly as
 *     in memcg_stat_churn: settle_flush() then an untimed gap before each read so
 *     each read starts from exactly gap-worth of churn and pays its own flush
 *     inside the timed region; the file/BPF order is alternated.
 *
 * Why this matters: both readers flush rstat through the same
 * mem_cgroup_flush_stats() path, and the cost of that flush grows with the
 * number of (cgroup, cpu) pairs that have pending updates.  Where memcg_stat_churn
 * dirties each cgroup on essentially one CPU (a read flushes one per-cpu tree per
 * cgroup), this test makes K a first-class knob: a read of a cgroup dirtied on K
 * CPUs must visit K per-cpu trees.  Sweeping K (see the narrow/wide/widest cases)
 * drives the shared flush cost F up and compresses the file/BPF ratio, isolating
 * the effect of per-cgroup cross-CPU fan-out.  Because the reader runs on a
 * reserved, churn-free CPU, the flush cost -- not scheduler jitter -- is what the
 * timed reads capture; the ratio is robust because the flush hits both readers
 * equally.
 *
 * The BPF program, its hash map and the snapshot struct are REUSED verbatim from
 * memcg_stat_reader (progs/memcg_stat_reader.c + memcg_stat_reader.h); only the
 * userspace load model (CPU-pinned churners) and sampling loop are new here.
 *
 * Under churn the stats are a moving target, so this test does NOT do a
 * field-by-field BPF-vs-file equality check (that is memcg_stat_reader's job).
 * Pass/fail gates only on structural sanity -- the iterator visited every cgroup
 * and the tree carries some anon charge.  The timing table and final RATIO line
 * are informational diagnostics, printed like any other test output (i.e. under
 * -v or on failure, never on a normal PASS).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE		/* sched_setaffinity(), CPU_SET() (lib.mk also -D's it) */
#endif
#include <test_progs.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "cgroup_helpers.h"
#include "memcg_stat_reader.h"
#include "memcg_stat_reader.skel.h"

#define SUBTREE_ROOT	"/mcg_pcpu"

#define WARMUP_ITERS	2

struct cg_node {
	char rel[128];
	__u64 id;
	bool is_leaf;
};

/* Field subset parsed from memory.stat (mirrors memcg_stat_reader). */
struct file_snap {
	__u64 anon, file, shmem, file_mapped, pgfault;
	__u64 current;		/* memory.current, bytes */
	__u64 max;		/* memory.max, bytes (valid unless max_is_max) */
	__u64 full_sum;
	__u32 full_fields;
	bool max_is_max;
};

static volatile __u64 sink;	/* keep the optimizer from eliding reads */

static long long now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

/* ---- allowed CPU set --------------------------------------------------- */

static int *cpu_list;		/* ids of the CPUs this process may run on */
static int n_cpu;		/* number of such CPUs */
static int n_reserved;		/* CPUs held out for the reader (0 or 1) */
static int reader_cpu = -1;	/* CPU the reader is pinned to, or -1 */
static cpu_set_t orig_affinity;	/* parent's affinity, restored on exit */

/*
 * Collect the CPUs the test is allowed to run on (respecting any cpuset the
 * harness put us in).  We spawn one pinned churner per usable CPU minus the one
 * reserved for the reader.  Bounded by CPU_SETSIZE (1024); machines wider than
 * that would use only the first CPU_SETSIZE CPUs, which is fine for a diagnostic.
 */
static int collect_cpus(void)
{
	cpu_set_t set;
	int i, want, n = 0;

	CPU_ZERO(&set);
	if (sched_getaffinity(0, sizeof(set), &set))
		return -1;
	orig_affinity = set;		/* restored in test teardown */
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

/* ---- tree construction (same shape as memcg_stat_reader) --------------- */

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
	char child[128];
	int i;

	if (depth == 0)
		return 0;

	/* Enable memory on this interior node so its children get a memcg. */
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

	if (add_node(SUBTREE_ROOT, depth == 0, root_fd))
		return -1;
	return build_children(SUBTREE_ROOT, fanout, depth);
}

/* ---- churn load (migrating churners, K CPUs per hot cgroup) ------------- */

/*
 * Shared control block, mmap'd MAP_SHARED before the forks so the parent can
 * signal all churners to stop with a single write.
 */
struct churn_ctl {
	volatile int stop;
};

static struct churn_ctl *ctl;
static pid_t *churn_pids;
static int n_churners;
static int n_hot_leaves;		/* distinct cgroups (leaves) churned */
static int n_cpus_per_leaf;		/* K: CPUs each hot cgroup is dirtied on */
static int churn_ready[2] = { -1, -1 };	/* churner -> parent "ready" barrier */

/* Pin the calling task to a single CPU. */
static int pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

/*
 * One churner process, dedicated to a single hot leaf but spread over K CPUs.
 * It joins its leaf, pins a resident anon set so the tree always carries some
 * charge, signals readiness, then loops: migrate to the next of its K CPUs and
 * do one mmap()+memset()+munmap() there.  The charge/uncharge happens on
 * whatever CPU the task currently runs on, so cycling the affinity queues this
 * leaf's rstat dirty on all K CPUs; those per-cpu entries persist until flushed,
 * so between two reads the leaf ends up dirty on all K CPUs and a reader's flush
 * of the subtree must visit K per-cpu trees for this one cgroup.  Never returns.
 *
 * @base is this churner's starting index into the churner CPU pool
 * (cpu_list[n_reserved ..]); its K CPUs are (base + 0..K-1) mod pool size.
 */
static void churner_child(const struct cg_node *leaf, int base, int k,
			  size_t region_bytes, size_t resident_bytes)
{
	int c_pool = n_cpu - n_reserved;
	void *resident;
	int j = 0;

	close(churn_ready[0]);

	/*
	 * Move onto our first CPU before charging.  Children inherit the reader's
	 * reserved-CPU affinity from the parent, so without this the resident set
	 * would be charged on the reader's CPU.
	 */
	if (pin_cpu(cpu_list[n_reserved + base % c_pool]))
		_exit(4);

	/*
	 * cgroup_helpers builds paths from getpid(); in this forked child that
	 * differs from the parent that built the tree, so use the _parent
	 * (getppid()) variant to resolve the leaf under the parent's work dir.
	 */
	if (join_parent_cgroup(leaf->rel))
		_exit(1);

	resident = mmap(NULL, resident_bytes, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (resident == MAP_FAILED)
		_exit(2);
	memset(resident, 1, resident_bytes);	/* fault in, keep mapped */

	if (write(churn_ready[1], "x", 1) != 1)
		_exit(3);
	close(churn_ready[1]);	/* so a sibling's early death yields EOF, not a parent hang */

	while (!ctl->stop) {
		void *p;

		/* migrate to the next of our K CPUs, then dirty the leaf there */
		pin_cpu(cpu_list[n_reserved + (base + j) % c_pool]);
		if (++j == k)
			j = 0;

		p = mmap(NULL, region_bytes, PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (p == MAP_FAILED)
			continue;
		memset(p, 1, region_bytes);	/* fault in -> anon charge */
		munmap(p, region_bytes);	/* free -> uncharge (keeps rstat dirty) */
	}
	munmap(resident, resident_bytes);
	_exit(0);
}

/*
 * Fork one migrating churner per hot leaf (H = @churn_leaves, 0 = all leaves),
 * each spread over K CPUs (@cpus_per_leaf, 0 or > pool => all churner CPUs).
 * Hot leaves are chosen evenly across the tree.  Returns 0 once every churner
 * has joined its leaf and pinned its resident set (so measurement starts under
 * steady-state load).  On failure the caller's cleanup path calls
 * stop_churners() to reap whatever was started.
 */
static int start_churners(size_t region_bytes, size_t resident_bytes,
			  int churn_leaves, int cpus_per_leaf)
{
	int *leaf_idx = NULL, *pool = NULL;
	int n_leaf_idx = 0, pool_n = 0;
	int c_pool = n_cpu - n_reserved;	/* CPUs available to churners */
	int k_eff, i, h, ret = -1;

	/* K: CPUs each hot cgroup is dirtied on (0 or too big => all churner CPUs) */
	k_eff = (cpus_per_leaf > 0 && cpus_per_leaf < c_pool) ? cpus_per_leaf
							     : c_pool;
	n_cpus_per_leaf = k_eff;

	/* gather all leaf node indices in creation order */
	leaf_idx = calloc(n_leaves, sizeof(*leaf_idx));
	if (!ASSERT_OK_PTR(leaf_idx, "calloc leaf_idx"))
		return -1;
	for (i = 0; i < n_nodes; i++)
		if (nodes[i].is_leaf)
			leaf_idx[n_leaf_idx++] = i;

	/*
	 * H hot cgroups (one migrating churner each), spread evenly across all
	 * leaves; churn_leaves <= 0 or >= n_leaves => every leaf is hot.
	 */
	pool_n = (churn_leaves > 0 && churn_leaves < n_leaf_idx) ? churn_leaves
								: n_leaf_idx;
	pool = calloc(pool_n, sizeof(*pool));
	if (!ASSERT_OK_PTR(pool, "calloc pool")) {
		free(leaf_idx);
		return -1;
	}
	for (i = 0; i < pool_n; i++)
		pool[i] = leaf_idx[(int)((long long)i * n_leaf_idx / pool_n)];
	free(leaf_idx);
	n_hot_leaves = pool_n;

	ctl = mmap(NULL, sizeof(*ctl), PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_NEQ(ctl, MAP_FAILED, "mmap churn_ctl")) {
		ctl = NULL;
		goto out;
	}
	ctl->stop = 0;

	if (!ASSERT_OK(pipe(churn_ready), "pipe churn_ready"))
		goto out;

	churn_pids = calloc(pool_n, sizeof(*churn_pids));
	if (!ASSERT_OK_PTR(churn_pids, "calloc churn_pids"))
		goto out;

	/*
	 * One migrating churner per hot leaf.  Churner h spans the K CPUs
	 * (h*K + 0..K-1) mod c_pool of the churner pool (cpu_list[n_reserved ..]),
	 * so different churners start on different CPUs and cpu_list[0] (the
	 * reader's reserved CPU) is never used by a churner.
	 */
	for (h = 0; h < pool_n; h++) {
		const struct cg_node *leaf = &nodes[pool[h]];
		pid_t pid = fork();

		if (pid < 0) {
			ASSERT_GE(pid, 0, "fork churner");
			goto out;
		}
		if (pid == 0)
			churner_child(leaf, h * k_eff, k_eff,
				      region_bytes, resident_bytes);

		churn_pids[n_churners++] = pid;
	}

	/* parent: this end is only for the children to signal on */
	close(churn_ready[1]);
	churn_ready[1] = -1;

	/* wait until every churner has joined + pinned its resident set */
	for (h = 0; h < n_churners; h++) {
		char c;
		ssize_t r = read(churn_ready[0], &c, 1);

		if (r == 0)
			fprintf(stderr,
				"a churner exited before signaling ready (affinity/join/mmap failure?)\n");
		if (!ASSERT_EQ(r, 1, "churner ready"))
			goto out;
	}
	ret = 0;
out:
	free(pool);
	return ret;
}

static void stop_churners(void)
{
	int i, status;

	if (ctl)
		ctl->stop = 1;			/* release all churn loops */

	if (churn_ready[1] >= 0) {
		close(churn_ready[1]);
		churn_ready[1] = -1;
	}
	if (churn_ready[0] >= 0) {
		close(churn_ready[0]);
		churn_ready[0] = -1;
	}

	for (i = 0; i < n_churners; i++) {
		if (!churn_pids || churn_pids[i] <= 0)
			continue;
		if (waitpid(churn_pids[i], &status, 0) == churn_pids[i] &&
		    (!WIFEXITED(status) || WEXITSTATUS(status) != 0))
			fprintf(stderr,
				"churner %d exited abnormally (status=0x%x)\n",
				churn_pids[i], status);
	}

	free(churn_pids);
	churn_pids = NULL;
	n_churners = 0;

	if (ctl) {
		munmap((void *)ctl, sizeof(*ctl));
		ctl = NULL;
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

/*
 * Untimed whole-subtree flush used to normalise the pre-read state.  Reading the
 * subtree root's memory.stat flushes the entire subtree's rstat, so the
 * usleep(gap) that follows re-accumulates *exactly* gap-worth of churn no matter
 * what the previous timed read was.  Without this reset the accumulation window
 * would be (previous_read_duration + gap), and since a file pass is ~20x longer
 * than a BPF walk that made the flush a BPF read pays depend on ordering -- a
 * ~15% window asymmetry, enough to invert bpf_matched vs bpf_full on
 * flush-dominated cases (e.g. "hot": few cgroups churned from many CPUs).
 * nodes[0] is SUBTREE_ROOT (added first in build_tree), whose memcg covers the
 * whole tree, so one read here flushes every node the timed reads care about.
 */
static void settle_flush(void)
{
	char buf[8192];

	if (nodes && n_nodes > 0)
		read_cgroup_file(nodes[0].rel, "memory.stat", buf, sizeof(buf));
}

/*
 * One timed traditional pass over the whole tree; returns nanoseconds.  A
 * settle_flush() then an untimed @gap_us idle precede the pass so the tree
 * re-accumulates exactly gap-worth of churn first; the resulting rstat flush is
 * then paid inside the timed region, giving every read the same start state.
 */
static long long file_pass(int gap_us)
{
	struct file_snap s;
	long long t0;
	int i;

	settle_flush();
	if (gap_us)
		usleep(gap_us);
	t0 = now_ns();
	for (i = 0; i < n_nodes; i++) {
		file_read_node(nodes[i].rel, &s);
		sink += s.anon + s.full_sum;
	}
	return now_ns() - t0;
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

/*
 * One timed BPF pass: kernel walk (ro) + map drain into userspace.  Returns the
 * total nanoseconds; *ro_ns gets the walk-only time, *got the entries drained.
 * A settle_flush() then an untimed @gap_us idle precede the walk, exactly as in
 * file_pass(), so the rstat flush the walk pays reflects the same gap-worth of
 * accumulated churn regardless of read ordering.
 */
static long long bpf_pass(struct bpf_link *link, struct memcg_stat_reader *skel,
			  struct memcg_stat_snapshot *tmp,
			  long long *ro_ns, int *got, int *werr, int gap_us)
{
	int mfd = bpf_map__fd(skel->maps.results);
	long long t0, t1, t2;
	int err;

	skel->bss->collect_full = 1;

	settle_flush();
	if (gap_us)
		usleep(gap_us);
	t0 = now_ns();
	err = bpf_walk_once(link);
	t1 = now_ns();
	*got = drain_map(mfd, tmp, n_nodes + 8);
	t2 = now_ns();

	if (werr)
		*werr = err;
	*ro_ns = t1 - t0;
	return t2 - t0;
}

/* ---- structural sanity (no field-by-field check under churn) ------------ */

static void check_structural(struct bpf_link *link,
			     struct memcg_stat_reader *skel)
{
	int mfd = bpf_map__fd(skel->maps.results);
	__u64 total_anon = 0;
	int i, missing = 0;

	skel->bss->collect_full = 0;
	if (!ASSERT_OK(bpf_walk_once(link), "bpf walk"))
		return;

	for (i = 0; i < n_nodes; i++) {
		struct memcg_stat_snapshot b;

		if (bpf_map_lookup_elem(mfd, &nodes[i].id, &b)) {
			missing++;
			continue;
		}
		total_anon += b.anon;
	}

	ASSERT_EQ(missing, 0, "all cgroups present in map");
	/*
	 * The churners pin a resident anon set for the whole window, so with no
	 * swap and no ancestor memory.max forcing reclaim (the base selftest
	 * config sets neither), the tree always carries anon while churn runs.
	 */
	ASSERT_GT(total_anon, 0, "tree carries anon under churn");
}

/* ---- one case ---------------------------------------------------------- */

struct sample_acc {
	long long file_ns;
	long long bpf_ns, bpf_ro_ns;
	int last_got;
};

struct testcase {
	const char *name;
	int fanout;
	int depth;
	int churn_leaves;	/* H: # hot cgroups (one migrating churner each); 0 = all leaves */
	int cpus_per_leaf;	/* K: CPUs each hot cgroup is dirtied on; 0 = all churner CPUs */
	size_t region_bytes;	/* per-iteration churn region */
	size_t resident_bytes;	/* pinned resident set per churner */
	int samples;
	int gap_us;		/* idle before EACH read: the "staleness" knob (see cases[]) */
};

static void run_case(const struct testcase *tc)
{
	struct memcg_stat_snapshot *tmp = NULL;
	struct memcg_stat_reader *skel = NULL;
	struct bpf_link *link = NULL;
	struct sample_acc acc = {};
	double f, b, bro;
	int root_fd = -1;
	int churners = 0;
	int bad_walks = 0;
	int s, w;

	if (!ASSERT_OK(build_tree(tc->fanout, tc->depth, &root_fd), "build tree"))
		goto out;

	if (start_churners(tc->region_bytes, tc->resident_bytes,
			   tc->churn_leaves, tc->cpus_per_leaf))
		goto out;
	churners = n_churners;

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

	tmp = calloc(n_nodes + 8, sizeof(*tmp));
	if (!ASSERT_OK_PTR(tmp, "calloc tmp"))
		goto out;

	/*
	 * Authoritative completeness/correctness gate: run once on the freshly
	 * loaded (still empty) map, so missing==0 proves this walk visited every
	 * cgroup.  The map is not cleared between the later timed walks, so the
	 * end-of-loop count is only a weaker, informational cross-check.
	 */
	check_structural(link, skel);

	/* warm caches/vmstats for both paths symmetrically (same gap regime) */
	for (w = 0; w < WARMUP_ITERS; w++) {
		long long ro;
		int got;

		file_pass(tc->gap_us);
		bpf_pass(link, skel, tmp, &ro, &got, NULL, tc->gap_us);
	}

	/*
	 * Timed samples.  Every read settle_flush()es then idles tc->gap_us
	 * (untimed) first, so the tree re-accumulates exactly gap-worth of churn
	 * and each read pays its own rstat flush inside the timed region.  The
	 * file/bpf order is flipped on odd samples so any residual jitter doesn't
	 * systematically favour whichever reader runs first.
	 */
	for (s = 0; s < tc->samples; s++) {
		long long ro;
		int got, werr;

		if (s & 1) {
			acc.bpf_ns += bpf_pass(link, skel, tmp, &ro, &got, &werr, tc->gap_us);
			acc.bpf_ro_ns += ro;
			acc.last_got = got;
			bad_walks += !!werr;
			acc.file_ns += file_pass(tc->gap_us);
		} else {
			acc.file_ns += file_pass(tc->gap_us);
			acc.bpf_ns += bpf_pass(link, skel, tmp, &ro, &got, &werr, tc->gap_us);
			acc.bpf_ro_ns += ro;
			acc.last_got = got;
			bad_walks += !!werr;
		}
	}

	f   = (double)acc.file_ns   / tc->samples / 1000.0;
	b   = (double)acc.bpf_ns    / tc->samples / 1000.0;
	bro = (double)acc.bpf_ro_ns / tc->samples / 1000.0;

	/*
	 * Informational timing diagnostic (captured like any test output: shown
	 * under -v or on failure, not on a normal PASS).  The pass/fail verdict
	 * comes solely from the structural checks above.
	 */
	printf("\n==== memcg_stat_churn_percpu: %s ====\n", tc->name);
	printf("tree: nodes=%d leaves=%d hot_leaves=%d cpus_per_leaf=%d dirty_pairs=%d cpus=%d reserved=%d churners=%d fanout=%d depth=%d region=%zuKB resident=%zuKB samples=%d gap=%dms\n",
	       n_nodes, n_leaves, n_hot_leaves, n_cpus_per_leaf,
	       n_hot_leaves * n_cpus_per_leaf, n_cpu, n_reserved, churners,
	       tc->fanout, tc->depth, tc->region_bytes >> 10,
	       tc->resident_bytes >> 10, tc->samples, tc->gap_us / 1000);
	printf("each hot cgroup churned across %d CPUs (migrating churner) so a reader flush visits ~%d per-cpu trees per hot cgroup; reader pinned to reserved CPU %d\n",
	       n_cpus_per_leaf, n_cpus_per_leaf, reader_cpu);
	printf("all times in us (average per full-tree read under churn, full memory.stat field set); ratio = file/bpf; ro = bpf read()-only (no map drain)\n");
	printf("each read flushes then idles gap=%dms so every read starts from exactly gap-worth of churn; the rstat flush is counted in the read\n",
	       tc->gap_us / 1000);
	printf("file_avg=%.1f  bpf_avg=%.1f  bpf_ro=%.1f  ratio(file/bpf)=%.2fx\n",
	       f, b, bro, b > 0 ? f / b : 0.0);
	printf("per-cgroup: file avg=%.0f ns  bpf avg=%.0f ns\n",
	       f * 1000.0 / n_nodes, b * 1000.0 / n_nodes);
	printf("bpf entries produced: %d (expected %d)\n", acc.last_got, n_nodes);
	printf("RATIO (%d CPUs/cgroup): file/bpf = %.2fx\n",
	       n_cpus_per_leaf, b > 0 ? f / b : 0.0);

	ASSERT_EQ(bad_walks, 0, "all timed bpf walks completed");
	ASSERT_EQ(acc.last_got, n_nodes, "bpf visited whole subtree under churn");

out:
	free(tmp);
	bpf_link__destroy(link);
	memcg_stat_reader__destroy(skel);
	if (root_fd >= 0)
		close(root_fd);
	stop_churners();	/* reap churners so leaves become removable */

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

/*
 * gap_us: idle time inserted (untimed) before every read so the tree
 * re-accumulates a roughly fixed amount of dirty rstat first; the read then
 * pays that flush inside its timed region.  This gives all four reads
 * (file/bpf x matched/full) approximately the same start state and folds the
 * flush cost into the measured time.  It is the "staleness / poll-interval"
 * knob: larger gap -> larger common flush -> the file/bpf ratio compresses.
 * See memcg_stat_churn for the full rationale; 50 ms is a reasonable default.
 */
#define CHURN_GAP_US	(50 * 1000)

static const struct testcase cases[] = {
	/*
	 * The narrow/wide/widest trio runs on a large (1111-cgroup) tree and
	 * churns a fixed set of 64 hot leaves, sweeping only K, the number of CPUs
	 * each hot cgroup is dirtied on, to isolate per-cgroup cross-CPU flush
	 * fan-out:
	 *
	 *   narrow  - K=1  : each hot cgroup dirty on 1 CPU   (64 x 1 dirty pairs).
	 *   wide    - K=8  : each hot cgroup dirty on 8 CPUs  (64 x 8 dirty pairs).
	 *   widest  - K=all: each hot cgroup dirty on every churner CPU (64 x cpus).
	 *
	 * The hot-cgroup count (64) is identical across all three, so only the
	 * per-cgroup CPU fan-out changes.  As K grows the shared rstat flush F grows
	 * (more per-cpu trees to visit), so both readers' cost rises and the
	 * file/bpf ratio compresses toward 1; widest is the most conservative
	 * regime.  The large tree keeps the whole-tree read cost dominant over the
	 * flush/scheduler jitter, so the ratios are reproducible (a small tree makes
	 * the sub-millisecond BPF read too noisy to compare).  samples are kept even
	 * so the file/bpf order-alternation (s & 1) cancels first-mover bias; widest
	 * gets more samples as its bigger flush has more variance.
	 */
	/* name          fan dep  H   K   region      resident    samp gap */
	{ "narrow",       10,  3, 64,  1,  256 << 10,  128 << 10,    8,  CHURN_GAP_US },
	{ "wide",         10,  3, 64,  8,  256 << 10,  128 << 10,    8,  CHURN_GAP_US },
	{ "widest",       10,  3, 64,  0,  256 << 10,  128 << 10,   10,  CHURN_GAP_US },
};

/*
 * The memcg kfuncs the reused BPF program relies on (bpf_get_mem_cgroup et al.)
 * are built only with CONFIG_MEMCG (mm/bpf_memcontrol.c).  On a kernel without
 * it they are absent from vmlinux BTF and the program fails to load, so probe
 * for one and skip cleanly rather than reporting a spurious failure.
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

/*
 * Reserve one CPU for the reader (this parent) and pin the parent to it, so its
 * timed reads run on a CPU that carries no churner.  Needs at least 2 CPUs; on a
 * single-CPU host we skip reserving and the one churner shares the CPU with the
 * reader (noisier, but 1-CPU hosts are not the target).  Best-effort: if the
 * parent cannot be pinned we carry on without a reservation.
 */
static void reserve_reader_cpu(void)
{
	if (n_cpu < 2)
		return;
	if (pin_cpu(cpu_list[0]))
		return;
	n_reserved = 1;
	reader_cpu = cpu_list[0];
}

void serial_test_memcg_stat_churn_percpu(void)
{
	int i;

	if (!memcg_kfuncs_available()) {
		test__skip();
		return;
	}

	if (!ASSERT_OK(collect_cpus(), "collect cpus"))
		return;

	reserve_reader_cpu();

	if (!ASSERT_OK(setup_cgroup_environment(), "setup cgroup env"))
		goto restore;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		if (!test__start_subtest(cases[i].name))
			continue;
		run_case(&cases[i]);
	}

	cleanup_cgroup_environment();
restore:
	/* undo reserve_reader_cpu() so later test_progs tests keep full affinity */
	sched_setaffinity(0, sizeof(orig_affinity), &orig_affinity);
	free(cpu_list);
	cpu_list = NULL;
	n_cpu = 0;
	n_reserved = 0;
	reader_cpu = -1;
}
