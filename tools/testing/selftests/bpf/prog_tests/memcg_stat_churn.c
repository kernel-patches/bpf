// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * memcg_stat_churn
 * ================
 * A load variant of the memcg_stat_reader benchmark.  Where memcg_stat_reader
 * charges a quiescent tree once and then measures both readers against static
 * stats, this test keeps the memory-cgroup rstat perpetually DIRTY while it
 * measures:
 *
 *   - Build a synthetic cgroup subtree (fanout x depth), same as the reader.
 *   - Fork one "churner" process per selected leaf.  Each churner joins its
 *     leaf, pins a small resident anon set (so tree anon stays > 0), then loops
 *     mmap()+memset()+munmap() for the whole measurement window.  The constant
 *     charge/uncharge traffic keeps every touched memcg's per-cpu stats dirty,
 *     so each reader pays a realistic flush/read cost instead of a warm no-op.
 *   - While the churn runs, the parent repeatedly SAMPLES both readers:
 *       (A) traditional: open/read/parse memory.stat (+current/+max) for every
 *           cgroup from userspace;
 *       (B) BPF: one SEC("iter.s/cgroup") walk over the subtree calling the
 *           memcg kfuncs into a hash map, drained once per sample.
 *     Before each timed read the parent idles for a fixed gap (untimed) so the
 *     tree re-accumulates a roughly fixed amount of dirty rstat; every read
 *     (file/BPF x matched/full) therefore starts from approximately the same
 *     state and pays its own rstat flush inside the timed region.  The
 *     file-vs-BPF order is also alternated across samples so residual jitter
 *     doesn't systematically favour whichever reader runs first.
 *   - Times are averaged over all samples and the file/BPF speedup ratio is
 *     reported.  The gap is the "staleness / poll-interval" knob: a larger gap
 *     means a larger flush that both paths pay, so the ratio is more
 *     conservative (see CHURN_GAP_US).
 *
 * The BPF program, its hash map and the snapshot struct are REUSED verbatim
 * from memcg_stat_reader (progs/memcg_stat_reader.c + memcg_stat_reader.h); only
 * the userspace load model and sampling loop are new here.
 *
 * Under churn the stats are a moving target, so this test does NOT do a
 * field-by-field BPF-vs-file equality check (that is memcg_stat_reader's job).
 * Pass/fail gates only on structural sanity -- the iterator visited every
 * cgroup and the tree carries some anon charge.  The timing table and final
 * RATIO line are informational diagnostics, printed like any other test output
 * (i.e. under -v or on failure, never on a normal PASS).
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

#define SUBTREE_ROOT	"/mcg_churn"

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

/* ---- churn load -------------------------------------------------------- */

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
static int churn_ready[2] = { -1, -1 };	/* churner -> parent "ready" barrier */

/*
 * One churner process.  Joins its leaf, pins a resident anon set so the tree
 * always carries some charge, signals readiness, then continuously faults in
 * and frees a private anon region until told to stop.  Never returns.
 */
static void churner_child(const struct cg_node *leaf, size_t region_bytes,
			  size_t resident_bytes)
{
	void *resident;

	close(churn_ready[0]);

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
		void *p = mmap(NULL, region_bytes, PROT_READ | PROT_WRITE,
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
 * Fork one churner per @charge_fraction-th leaf.  Returns 0 once every churner
 * has joined its leaf and pinned its resident set (so measurement starts under
 * steady-state load).  On failure the caller's cleanup path calls
 * stop_churners() to reap whatever was started.
 */
static int start_churners(size_t region_bytes, size_t resident_bytes,
			  int charge_fraction)
{
	int mod = charge_fraction > 0 ? charge_fraction : 1;
	int leaf_idx = 0;
	int i;

	ctl = mmap(NULL, sizeof(*ctl), PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_NEQ(ctl, MAP_FAILED, "mmap churn_ctl")) {
		ctl = NULL;
		return -1;
	}
	ctl->stop = 0;

	if (!ASSERT_OK(pipe(churn_ready), "pipe churn_ready"))
		return -1;

	churn_pids = calloc(n_leaves, sizeof(*churn_pids));
	if (!ASSERT_OK_PTR(churn_pids, "calloc churn_pids"))
		return -1;

	for (i = 0; i < n_nodes; i++) {
		pid_t pid;

		if (!nodes[i].is_leaf)
			continue;
		if ((leaf_idx++ % mod) != 0)
			continue;

		pid = fork();
		if (pid < 0) {
			ASSERT_GE(pid, 0, "fork churner");
			return -1;
		}
		if (pid == 0)
			churner_child(&nodes[i], region_bytes, resident_bytes);

		churn_pids[n_churners++] = pid;
	}

	/* parent: this end is only for the children to signal on */
	close(churn_ready[1]);
	churn_ready[1] = -1;

	/* wait until every churner has joined + pinned its resident set */
	for (i = 0; i < n_churners; i++) {
		char c;
		ssize_t r = read(churn_ready[0], &c, 1);

		if (r == 0)
			fprintf(stderr,
				"a churner exited before signaling ready (join_parent_cgroup/mmap failure?)\n");
		if (!ASSERT_EQ(r, 1, "churner ready"))
			return -1;
	}
	return 0;
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
 * One timed traditional pass over the whole tree; returns nanoseconds.
 * @gap_us idles (untimed) before the pass so the tree re-accumulates a roughly
 * fixed amount of churn first; the resulting rstat flush is then paid inside the
 * timed region, giving every read approximately the same start state.
 */
static long long file_pass(int gap_us)
{
	struct file_snap s;
	long long t0;
	int i;

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
 * @gap_us idles (untimed) before the walk, exactly as in file_pass(), so the
 * per-node rstat flush the walk pays reflects the same accumulated churn.
 */
static long long bpf_pass(struct bpf_link *link, struct memcg_stat_reader *skel,
			  struct memcg_stat_snapshot *tmp,
			  long long *ro_ns, int *got, int *werr, int gap_us)
{
	int mfd = bpf_map__fd(skel->maps.results);
	long long t0, t1, t2;
	int err;

	skel->bss->collect_full = 1;

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
	int churn_fraction;	/* one churner per Nth leaf; 1 = all */
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
			   tc->churn_fraction))
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
	 * Timed samples.  Every read idles tc->gap_us (untimed) first, so the
	 * tree re-accumulates a roughly fixed amount of churn and each read
	 * starts from approximately the same state, paying its own rstat flush
	 * inside the timed region.  The file/bpf order is flipped on odd samples
	 * so any residual jitter doesn't systematically favour whichever reader
	 * runs first.
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
	printf("\n==== memcg_stat_churn: %s ====\n", tc->name);
	printf("tree: nodes=%d leaves=%d churners=%d fanout=%d depth=%d region=%zuKB resident=%zuKB samples=%d gap=%dms\n",
	       n_nodes, n_leaves, churners, tc->fanout, tc->depth,
	       tc->region_bytes >> 10, tc->resident_bytes >> 10, tc->samples,
	       tc->gap_us / 1000);
	printf("all times in us (average per full-tree read under churn, full memory.stat field set); ratio = file/bpf; ro = bpf read()-only (no map drain)\n");
	printf("each read idles gap=%dms first so every read starts from ~the same accumulated churn; the rstat flush is counted in the read\n",
	       tc->gap_us / 1000);
	printf("file_avg=%.1f  bpf_avg=%.1f  bpf_ro=%.1f  ratio(file/bpf)=%.2fx\n",
	       f, b, bro, b > 0 ? f / b : 0.0);
	printf("per-cgroup: file avg=%.0f ns  bpf avg=%.0f ns\n",
	       f * 1000.0 / n_nodes, b * 1000.0 / n_nodes);
	printf("bpf entries produced: %d (expected %d)\n", acc.last_got, n_nodes);
	printf("RATIO (under churn): file/bpf = %.2fx\n", b > 0 ? f / b : 0.0);

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
 * Pick it past the point where the flush cost saturates; validate by checking
 * that bpf matched <= bpf full is restored and that doubling it barely moves
 * the numbers.  50 ms is a reasonable default here.
 */
#define CHURN_GAP_US	(50 * 1000)

static const struct testcase cases[] = {
	/*
	 * Both cases use a large (1111-cgroup) tree, where the whole-tree read is
	 * big enough that its cost dominates the rstat flush and scheduler jitter,
	 * so the reported ratios are reproducible run to run; on a small (tens of
	 * cgroups) tree the sub-millisecond BPF read is swamped by that noise and
	 * the ratio bounces.  They differ only in churn density -- large_dense
	 * churns one leaf in 4, large_sparse one in 8 -- which changes how much of
	 * the tree the shared flush has to touch.  samples are kept even so the
	 * file/bpf order-alternation (s & 1) cancels residual first-mover bias.
	 */
	/* name           fan dep frac  region       resident     samp gap */
	{ "large_dense",  10,  3,  4,   256 << 10,   128 << 10,     8,  CHURN_GAP_US },
	{ "large_sparse", 10,  3,  8,   256 << 10,   128 << 10,     8,  CHURN_GAP_US },
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

void serial_test_memcg_stat_churn(void)
{
	int i;

	if (!memcg_kfuncs_available()) {
		test__skip();
		return;
	}

	if (!ASSERT_OK(setup_cgroup_environment(), "setup cgroup env"))
		return;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		if (!test__start_subtest(cases[i].name))
			continue;
		run_case(&cases[i]);
	}

	cleanup_cgroup_environment();
}
