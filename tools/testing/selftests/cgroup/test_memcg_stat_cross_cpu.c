// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Compare memcg BPF kfuncs with memory.stat over a charged subtree. Chargers
 * spread anonymous memory across CPUs and hold it. Read BPF first so its flush
 * is not consumed by memory.stat, then require two file samples to bracket each
 * BPF value. Each leaf must cover its charge; root anon must equal the leaf sum.
 */
#define _GNU_SOURCE

#include <errno.h>
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

#define FLUSH_MARGIN		2

/* Bound total charge on large systems. */
#define MAX_TOTAL_CHARGE	(256UL << 20)

/* Bound the CPUs used by each leaf. */
#define MAX_CPUS_PER_LEAF	16

#define CHARGE_WAIT_RETRIES	500

static char root[PATH_MAX];
static char *subtree_root;
static long page_size;

/* cgroupfs values in bytes. */
struct file_snap {
	long anon, file, shmem, file_mapped, pgfault;
	long current;
};

struct cg_node {
	char path[PATH_MAX];
	unsigned long long id;
	bool is_leaf;			/* holds a charge of its own */
	long previous_current;		/* previous memory.current poll */
	struct memcg_stat_snapshot bpf;	/* read through the kfuncs */
	struct file_snap file[2];	/* post-BPF cgroupfs samples */
};

static struct cg_node *nodes;	/* DFS order: a parent precedes its children */
static int n_nodes;
static int n_leaves;

/* ---- CPUs this test may run on ----------------------------------------- */

static cpu_set_t allowed_cpus;
static int n_cpu;
static long n_online_cpu;

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
	n->previous_current = -1;
	if (is_leaf)
		n_leaves++;
	n_nodes++;
	return 0;
}

/* Build @levels below @path; only leaves are charged. */
static int build_children(const char *path, int fanout, int levels)
{
	char child[PATH_MAX];
	int i;

	if (levels == 0)
		return 0;

	/* Give child cgroups a memcg. */
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

/* Destroy children before parents, then reap chargers. */
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

	/* Keep each CPU's slice page-aligned. */
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

static int leaf_charge(size_t want, int k, size_t *bytes)
{
	size_t min_pages, pages, want_pages;

	if ((size_t)n_online_cpu > SIZE_MAX / FLUSH_MARGIN /
					 MEMCG_CHARGE_BATCH)
		return -EOVERFLOW;

	/* Force more than one pending batch per CPU across the subtree. */
	min_pages = (size_t)FLUSH_MARGIN * MEMCG_CHARGE_BATCH * n_online_cpu;
	pages = min_pages / n_leaves + !!(min_pages % n_leaves);
	want_pages = want / page_size + !!(want % page_size);
	if (pages < want_pages)
		pages = want_pages;
	if (pages < (size_t)k)
		pages = k;

	if (pages > MAX_TOTAL_CHARGE / (size_t)n_leaves / page_size)
		return -E2BIG;

	*bytes = pages * page_size;
	return 0;
}

static int start_chargers(int k, size_t bytes)
{
	struct charge_args ca = { .bytes = bytes, .k = k };
	long prev, cur;
	bool ready;
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

	/* Wait until every leaf is fully charged and stable. */
	for (retries = CHARGE_WAIT_RETRIES; retries; retries--) {
		ready = true;
		for (i = 0; i < n_nodes; i++) {
			if (!nodes[i].is_leaf)
				continue;

			cur = cg_read_long(nodes[i].path, "memory.current");
			if (cur < 0) {
				ksft_print_msg("cannot read %s/memory.current: %s\n",
					       nodes[i].path, strerror(errno));
				return -1;
			}

			prev = nodes[i].previous_current;
			nodes[i].previous_current = cur;
			if (cur < (long)bytes || cur != prev)
				ready = false;
		}
		if (ready)
			return 0;
		usleep(DEFAULT_WAIT_INTERVAL_US / 10);
	}

	for (i = 0; i < n_nodes; i++) {
		if (nodes[i].is_leaf && nodes[i].previous_current < (long)bytes) {
			ksft_print_msg("%s reached only %ld of %zu charged bytes\n",
				       nodes[i].path, nodes[i].previous_current,
				       bytes);
			return -1;
		}
	}
	ksft_print_msg("memory.current did not settle before the timeout\n");
	return -1;
}

/* ---- the two readers ---------------------------------------------------- */

/* Flush the subtree and collect each cgroup's kfunc values. */
static int read_bpf(int root_fd)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct memcg_stat_cross_cpu *skel = NULL;
	union bpf_iter_link_info linfo = {};
	struct bpf_link *link = NULL;
	int ret = -1, err, i, mfd, fd;
	char buf[4096];
	ssize_t r;

	skel = memcg_stat_cross_cpu__open();
	if (!skel) {
		ksft_print_msg("skel open failed: %s (%d)\n",
			       strerror(errno), errno);
		return -1;
	}
	err = bpf_program__set_autoload(skel->progs.memcg_kfuncs_probe, false);
	if (err) {
		ksft_print_msg("disabling capability probe failed: %s (%d)\n",
			       strerror(-err), err);
		goto out;
	}
	err = bpf_map__set_max_entries(skel->maps.results, n_nodes + 8);
	if (err) {
		ksft_print_msg("set max_entries failed: %s (%d)\n",
			       strerror(-err), err);
		goto out;
	}
	err = memcg_stat_cross_cpu__load(skel);
	if (err) {
		ksft_print_msg("skel load failed: %s (%d)\n",
			       strerror(-err), err);
		goto out;
	}

	linfo.cgroup.cgroup_fd = root_fd;
	linfo.cgroup.order = BPF_CGROUP_ITER_DESCENDANTS_PRE;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.cgroup_memcg_stat_cross_cpu,
					&opts);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		ksft_print_msg("attach iter failed: %s (%d)\n",
			       strerror(-err), err);
		goto out;
	}

	fd = bpf_iter_create(bpf_link__fd(link));
	if (fd < 0) {
		ksft_print_msg("bpf_iter_create failed: %s (%d)\n",
			       strerror(errno), errno);
		goto out;
	}
	do {
		r = read(fd, buf, sizeof(buf));
	} while (r > 0 || (r < 0 && errno == EINTR));
	err = errno;
	close(fd);
	if (r < 0) {
		ksft_print_msg("bpf walk failed: %s (%d)\n",
			       strerror(err), err);
		goto out;
	}

	mfd = bpf_map__fd(skel->maps.results);
	for (i = 0; i < n_nodes; i++)
		if (bpf_map_lookup_elem(mfd, &nodes[i].id, &nodes[i].bpf)) {
			ksft_print_msg("no map entry for %s: %s (%d)\n",
				       nodes[i].path, strerror(errno), errno);
			goto out;
		}
	ret = 0;
out:
	bpf_link__destroy(link);
	memcg_stat_cross_cpu__destroy(skel);
	return ret;
}

/* Read one cgroupfs snapshot. */
static int read_files(int slot)
{
	int i;

	for (i = 0; i < n_nodes; i++) {
		const char *path = nodes[i].path;
		struct file_snap *f = &nodes[i].file[slot];

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
	int s;

	ksft_print_msg("%s bpf   : anon=%llu file=%llu shmem=%llu fmapped=%llu pgfault=%llu\n",
		       n->path, n->bpf.anon, n->bpf.file, n->bpf.shmem,
		       n->bpf.file_mapped, n->bpf.pgfault);
	for (s = 0; s < 2; s++)
		ksft_print_msg("%s file%d: anon=%ld file=%ld shmem=%ld fmapped=%ld pgfault=%ld\n",
			       n->path, s, n->file[s].anon, n->file[s].file,
			       n->file[s].shmem, n->file[s].file_mapped,
			       n->file[s].pgfault);
}

/* Equal file samples require an exact BPF match; otherwise accept their range. */
static bool bracketed(unsigned long long v, long a, long b)
{
	long lo = a < b ? a : b;
	long hi = a < b ? b : a;

	return v >= (unsigned long long)lo && v <= (unsigned long long)hi;
}

static int check_tree(size_t charged)
{
	unsigned long long root_anon = 0, leaf_anon = 0;
	int i, bad = 0;

	for (i = 0; i < n_nodes; i++) {
		const struct cg_node *n = &nodes[i];
		const struct memcg_stat_snapshot *b = &n->bpf;
		const struct file_snap *f0 = &n->file[0], *f1 = &n->file[1];

		if (!bracketed(b->anon, f0->anon, f1->anon) ||
		    !bracketed(b->file, f0->file, f1->file) ||
		    !bracketed(b->shmem, f0->shmem, f1->shmem) ||
		    !bracketed(b->file_mapped, f0->file_mapped,
			       f1->file_mapped) ||
		    !bracketed(b->pgfault, f0->pgfault, f1->pgfault)) {
			ksft_print_msg("kfuncs disagree with memory.stat\n");
			dump_node(n);
			bad++;
		}

		/* Live page counters are bounds, not flushed statistics. */
		if (b->anon > b->usage_pages * (unsigned long long)page_size ||
		    f1->anon > f1->current) {
			ksft_print_msg("%s: anon above usage: bpf %llu/%llu file %ld/%ld\n",
				       n->path, b->anon,
				       b->usage_pages * (unsigned long long)page_size,
				       f1->anon, f1->current);
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

/* Accept PAGE_COUNTER_MAX values from either 32- or 64-bit kernels. */
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
	int cpus_per_leaf;	/* K, or 0 for the bounded cross-CPU count */
	size_t resident_bytes;	/* anon per leaf, raised if too small */
};

static int run_case(const struct testcase *tc)
{
	int root_fd = -1, ret = KSFT_FAIL, err, k;
	size_t charged;

	if (build_tree(tc->fanout, tc->depth, &root_fd)) {
		ksft_print_msg("cannot build the tree\n");
		goto out;
	}

	k = tc->cpus_per_leaf;
	if (k <= 0)
		k = n_cpu < MAX_CPUS_PER_LEAF ? n_cpu : MAX_CPUS_PER_LEAF;
	else if (k > n_cpu)
		k = n_cpu;
	err = leaf_charge(tc->resident_bytes, k, &charged);
	if (err == -E2BIG) {
		ksft_print_msg("%s needs more than %luMB to trigger a flush on %ld online CPUs\n",
			       tc->name, MAX_TOTAL_CHARGE >> 20, n_online_cpu);
		ret = KSFT_SKIP;
		goto out;
	}
	if (err) {
		ksft_print_msg("cannot calculate the charge for %s: %s (%d)\n",
			       tc->name, strerror(-err), err);
		goto out;
	}

	ksft_print_msg("%s: %d cgroups, %d leaves, %d/%d cpus, %zuKB per leaf\n",
		       tc->name, n_nodes, n_leaves, k, n_cpu, charged >> 10);

	if (start_chargers(k, charged))
		goto out;

	/* Read BPF first; memory.stat would consume the pending flush. */
	if (read_bpf(root_fd) || read_files(0) || read_files(1))
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
	{ "single_cpu_large_tree", 4, 3, 1, 256 << 10 },
	{ "cross_cpu_large_tree", 4, 3, 0, 256 << 10 },
};

static bool memcg_kfuncs_available(void)
{
	static const char *const kfuncs[] = {
		"bpf_get_mem_cgroup",
		"bpf_put_mem_cgroup",
		"bpf_mem_cgroup_flush_stats",
		"bpf_mem_cgroup_page_state",
		"bpf_mem_cgroup_vm_events",
	};
	struct btf *btf;
	int err, i;

	btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(btf);
	if (err) {
		ksft_print_msg("cannot load vmlinux BTF: %s (%d)\n",
			       strerror(-err), err);
		return false;
	}

	for (i = 0; i < ARRAY_SIZE(kfuncs); i++) {
		if (btf__find_by_name_kind(btf, kfuncs[i], BTF_KIND_FUNC) > 0)
			continue;
		ksft_print_msg("required kfunc %s is not in vmlinux BTF\n",
			       kfuncs[i]);
		btf__free(btf);
		return false;
	}
	if (btf__find_by_name_kind(btf, "bpf_iter_cgroup", BTF_KIND_FUNC) <= 0) {
		ksft_print_msg("cgroup BPF iterator is not in vmlinux BTF\n");
		btf__free(btf);
		return false;
	}
	btf__free(btf);
	return true;
}

static bool unsupported_bpf_feature_error(int err)
{
	return err == -EINVAL || err == -ENOENT || err == -EOPNOTSUPP;
}

/* Return 1 if supported, 0 if unavailable, or a negative error. */
static int probe_memcg_bpf_features(int root_fd)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct memcg_stat_cross_cpu *skel;
	union bpf_iter_link_info linfo = {};
	struct bpf_link *link = NULL;
	int ret, err, iter_fd = -1;

	skel = memcg_stat_cross_cpu__open();
	if (!skel) {
		err = errno ? -errno : -EINVAL;
		ksft_print_msg("capability probe open failed: %s (%d)\n",
			       strerror(-err), err);
		return err;
	}

	err = bpf_program__set_autoload(skel->progs.cgroup_memcg_stat_cross_cpu,
					false);
	if (err) {
		ksft_print_msg("disabling test program failed: %s (%d)\n",
			       strerror(-err), err);
		ret = err;
		goto out;
	}

	err = memcg_stat_cross_cpu__load(skel);
	if (err) {
		ksft_print_msg("BPF capability probe load failed: %s (%d)\n",
			       strerror(-err), err);
		ret = unsupported_bpf_feature_error(err) ? 0 : err;
		goto out;
	}

	linfo.cgroup.cgroup_fd = root_fd;
	linfo.cgroup.order = BPF_CGROUP_ITER_SELF_ONLY;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.memcg_kfuncs_probe, &opts);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		ksft_print_msg("BPF capability probe attach failed: %s (%d)\n",
			       strerror(-err), err);
		ret = unsupported_bpf_feature_error(err) ? 0 : err;
		goto out;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		err = -errno;
		ksft_print_msg("BPF capability probe iterator creation failed: %s (%d)\n",
			       strerror(-err), err);
		ret = unsupported_bpf_feature_error(err) ? 0 : err;
		goto out;
	}

	ret = 1;
out:
	if (iter_fd >= 0)
		close(iter_fd);
	bpf_link__destroy(link);
	memcg_stat_cross_cpu__destroy(skel);
	return ret;
}

int main(int argc, char **argv)
{
	int feature_fd, i, ret;

	ksft_print_header();

	/* Probe BTF before operations that may require privileges. */
	if (!memcg_kfuncs_available())
		ksft_exit_skip("memcg BPF kfuncs are not available\n");

	if (cg_find_unified_root(root, sizeof(root), NULL))
		ksft_exit_skip("cgroup v2 isn't mounted\n");
	feature_fd = open(root, O_RDONLY | O_DIRECTORY);
	if (feature_fd < 0)
		ksft_exit_fail_msg("cannot open cgroup root: %s (%d)\n",
				   strerror(errno), errno);
	ret = probe_memcg_bpf_features(feature_fd);
	close(feature_fd);
	if (!ret)
		ksft_exit_skip("sleepable cgroup iterator or memcg kfuncs are not available\n");
	if (ret < 0)
		ksft_exit_fail_msg("cannot probe BPF capabilities: %s (%d)\n",
				   strerror(-ret), ret);

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
	n_online_cpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (n_online_cpu <= 0)
		ksft_exit_fail_msg("cannot determine the number of online CPUs\n");

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		page_size = BUF_SIZE;

	subtree_root = cg_name(root, SUBTREE_NAME);
	if (!subtree_root)
		ksft_exit_skip("cannot build subtree root path\n");

	/* Set the plan after all global skip checks. */
	ksft_set_plan(ARRAY_SIZE(cases));

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

	free(subtree_root);
	ksft_finished();
}
