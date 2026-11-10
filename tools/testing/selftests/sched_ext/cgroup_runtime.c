// SPDX-License-Identifier: GPL-2.0
/*
 * Verify that a BPF scheduler with SCX_OPS_CHARGE_CPU_MAX shares a cgroup's
 * cpu.max quota with the fair class: what the cgroup's tasks run in both
 * classes, with and without SCX_OPS_SWITCH_PARTIAL and while tasks switch
 * class, stays within the quota; nothing is gained or lost when the
 * scheduler loads and unloads; and a scheduler that ignores
 * scx_bpf_task_cpu_max_runtime() leaves the fair tasks at most a quota of
 * debt and a slice per CPU, while one that stops tasks late pays the overrun
 * back.
 * Also verify that cpu.max and cpu.max.runtime writes reach the scheduler
 * in the order the fair class applied them.
 *
 * Usage is cpu.stat's usage_usec. A window of n periods may hold n + 1
 * refills and start or end with up to a quota, and each CPU may hold up to
 * a slice (sched_cfs_bandwidth_slice_us), so the checks allow that.
 */

#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/limits.h>
#include <pthread.h>
#include <sched.h>
#include <scx/common.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "cgroup_runtime.bpf.skel.h"
#include "cgroup_util.h"
#include "scx_test.h"

#ifndef SCHED_EXT
#define SCHED_EXT	7
#endif

#define PERIOD_US	100000LL
#define QUOTA_US	20000LL
#define NR_PERIODS	10
#define NR_BURNERS	2

struct ctx {
	struct cgroup_runtime *skel;
	struct bpf_link *link;
	char root[PATH_MAX];
	char parent[PATH_MAX];
	char cg[PATH_MAX];
	bool parent_created;
	bool cg_created;
	pid_t burner[NR_BURNERS];
	long long slice_us;
	long long saved_slice_us;
};

static int join_path(char *dst, size_t dst_size, const char *parent, const char *name)
{
	int ret;

	ret = snprintf(dst, dst_size, "%s/%s", parent, name);
	if (ret < 0 || (size_t)ret >= dst_size)
		return -ENAMETOOLONG;
	return 0;
}

static u64 now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

static u64 cgroup_id(const char *path)
{
	union {
		u64 id;
		unsigned char bytes[8];
	} id = {};
	struct file_handle *handle;
	int mount_id, ret;

	handle = calloc(1, sizeof(*handle) + sizeof(id));
	if (!handle)
		return 0;
	handle->handle_bytes = sizeof(id);
	ret = name_to_handle_at(AT_FDCWD, path, handle, &mount_id, 0);
	if (!ret && handle->handle_bytes == sizeof(id))
		memcpy(id.bytes, handle->f_handle, sizeof(id));
	free(handle);

	return ret ? 0 : id.id;
}

static long long read_runtime(struct ctx *ctx)
{
	return cg_read_long(ctx->cg, "cpu.max.runtime");
}

static long long read_usage(struct ctx *ctx)
{
	return cg_read_key_long(ctx->cg, "cpu.stat", "usage_usec");
}

static int write_str(const char *cgroup, const char *file, const char *fmt, ...)
{
	char buf[64];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	return cg_write(cgroup, file, buf);
}

static bool controller_enabled(const char *cgroup, const char *file, const char *controller)
{
	char buf[4096], *saveptr, *token;

	if (cg_read(cgroup, file, buf, sizeof(buf)))
		return false;
	for (token = strtok_r(buf, "\n ", &saveptr); token;
	     token = strtok_r(NULL, "\n ", &saveptr))
		if (!strcmp(token, controller))
			return true;
	return false;
}

static int set_policy(pid_t pid, int policy)
{
	struct sched_param param = {};

	return sched_setscheduler(pid, policy, &param);
}

static void stop_burners(struct ctx *ctx)
{
	int i;

	for (i = 0; i < NR_BURNERS; i++) {
		if (ctx->burner[i] <= 0)
			continue;
		kill(ctx->burner[i], SIGKILL);
		waitpid(ctx->burner[i], NULL, 0);
		ctx->burner[i] = 0;
	}
}

/* a task in @ctx->cg that spins on CPU @i + 1 under @policy */
static int start_burner(struct ctx *ctx, int i, int policy)
{
	cpu_set_t set;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return -errno;
	if (!pid)
		for (;;)
			;

	ctx->burner[i] = pid;
	CPU_ZERO(&set);
	CPU_SET((i + 1) % libbpf_num_possible_cpus(), &set);
	if (sched_setaffinity(pid, sizeof(set), &set) ||
	    cg_enter(ctx->cg, pid) || set_policy(pid, policy))
		return -1;
	return 0;
}

static void cleanup(void *arg)
{
	struct ctx *ctx = arg;

	if (!ctx)
		return;
	stop_burners(ctx);
	bpf_link__destroy(ctx->link);
	cgroup_runtime__destroy(ctx->skel);
	if (ctx->saved_slice_us)
		write_str("/proc/sys/kernel", "sched_cfs_bandwidth_slice_us", "%lld",
			  ctx->saved_slice_us);
	if (ctx->cg_created)
		cg_destroy(ctx->cg);
	if (ctx->parent_created)
		cg_destroy(ctx->parent);
	free(ctx);
}

/*
 * Open the skeleton and make parent/cg under the cgroup2 root, with a quota
 * of @quota us per @period us, a burst of @burst us and a runtime of
 * @runtime us on cg.
 */
static enum scx_test_status setup_ctx(void **ctxp, long long quota,
				      long long period, long long burst,
				      long long runtime)
{
	struct ctx *ctx;
	char name[64];

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return SCX_TEST_FAIL;
	*ctxp = ctx;

	/* SCX_ENUM_INIT() exits if vmlinux BTF can't be loaded: before cgroups */
	ctx->skel = cgroup_runtime__open();
	if (!ctx->skel) {
		SCX_ERR("Failed to open skel");
		return SCX_TEST_FAIL;
	}
	SCX_ENUM_INIT(ctx->skel);

	ctx->slice_us = 5000;
	if (!access("/proc/sys/kernel/sched_cfs_bandwidth_slice_us", R_OK))
		ctx->slice_us = cg_read_long("/proc/sys/kernel",
					     "sched_cfs_bandwidth_slice_us");

	if (cg_find_unified_root(ctx->root, sizeof(ctx->root), NULL))
		return SCX_TEST_SKIP;
	if (!controller_enabled(ctx->root, "cgroup.subtree_control", "cpu") &&
	    cg_write(ctx->root, "cgroup.subtree_control", "+cpu"))
		return SCX_TEST_SKIP;

	snprintf(name, sizeof(name), "scx_cgroup_runtime_%d", getpid());
	if (join_path(ctx->parent, sizeof(ctx->parent), ctx->root, name) ||
	    join_path(ctx->cg, sizeof(ctx->cg), ctx->parent, "cg")) {
		SCX_ERR("Cgroup path is too long");
		return SCX_TEST_FAIL;
	}

	if (cg_create(ctx->parent)) {
		SCX_ERR("Failed to create %s", ctx->parent);
		return SCX_TEST_FAIL;
	}
	ctx->parent_created = true;
	if (cg_write(ctx->parent, "cgroup.subtree_control", "+cpu")) {
		SCX_ERR("Failed to enable cpu in %s", ctx->parent);
		return SCX_TEST_FAIL;
	}
	if (cg_create(ctx->cg)) {
		SCX_ERR("Failed to create %s", ctx->cg);
		return SCX_TEST_FAIL;
	}
	ctx->cg_created = true;

	if (access(cg_control(ctx->cg, "cpu.max.runtime"), F_OK))
		return SCX_TEST_SKIP;

	if (write_str(ctx->cg, "cpu.max", "%lld %lld", quota, period) ||
	    write_str(ctx->cg, "cpu.max.burst", "%lld", burst) ||
	    write_str(ctx->cg, "cpu.max.runtime", "%lld", runtime)) {
		SCX_ERR("Failed to configure %s", ctx->cg);
		return SCX_TEST_FAIL;
	}

	ctx->skel->bss->cgid = cgroup_id(ctx->cg);
	if (!ctx->skel->bss->cgid) {
		SCX_ERR("Failed to read the cgroup ID of %s", ctx->cg);
		return SCX_TEST_FAIL;
	}
	if (libbpf_num_possible_cpus() < NR_BURNERS + 1)
		return SCX_TEST_SKIP;
	return SCX_TEST_PASS;
}

static enum scx_test_status setup_rate(void **ctxp)
{
	return setup_ctx(ctxp, QUOTA_US, PERIOD_US, 0, QUOTA_US);
}

static enum scx_test_status attach_ops(struct ctx *ctx, bool partial)
{
	ctx->link = bpf_map__attach_struct_ops(partial ? ctx->skel->maps.partial_ops :
						       ctx->skel->maps.full_ops);
	SCX_FAIL_IF(!ctx->link, "Failed to attach scheduler");
	return SCX_TEST_PASS;
}

static enum scx_test_status load_ops(struct ctx *ctx, bool partial)
{
	bpf_map__set_autoattach(ctx->skel->maps.partial_ops, false);
	bpf_map__set_autoattach(ctx->skel->maps.full_ops, false);
	SCX_FAIL_IF(cgroup_runtime__load(ctx->skel), "Failed to load skel");
	return attach_ops(ctx, partial);
}

static void detach(struct ctx *ctx)
{
	bpf_link__destroy(ctx->link);
	ctx->link = NULL;
}

/*
 * Run two burners in cg under @policy[], the first switching class every
 * 7 ms if @toggle, and check that cg runs its quota per period, no more and
 * not much less.
 */
static enum scx_test_status run_rate(struct ctx *ctx, bool partial,
				     const int *policy, bool toggle)
{
	long long tol = NR_BURNERS * ctx->slice_us + QUOTA_US;
	long long used, u0;
	bool ext = false;
	u64 end;
	int i;

	if (load_ops(ctx, partial))
		return SCX_TEST_FAIL;
	for (i = 0; i < NR_BURNERS; i++)
		SCX_EQ(start_burner(ctx, i, policy[i]), 0);

	usleep(3 * PERIOD_US);
	u0 = read_usage(ctx);
	end = now_us() + NR_PERIODS * PERIOD_US;
	while (now_us() < end) {
		if (toggle) {
			ext = !ext;
			SCX_EQ(set_policy(ctx->burner[0], ext ? SCHED_EXT : SCHED_OTHER), 0);
		}
		usleep(7000);
	}
	used = read_usage(ctx) - u0;
	stop_burners(ctx);

	printf("ran %lld us in %d periods of quota %lld us, %lu held\n",
	       used, NR_PERIODS, QUOTA_US, (unsigned long)ctx->skel->bss->nr_held);
	SCX_GE(used, QUOTA_US * NR_PERIODS - tol);
	SCX_LE(used, QUOTA_US * NR_PERIODS + tol);
	SCX_ASSERT_ALIVE(ctx->skel, uei);
	return SCX_TEST_PASS;
}

static enum scx_test_status run_full(void *arg)
{
	static const int policy[] = { SCHED_OTHER, SCHED_OTHER };

	return run_rate(arg, false, policy, false);
}

static enum scx_test_status run_partial_ext(void *arg)
{
	static const int policy[] = { SCHED_EXT, SCHED_EXT };

	return run_rate(arg, true, policy, false);
}

static enum scx_test_status run_partial_fair(void *arg)
{
	static const int policy[] = { SCHED_OTHER, SCHED_OTHER };

	return run_rate(arg, true, policy, false);
}

static enum scx_test_status run_partial_mixed(void *arg)
{
	static const int policy[] = { SCHED_EXT, SCHED_OTHER };

	return run_rate(arg, true, policy, false);
}

static enum scx_test_status run_switch(void *arg)
{
	static const int policy[] = { SCHED_OTHER, SCHED_EXT };

	return run_rate(arg, true, policy, true);
}

/*
 * With a quota of 1 ms per second and a runtime of 3 s, what cg runs while
 * the scheduler loads, runs and unloads is what its runtime loses, up to a
 * slice per CPU and the few refills.
 */
#define LU_QUOTA_US	1000LL
#define LU_PERIOD_US	1000000LL

static enum scx_test_status setup_load_unload(void **ctxp)
{
	return setup_ctx(ctxp, LU_QUOTA_US, LU_PERIOD_US, 4000000, 3000000);
}

static enum scx_test_status run_load_unload(void *arg)
{
	struct ctx *ctx = arg;
	long long r0, u0, drawn, used, refills, tol;
	u64 t0, t1;
	int i;

	bpf_map__set_autoattach(ctx->skel->maps.partial_ops, false);
	bpf_map__set_autoattach(ctx->skel->maps.full_ops, false);
	SCX_FAIL_IF(cgroup_runtime__load(ctx->skel), "Failed to load skel");

	t0 = now_us();
	r0 = read_runtime(ctx);
	u0 = read_usage(ctx);
	for (i = 0; i < NR_BURNERS; i++)
		SCX_EQ(start_burner(ctx, i, SCHED_OTHER), 0);
	usleep(100000);
	if (attach_ops(ctx, false))
		return SCX_TEST_FAIL;
	usleep(200000);
	detach(ctx);
	usleep(100000);
	stop_burners(ctx);
	drawn = r0 - read_runtime(ctx);
	used = read_usage(ctx) - u0;
	t1 = now_us();

	refills = LU_QUOTA_US * ((t1 - t0) / LU_PERIOD_US + 2);
	tol = NR_BURNERS * ctx->slice_us;
	printf("ran %lld us, runtime down %lld us\n", used, drawn);
	SCX_GE(used, 300000);
	SCX_GE(used, drawn - tol);
	SCX_LE(used, drawn + refills + tol);
	return SCX_TEST_PASS;
}

/*
 * A scheduler that ignores scx_bpf_task_cpu_max_runtime() runs a task far
 * past the quota. Once the task is back on the fair class, it runs its quota
 * again, less at most a quota and a slice of debt.
 */
static enum scx_test_status run_clamp(void *arg)
{
	struct ctx *ctx = arg;
	long long u0, ignored, used;

	ctx->skel->bss->ignore_runtime = true;
	if (load_ops(ctx, true))
		return SCX_TEST_FAIL;
	SCX_EQ(start_burner(ctx, 0, SCHED_EXT), 0);

	u0 = read_usage(ctx);
	usleep(5 * PERIOD_US);
	ignored = read_usage(ctx) - u0;

	SCX_EQ(set_policy(ctx->burner[0], SCHED_OTHER), 0);
	u0 = read_usage(ctx);
	usleep(5 * PERIOD_US);
	used = read_usage(ctx) - u0;
	stop_burners(ctx);

	printf("ran %lld us ignoring the quota, then %lld us on the fair class\n",
	       ignored, used);
	SCX_GE(ignored, 4 * PERIOD_US);
	SCX_GE(used, 4 * QUOTA_US - 2 * ctx->slice_us);
	SCX_LE(used, 6 * QUOTA_US + ctx->slice_us);
	SCX_ASSERT_ALIVE(ctx->skel, uei);
	return SCX_TEST_PASS;
}

/*
 * The scheduler stops a task only at a tick, so each period it overruns a
 * quota of 2 ms by up to a tick. With a slice of 1 ms, the next tick's
 * charge takes the CPU past the -slice floor. The debt must still be paid
 * from the next periods, so over 100 periods cg runs its quota, with the
 * second burner moving between CPUs 2 and 3 every 7 ms.
 */
#define DEBT_QUOTA_US	2000LL
#define DEBT_PERIOD_US	10000LL
#define DEBT_PERIODS	100

static enum scx_test_status setup_debt(void **ctxp)
{
	enum scx_test_status ret;
	struct ctx *ctx;

	ret = setup_ctx(ctxp, DEBT_QUOTA_US, DEBT_PERIOD_US, 0, DEBT_QUOTA_US);
	if (ret != SCX_TEST_PASS)
		return ret;
	ctx = *ctxp;
	if (write_str("/proc/sys/kernel", "sched_cfs_bandwidth_slice_us", "1000"))
		return SCX_TEST_SKIP;
	ctx->saved_slice_us = ctx->slice_us;
	ctx->slice_us = 1000;
	return SCX_TEST_PASS;
}

static enum scx_test_status run_debt(void *arg)
{
	struct ctx *ctx = arg;
	long long tol = (NR_BURNERS + 1) * ctx->slice_us + DEBT_QUOTA_US;
	long long want = DEBT_QUOTA_US * DEBT_PERIODS;
	long long used, u0;
	bool moved = false;
	cpu_set_t set;
	u64 end;
	int i;

	if (libbpf_num_possible_cpus() < 4)
		return SCX_TEST_SKIP;
	if (load_ops(ctx, true))
		return SCX_TEST_FAIL;
	for (i = 0; i < NR_BURNERS; i++)
		SCX_EQ(start_burner(ctx, i, SCHED_EXT), 0);

	usleep(3 * DEBT_PERIOD_US);
	u0 = read_usage(ctx);
	end = now_us() + DEBT_PERIODS * DEBT_PERIOD_US;
	while (now_us() < end) {
		moved = !moved;
		CPU_ZERO(&set);
		CPU_SET(moved ? 3 : 2, &set);
		SCX_EQ(sched_setaffinity(ctx->burner[1], sizeof(set), &set), 0);
		usleep(7000);
	}
	used = read_usage(ctx) - u0;
	stop_burners(ctx);

	printf("ran %lld us in %d periods of quota %lld us\n", used,
	       DEBT_PERIODS, DEBT_QUOTA_US);
	SCX_GE(used, want - tol);
	SCX_LE(used, want + tol);
	SCX_ASSERT_ALIVE(ctx->skel, uei);
	return SCX_TEST_PASS;
}

/*
 * One thread alternates cpu.max between quotas of 100ms and 10ms, without a
 * burst, while another writes a runtime of 90ms, which only the first
 * allows. The scheduler must never get a runtime above the quota it was last
 * given, and must end with the quota cpu.max has.
 */
#define INTERLEAVE_US	2000000ULL

struct interleave {
	struct ctx *ctx;
	long nr_ok;
	long nr_einval;
	long nr_err;
};

static void *interleave_quota(void *arg)
{
	struct interleave *il = arg;
	u64 end = now_us() + INTERLEAVE_US;
	bool high = false;

	while (now_us() < end) {
		if (write_str(il->ctx->cg, "cpu.max", "%lld %lld",
			      high ? 100000LL : 10000LL, 1000000LL))
			il->nr_err++;
		else
			il->nr_ok++;
		high = !high;
	}
	return NULL;
}

static void *interleave_runtime(void *arg)
{
	struct interleave *il = arg;
	u64 end = now_us() + INTERLEAVE_US;

	while (now_us() < end) {
		int fd = cg_open(il->ctx->cg, "cpu.max.runtime", O_WRONLY);

		if (fd < 0) {
			il->nr_err++;
			continue;
		}
		if (write(fd, "90000", 5) == 5)
			il->nr_ok++;
		else if (errno == EINVAL)
			il->nr_einval++;
		else
			il->nr_err++;
		close(fd);
	}
	return NULL;
}

static enum scx_test_status setup_interleave(void **ctxp)
{
	return setup_ctx(ctxp, 100000, 1000000, 0, 100000);
}

static enum scx_test_status run_interleave(void *arg)
{
	struct ctx *ctx = arg;
	struct interleave quota = { .ctx = ctx }, runtime = { .ctx = ctx };
	pthread_t tq, tr;
	char buf[64];

	if (load_ops(ctx, true))
		return SCX_TEST_FAIL;
	SCX_EQ(ctx->skel->bss->quota_us, 100000);

	SCX_EQ(pthread_create(&tq, NULL, interleave_quota, &quota), 0);
	SCX_EQ(pthread_create(&tr, NULL, interleave_runtime, &runtime), 0);
	pthread_join(tq, NULL);
	pthread_join(tr, NULL);

	SCX_EQ(quota.nr_err, 0);
	SCX_EQ(runtime.nr_err, 0);
	SCX_GT(runtime.nr_ok, 0);
	SCX_EQ(ctx->skel->bss->nr_bad_order, 0);
	SCX_EQ(ctx->skel->bss->nr_set_bw, quota.nr_ok);
	SCX_EQ(ctx->skel->bss->nr_set_runtime, runtime.nr_ok);

	SCX_EQ(cg_read(ctx->cg, "cpu.max", buf, sizeof(buf)), 0);
	SCX_EQ(ctx->skel->bss->quota_us, atoll(buf));
	SCX_EQ(ctx->skel->bss->burst_us, 0);

	printf("cpu.max writes %ld, cpu.max.runtime writes %ld (%ld EINVAL)\n",
	       quota.nr_ok, runtime.nr_ok, runtime.nr_einval);
	SCX_ASSERT_ALIVE(ctx->skel, uei);
	return SCX_TEST_PASS;
}

#define RUNTIME_TEST(__name, __setup, __desc)				\
	struct scx_test cgroup_runtime_##__name = {			\
		.name = "cgroup_runtime_" #__name,			\
		.description = __desc,					\
		.setup = __setup,					\
		.run = run_##__name,					\
		.cleanup = cleanup,					\
	}

RUNTIME_TEST(full, setup_rate, "Without partial switch, the BPF scheduler's tasks run their quota");
RUNTIME_TEST(partial_ext, setup_rate, "SCHED_EXT tasks of a cgroup run its quota");
RUNTIME_TEST(partial_fair, setup_rate, "Fair tasks of a cgroup run its quota");
RUNTIME_TEST(partial_mixed, setup_rate, "Fair and SCHED_EXT tasks of a cgroup share its quota");
RUNTIME_TEST(switch, setup_rate, "A task switching class every 7 ms stays within the quota");
RUNTIME_TEST(load_unload, setup_load_unload, "Load and unload neither gain nor lose runtime");
RUNTIME_TEST(clamp, setup_rate, "A scheduler ignoring the quota leaves a bounded debt");
RUNTIME_TEST(debt, setup_debt, "Debt past a quota is paid in the next periods");
RUNTIME_TEST(interleave, setup_interleave, "cpu.max writes reach the scheduler in order");

/* REGISTER_SCX_TEST() can be used once per file */
__attribute__((constructor))
static void register_cgroup_runtime_tests(void)
{
	scx_test_register(&cgroup_runtime_full);
	scx_test_register(&cgroup_runtime_partial_ext);
	scx_test_register(&cgroup_runtime_partial_fair);
	scx_test_register(&cgroup_runtime_partial_mixed);
	scx_test_register(&cgroup_runtime_switch);
	scx_test_register(&cgroup_runtime_load_unload);
	scx_test_register(&cgroup_runtime_clamp);
	scx_test_register(&cgroup_runtime_debt);
	scx_test_register(&cgroup_runtime_interleave);
}
