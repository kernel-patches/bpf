// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include "cgroup_helpers.h"
#include "cgroup_iter_cpu.h"
#include "cgroup_iter_cpu.skel.h"

static int read_stats(struct bpf_link *link)
{
	int fd, ret = 0;
	ssize_t bytes;

	fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_OK_FD(fd, "bpf_iter_create"))
		return 1;

	bytes = read(fd, NULL, 0);
	if (!ASSERT_EQ(bytes, 0, "read fd"))
		ret = 1;

	close(fd);
	return ret;
}

/* Read cgroup file @name into @buf. */
static int read_cgroup_file(int cgroup_fd, const char *name, char *buf,
			    size_t size)
{
	ssize_t n;
	int fd;

	fd = openat(cgroup_fd, name, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, size - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	return 0;
}

/* Parse the "cpu.stat" file into @out. */
static int parse_cpu_stat(int cgroup_fd, struct cpu_query *out)
{
	char buf[4096], *line, *sp;
	unsigned long long v;

	if (read_cgroup_file(cgroup_fd, "cpu.stat", buf, sizeof(buf)))
		return -1;

	for (line = strtok_r(buf, "\n", &sp); line;
	     line = strtok_r(NULL, "\n", &sp)) {
		if (sscanf(line, "usage_usec %llu", &v) == 1)
			out->usage_usec = v;
		else if (sscanf(line, "user_usec %llu", &v) == 1)
			out->user_usec = v;
		else if (sscanf(line, "system_usec %llu", &v) == 1)
			out->system_usec = v;
		else if (sscanf(line, "nice_usec %llu", &v) == 1)
			out->nice_usec = v;
		else if (sscanf(line, "core_sched.force_idle_usec %llu", &v) == 1)
			out->forceidle_usec = v;
		else if (sscanf(line, "nr_periods %llu", &v) == 1)
			out->nr_periods = v;
		else if (sscanf(line, "nr_throttled %llu", &v) == 1)
			out->nr_throttled = v;
		else if (sscanf(line, "throttled_usec %llu", &v) == 1)
			out->throttled_usec = v;
		else if (sscanf(line, "nr_bursts %llu", &v) == 1)
			out->nr_bursts = v;
		else if (sscanf(line, "burst_usec %llu", &v) == 1)
			out->burst_usec = v;
	}
	return 0;
}

/*
 * Parse the "cpu.stat.local" file into @out.
 */
static int parse_cpu_stat_local(int cgroup_fd, struct cpu_query *out)
{
	unsigned long long v;
	char buf[256];

	if (read_cgroup_file(cgroup_fd, "cpu.stat.local", buf, sizeof(buf)))
		return -1;
	if (sscanf(buf, "throttled_usec %llu", &v) != 1)
		return -1;
	out->throttled_self_usec = v;
	return 0;
}

/* Read file value the bpf program reads. */
static int parse_stats(int cgroup_fd, struct cpu_query *out, bool have_bw)
{
	if (parse_cpu_stat(cgroup_fd, out))
		return -1;
	if (have_bw && parse_cpu_stat_local(cgroup_fd, out))
		return -1;
	return 0;
}

/*
 * Check whether this kernel accounts CFS bandwidth.
 */
static bool cgroup_has_bw_stat(int cgroup_fd)
{
	char buf[4096];

	if (read_cgroup_file(cgroup_fd, "cpu.stat", buf, sizeof(buf)))
		return false;
	return strstr(buf, "nr_periods ");
}

/* Fork a child that spins in the current cgroup, kill it if the test exits. */
static pid_t spawn_cpu_hog(void)
{
	pid_t pid = fork();

	if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		while (1)
			;
	}
	return pid;
}

void test_cgroup_iter_cpu(void)
{
	char *cgroup_rel_path = "/cgroup_iter_cpu_test";
	struct cgroup_iter_cpu *skel;
	struct cpu_query *q;
	struct bpf_link *link;
	bool wrote_max, have_bw;
	int cgroup_fd;
	pid_t hog;

	cgroup_fd = cgroup_setup_and_join(cgroup_rel_path);
	if (!ASSERT_OK_FD(cgroup_fd, "cgroup_setup_and_join"))
		return;

	wrote_max = !write_cgroup_file(cgroup_rel_path, "cpu.max", "10000 100000");

	skel = cgroup_iter_cpu__open_and_load();
	if (!ASSERT_OK_PTR(skel, "cgroup_iter_cpu__open_and_load"))
		goto cleanup_cgroup_fd;

	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo = {
		.cgroup.cgroup_fd = cgroup_fd,
		.cgroup.order = BPF_CGROUP_ITER_SELF_ONLY,
	};
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.cgroup_cpu_query, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		goto cleanup_skel;

	q = &skel->data_query->cpu_query;

	hog = spawn_cpu_hog();
	if (!ASSERT_GT(hog, 0, "spawn_cpu_hog"))
		goto cleanup_link;

	sleep(1);

	/* Run the bpf program before anything here reads cpu.stat. */
	if (!ASSERT_OK(read_stats(link), "read stats"))
		goto cleanup_hog;

	have_bw = wrote_max && cgroup_has_bw_stat(cgroup_fd);

	if (test__start_subtest("cgroup_iter_cpu__cputime")) {
		ASSERT_GT(q->usage_usec, 0, "usage_usec");
		ASSERT_GT(q->user_usec + q->system_usec, 0, "user+system_usec");
	}
	if (test__start_subtest("cgroup_iter_cpu__throttling")) {
		if (!have_bw) {
			test__skip();
		} else {
			ASSERT_GT(q->nr_periods, 0, "nr_periods");
			ASSERT_GT(q->nr_throttled, 0, "nr_throttled");
			ASSERT_GT(q->throttled_usec, 0, "throttled_usec");
			ASSERT_GT(q->throttled_self_usec, 0, "throttled_self_usec");
		}
	}

	/*
	 * cpu.stat cputime grows on every tick a task in the cgroup runs, so
	 * stop them all before comparing
	 */
	if (test__start_subtest("cgroup_iter_cpu__match")) {
		struct cpu_query filev = {};
		int i, stable = 0;

		kill(hog, SIGSTOP);
		waitpid(hog, NULL, WUNTRACED);
		if (!ASSERT_OK(join_root_cgroup(), "join_root_cgroup"))
			goto cleanup_hog;

		/*
		 * The period timer keeps adding to nr_periods for a while
		 * after the hog stops
		 */
		for (i = 0; i < 20; i++) {
			struct cpu_query before = {}, after = {};

			if (!ASSERT_OK(parse_stats(cgroup_fd, &before, have_bw), "cpu.stat") ||
			    !ASSERT_OK(read_stats(link), "read stats") ||
			    !ASSERT_OK(parse_stats(cgroup_fd, &after, have_bw), "cpu.stat"))
				goto cleanup_hog;

			if (!memcmp(&before, &after, sizeof(before))) {
				filev = before;
				stable = 1;
				break;
			}
			usleep(100000);
		}

		if (!ASSERT_TRUE(stable, "cpu.stat stable"))
			goto cleanup_hog;

		ASSERT_EQ(q->usage_usec, filev.usage_usec, "usage_usec");
		ASSERT_EQ(q->user_usec, filev.user_usec, "user_usec");
		ASSERT_EQ(q->system_usec, filev.system_usec, "system_usec");
		ASSERT_EQ(q->nice_usec, filev.nice_usec, "nice_usec");
		ASSERT_EQ(q->forceidle_usec, filev.forceidle_usec, "forceidle_usec");

		if (have_bw) {
			ASSERT_EQ(q->nr_periods, filev.nr_periods, "nr_periods");
			ASSERT_EQ(q->nr_throttled, filev.nr_throttled, "nr_throttled");
			ASSERT_EQ(q->throttled_usec, filev.throttled_usec, "throttled_usec");
			ASSERT_EQ(q->nr_bursts, filev.nr_bursts, "nr_bursts");
			ASSERT_EQ(q->burst_usec, filev.burst_usec, "burst_usec");
			ASSERT_EQ(q->throttled_self_usec, filev.throttled_self_usec,
				  "throttled_self_usec");
		}
	}

cleanup_hog:
	kill(hog, SIGKILL);
	waitpid(hog, NULL, 0);
cleanup_link:
	bpf_link__destroy(link);
cleanup_skel:
	cgroup_iter_cpu__destroy(skel);
cleanup_cgroup_fd:
	close(cgroup_fd);
	cleanup_cgroup_environment();
}
