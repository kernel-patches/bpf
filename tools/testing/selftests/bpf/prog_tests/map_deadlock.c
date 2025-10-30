// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include "map_deadlock.skel.h"


static int perf_open_all_cpus(struct perf_event_attr *attr, int fds[], int max_cpus)
{
	int n = 0;

	for (int cpu = 0; cpu < max_cpus; cpu++) {
		int fd = syscall(__NR_perf_event_open, attr, -1 /* pid: all */, cpu,
				 -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
		if (fd < 0)
			continue;
		fds[cpu] = fd;
		n++;
	}
	return n;
}

struct thread_arg {
	int map_fd;
	bool *stop;
};

static void *user_update_thread(void *argp)
{
	struct thread_arg *arg = argp;
	u32 key = 0;
	u64 val = 1;

	while (!*arg->stop) {
		key++;
		val++;
		bpf_map_update_elem(arg->map_fd, &key, &val, BPF_ANY);
		if ((key & 0x7) == 0)
			bpf_map_delete_elem(arg->map_fd, &key);
	}
	return NULL;
}

static void test_map(const char *map_name, int map_index)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.size = sizeof(struct perf_event_attr),
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.sample_period = 1000000,
		.freq = 0,
		.disabled = 0,
		.wakeup_events = 1,
	};
	int map_fd, nfd = 0, max_cpus, err;
	struct bpf_link **links = NULL;
	struct map_deadlock *skel;
	struct bpf_program *prog;
	struct thread_arg targ;
	bool stop = false;
	int *fds = NULL;
	pthread_t thr;

	skel = map_deadlock__open();
	if (!ASSERT_OK_PTR(skel, "map_deadlock__open"))
		return;
	skel->rodata->map_index = map_index;
	err = map_deadlock__load(skel);
	if (!ASSERT_OK(err, "map_deadlock__load"))
		goto out;

	prog = skel->progs.on_perf;
	map_fd = bpf_object__find_map_fd_by_name(skel->obj, map_name);
	if (!ASSERT_GE(map_fd, 0, map_name))
		goto out;

	max_cpus = libbpf_num_possible_cpus();
	if (!ASSERT_GT(max_cpus, 0, "num cpus"))
		goto out;

	links = calloc(max_cpus, sizeof(*links));
	ASSERT_OK_PTR(links, "alloc links");
	fds = calloc(max_cpus, sizeof(*fds));
	ASSERT_OK_PTR(fds, "alloc fds");
	for (int i = 0; i < max_cpus; i++)
		fds[i] = -1;

	nfd = perf_open_all_cpus(&attr, fds, max_cpus);
	if (!ASSERT_GT(nfd, 0, "perf fds"))
		goto out;

	for (int cpu = 0; cpu < max_cpus; cpu++) {
		if (fds[cpu] < 0)
			continue;
		links[cpu] = bpf_program__attach_perf_event(prog, fds[cpu]);
		if (!ASSERT_OK_PTR(links[cpu], "attach perf"))
			goto out;
	}

	targ.map_fd = map_fd;
	targ.stop = &stop;
	err = pthread_create(&thr, NULL, user_update_thread, &targ);
	if (!ASSERT_OK(err, "create thr"))
		goto out;

	/* 1 second should be enough to trigger the deadlock */
	sleep(1);
	stop = true;
	(void)pthread_join(thr, NULL);
	/* TODO: read dmesg to check the deadlock? */
out:
	if (links) {
		for (int cpu = 0; cpu < max_cpus; cpu++) {
			if (links[cpu])
				bpf_link__destroy(links[cpu]);
		}
	}
	if (fds) {
		for (int cpu = 0; cpu < max_cpus; cpu++) {
			if (fds[cpu] >= 0)
				close(fds[cpu]);
		}
	}
	free(links);
	free(fds);
	map_deadlock__destroy(skel);
}

void test_map_deadlock(void)
{
	if (test__start_subtest("lru"))
		test_map("lru_map", 0);
}
