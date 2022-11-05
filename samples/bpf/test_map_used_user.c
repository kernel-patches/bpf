// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 ByteDance
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <sys/types.h>
#include <asm/unistd.h>
#include <unistd.h>
#include <assert.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <signal.h>
#include <linux/bpf.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define TEST_BIT(t) (1U << (t))
#define MAX_NR_CPUS 1024

static __u64 time_get_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

enum test_type {
	HASH_TOUCH_PREALLOC,
	HASH_TOUCH,
	NR_TESTS,
};

const char *test_map_names[NR_TESTS] = {
	[HASH_TOUCH_PREALLOC] = "hash_map",
	[HASH_TOUCH] = "hash_map",
};

static int test_flags = ~0;
static __u32 num_map_entries;
static __u32 inner_lru_hash_size;
static __u32 max_cnt = 1000;

static int check_test_flags(enum test_type t)
{
	return test_flags & TEST_BIT(t);
}

static void test_hash_touch_prealloc(int cpu)
{
	__u64 start_time;
	int i;

	start_time = time_get_ns();
	for (i = 0; i < max_cnt; i++)
		syscall(__NR_umount2, NULL, 0);
	printf("%d:hash_touch pre-alloc %lld touches per sec\n",
		   cpu, max_cnt * 1000000000ll / (time_get_ns() - start_time));
}

static void test_hash_touch(int cpu)
{
	__u64 start_time;
	int i;

	start_time = time_get_ns();
	for (i = 0; i < max_cnt; i++)
		syscall(__NR_mount, NULL, NULL, NULL, 0, NULL);
	printf("%d:hash_touch %lld touchess per sec\n",
		   cpu, max_cnt * 1000000000ll * 64 / (time_get_ns() - start_time));
}

typedef void (*test_func)(int cpu);
const test_func test_funcs[] = {
	[HASH_TOUCH_PREALLOC] = test_hash_touch_prealloc,
	[HASH_TOUCH] = test_hash_touch,
};

static void loop(int cpu)
{
	cpu_set_t cpuset;
	int i;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	sched_setaffinity(0, sizeof(cpuset), &cpuset);

	for (i = 0; i < NR_TESTS; i++) {
		if (check_test_flags(i))
			test_funcs[i](cpu);
	}
}

static void run_perf_test(int tasks)
{
	pid_t pid[tasks];
	int i;

	for (i = 0; i < tasks; i++) {
		pid[i] = fork();
		if (pid[i])
			printf("Spawn process #%d [%u]\n", i, pid[i]);

		if (pid[i] == 0) {
			loop(i);
			exit(0);
		} else if (pid[i] == -1) {
			printf("couldn't spawn #%d process\n", i);
			exit(1);
		}
	}
	for (i = 0; i < tasks; i++) {
		int status;

		assert(waitpid(pid[i], &status, 0) == pid[i]);
		assert(status == 0);
	}
}

static void fixup_map(struct bpf_object *obj)
{
	struct bpf_map *map;
	int i;

	bpf_object__for_each_map(map, obj) {
		const char *name = bpf_map__name(map);

		/* Only change the max_entries for the enabled test(s) */
		for (i = 0; i < NR_TESTS; i++) {
			if (!strcmp(test_map_names[i], name) &&
				(check_test_flags(i))) {
				bpf_map__set_max_entries(map, num_map_entries);
				continue;
			}
		}
	}

	inner_lru_hash_size = num_map_entries;
}

int main(int argc, char **argv)
{
	int nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	struct bpf_link *links[8];
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	int i = 0;

	if (argc > 1)
		test_flags = atoi(argv[1]) ? : test_flags;

	if (argc > 2)
		nr_cpus = atoi(argv[2]) ? : nr_cpus;

	if (argc > 3)
		num_map_entries = atoi(argv[3]);

	if (argc > 4)
		max_cnt = atoi(argv[4]);

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	/* resize BPF map prior to loading */
	if (num_map_entries > 0)
		fixup_map(obj);

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	bpf_object__for_each_program(prog, obj) {
		links[i] = bpf_program__attach(prog);
		if (libbpf_get_error(links[i])) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
			links[i] = NULL;
			goto cleanup;
		}
		i++;
	}

	run_perf_test(nr_cpus);

cleanup:
	for (i--; i >= 0; i--)
		bpf_link__destroy(links[i]);

	bpf_object__close(obj);
	return 0;
}
