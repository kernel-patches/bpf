// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Huawei Technologies Inc. */
#include <test_progs.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include "bpf/libbpf_internal.h"
#include "arena_percpu_only.skel.h"
#include "arena_percpu_mixed.skel.h"

static cpu_set_t affinity_save;

static int pin_to(int cpu)
{
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	return sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

static int run_on_cpu(int cpu, struct bpf_program *prog, const char *name)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	if (pin_to(cpu))
		return -1;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);

	if (!ASSERT_OK(err, name))
		return -1;
	if (!ASSERT_OK(opts.retval, name))
		return -1;
	return 0;
}

static int save_affinity(void)
{
	if (!ASSERT_OK(sched_getaffinity(0, sizeof(affinity_save), &affinity_save),
		       "save_affinity"))
		return -1;
	return 0;
}

static void restore_affinity(void)
{
	sched_setaffinity(0, sizeof(affinity_save), &affinity_save);
}

static int parse_possible_cpus(bool **possible, int *nr_possible)
{
	if (!ASSERT_OK(parse_cpu_mask_file("/sys/devices/system/cpu/possible",
					   possible, nr_possible),
		       "parse_possible"))
		return -1;
	return 0;
}

/* check one cpu's copy of a per-cpu global */
static void check_percpu_value(struct bpf_map *arena, void *var, int cpu,
			       __u64 expected, const char *name)
{
	__u64 *p = bpf_map__arena_percpu_ptr(arena, var, cpu);

	if (!ASSERT_OK_PTR(p, name))
		return;
	ASSERT_EQ(*p, expected, name);
}

static void test_arena_percpu_only(void)
{
	struct arena_percpu_only *skel;
	struct bpf_map *arena;
	bool *possible = NULL;
	int possible_cpus, cpu, picked_cpu = -1, i, err;

	if (save_affinity())
		return;

	skel = arena_percpu_only__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	if (parse_possible_cpus(&possible, &possible_cpus))
		goto out;

	/* size the arena for the per-cpu chunks and load the object */
	if (!ASSERT_OK(bpf_map__set_max_entries(skel->maps.arena, possible_cpus),
		       "set_max_entries"))
		goto out;
	if (!ASSERT_OK(arena_percpu_only__load(skel), "load"))
		goto out;
	arena = skel->maps.arena;

	if (!ASSERT_OK_PTR(skel->arena_percpu, "arena_percpu"))
		goto out;

	/* every chunk starts as a copy of the initialized section */
	for (cpu = 0; cpu < possible_cpus; cpu++) {
		if (!possible[cpu])
			continue;
		check_percpu_value(arena, &skel->arena_percpu->counter, cpu,
				   0x123456, "counter_init");
	}

	/* pick one cpu to pin */
	for (i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &affinity_save)) {
			picked_cpu = i;
			break;
		}
	}
	if (!ASSERT_GE(picked_cpu, 0, "pick_cpu"))
		goto out;

	err = run_on_cpu(picked_cpu, skel->progs.arena_percpu_only_write, "run on cpu");
	if (err < 0)
		goto out;

	/* only the cpu the program ran on got written */
	for (cpu = 0; cpu < possible_cpus; cpu++) {
		if (!possible[cpu])
			continue;

		if (cpu == picked_cpu)
			check_percpu_value(arena, &skel->arena_percpu->counter,
					   cpu, picked_cpu, "counter_written");
		else
			check_percpu_value(arena, &skel->arena_percpu->counter,
					   cpu, 0x123456, "counter_untouched");
	}

out:
	free(possible);
	arena_percpu_only__destroy(skel);
	restore_affinity();
}

static void test_arena_percpu_mixed(void)
{
	struct arena_percpu_mixed *skel;
	struct bpf_map *arena, *bss_map;
	bool *possible = NULL, *online = NULL, *written = NULL;
	int possible_cpus, online_cpus, nr_written = 0, cpu, err;

	if (save_affinity())
		return;

	skel = arena_percpu_mixed__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	if (parse_possible_cpus(&possible, &possible_cpus))
		goto out;

	/* size the arena for the per-cpu chunks and load the object */
	if (!ASSERT_OK(bpf_map__set_max_entries(skel->maps.arena, possible_cpus + 16),
		       "set_max_entries"))
		goto out;
	if (!ASSERT_OK(arena_percpu_mixed__load(skel), "load"))
		goto out;
	arena = skel->maps.arena;

	for (cpu = 0; cpu < possible_cpus; cpu++) {
		if (!possible[cpu])
			continue;

		check_percpu_value(arena, &skel->arena_percpu->data1, cpu,
				   0x123456789, "data1_init");
		check_percpu_value(arena, &skel->arena_percpu->data2, cpu,
				   0x987654321, "data2_init");
	}

	if (!ASSERT_OK(parse_cpu_mask_file("/sys/devices/system/cpu/online",
					   &online, &online_cpus),
		       "parse_online"))
		goto out;

	written = calloc(online_cpus, sizeof(*written));
	if (!ASSERT_OK_PTR(written, "written_alloc"))
		goto out;

	for (cpu = 0; cpu < online_cpus; cpu++) {
		if (!online[cpu] || cpu >= CPU_SETSIZE || !CPU_ISSET(cpu, &affinity_save))
			continue;

		err = run_on_cpu(cpu, skel->progs.arena_percpu_mixed_write, "write");
		if (err < 0)
			goto out;
		if (err > 0)
			continue;
		written[cpu] = true;
		nr_written++;
	}
	if (!ASSERT_GE(nr_written, 1, "cpus_exercised"))
		goto out;

	/* check every written chunk from user space */
	for (cpu = 0; cpu < online_cpus; cpu++) {
		if (!written[cpu])
			continue;

		check_percpu_value(arena, &skel->arena_percpu->data1, cpu,
				   cpu, "data1_written");
		check_percpu_value(arena, &skel->arena_percpu->data2, cpu,
				   cpu << 2, "data2_written");
	}

	/* the __arena global should not be touched */
	ASSERT_EQ(skel->arena->arena_global, 0x5a5ba5a5c0dec0de, "arena_global_intact");

	/* api error paths: cpu out of range, pointer outside cpu 0's chunk */
	ASSERT_ERR_PTR(bpf_map__arena_percpu_ptr(arena, &skel->arena_percpu->data1,
						 possible_cpus), "api_cpu_range");
	ASSERT_ERR_PTR(bpf_map__arena_percpu_ptr(arena, possible, 0),
		       "api_not_in_chunk");

	/* a non-ARENA map has no per-cpu chunks to index */
	bss_map = bpf_object__find_map_by_name(skel->obj, ".bss");
	if (ASSERT_OK_PTR(bss_map, "bss_map"))
		ASSERT_EQ(libbpf_get_error(bpf_map__arena_percpu_ptr(bss_map, &cpu, 0)),
			  -EINVAL, "api_not_arena");

out:
	free(written);
	free(online);
	free(possible);
	arena_percpu_mixed__destroy(skel);
	restore_affinity();
}

void test_arena_percpu(void)
{
	if (!feat_supported(NULL, FEAT_ARENA_PERCPU_DATA)) {
		test__skip();
		return;
	}
	if (test__start_subtest("percpu_only"))
		test_arena_percpu_only();
	if (test__start_subtest("percpu_mixed"))
		test_arena_percpu_mixed();
}
