// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Huawei Technologies Inc. */
#include <test_progs.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include "bpf/libbpf_internal.h"
#include "arena_percpu_only.skel.h"
#include "arena_percpu_mixed.skel.h"

static char log_buf[16384];
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

/* check out of range pseudo instructions and accesses */
static void test_arena_percpu_percpu_bounds(void)
{
	struct bpf_insn insns[] = {
		BPF_LD_IMM64_RAW(BPF_REG_1, BPF_PSEUDO_ARENA_PERCPU, 0),
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 0),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	LIBBPF_OPTS(bpf_map_create_opts, map_opts);
	LIBBPF_OPTS(bpf_prog_load_opts, prog_opts);
	bool *possible = NULL;
	__u32 page_sz = getpagesize();
	__u32 bad_offs[2];
	char expected[128];
	void *arena = MAP_FAILED;
	int possible_cpus, nr_pages, map_fd, prog_fd, i;

	if (parse_possible_cpus(&possible, &possible_cpus))
		return;

	/* a one-page per-cpu chunk at page 1 of the arena */
	map_opts.map_flags = BPF_F_MMAPABLE;
	map_opts.arena_percpu_chunk_off = page_sz;
	map_opts.arena_percpu_chunk_sz = page_sz;

	prog_opts.log_buf = log_buf;
	prog_opts.log_size = sizeof(log_buf);
	prog_opts.log_level = 1;

	/* one page per possible cpu plus one for the chunk offset */
	nr_pages = possible_cpus + 1;

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena_percpu_ref",
				0, 0, nr_pages, &map_opts);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		goto out;

	arena = mmap(NULL, nr_pages * page_sz, PROT_READ | PROT_WRITE,
		     MAP_SHARED, map_fd, 0);
	if (!ASSERT_NEQ(arena, MAP_FAILED, "arena_mmap"))
		goto out;

	insns[0].imm = map_fd;

	/* a reference at the start of the chunk loads */
	insns[1].imm = page_sz;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT,
				"arena_percpu_ref", "GPL", insns,
				ARRAY_SIZE(insns), &prog_opts);
	if (!ASSERT_GE(prog_fd, 0, "in_range_load"))
		goto out;
	close(prog_fd);

	/* the first u64 below the chunk and one past its end are rejected */
	bad_offs[0] = page_sz - 8;
	bad_offs[1] = page_sz + page_sz;

	for (i = 0; i < ARRAY_SIZE(bad_offs); i++) {
		insns[1].imm = bad_offs[i];
		prog_fd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT,
					"arena_percpu_ref", "GPL", insns,
					ARRAY_SIZE(insns), &prog_opts);
		if (!ASSERT_LT(prog_fd, 0, "out_of_range_load"))
			close(prog_fd);
		snprintf(expected, sizeof(expected),
			 "per-cpu arena reference at offset %u "
			 "outside cpu 0's chunk", bad_offs[i]);
		ASSERT_HAS_SUBSTR(log_buf, expected, "out_of_range_log");
	}

	/* the last u64 of the chunk is in range and loads */
	insns[1].imm = page_sz + page_sz - 8;
	insns[2].off = 0;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT,
				"arena_percpu_ref", "GPL", insns,
				ARRAY_SIZE(insns), &prog_opts);
	if (!ASSERT_GE(prog_fd, 0, "last_u64_load"))
		goto out;
	close(prog_fd);

	/* one u64 past the chunk end is rejected */
	insns[2].off = 8;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT,
				"arena_percpu_ref", "GPL", insns,
				ARRAY_SIZE(insns), &prog_opts);
	if (!ASSERT_LT(prog_fd, 0, "out_of_range_access"))
		close(prog_fd);
	snprintf(expected, sizeof(expected),
		 "per-cpu arena access at offset %d size 8 "
		 "outside cpu 0's chunk", (int)page_sz);
	ASSERT_HAS_SUBSTR(log_buf, expected, "out_of_range_access_log");

	/* an access below the chunk start is rejected */
	insns[1].imm = page_sz;
	insns[2].off = -8;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT,
				"arena_percpu_ref", "GPL", insns,
				ARRAY_SIZE(insns), &prog_opts);
	if (!ASSERT_LT(prog_fd, 0, "below_chunk_access"))
		close(prog_fd);
	snprintf(expected, sizeof(expected),
		 "per-cpu arena access at offset -8 size 8 "
		 "outside cpu 0's chunk");
	ASSERT_HAS_SUBSTR(log_buf, expected, "below_chunk_access_log");

out:
	if (arena != MAP_FAILED)
		munmap(arena, nr_pages * page_sz);
	if (map_fd >= 0)
		close(map_fd);
	free(possible);
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
	if (test__start_subtest("percpu_bounds"))
		test_arena_percpu_percpu_bounds();
}
