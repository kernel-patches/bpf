// SPDX-License-Identifier: GPL-2.0
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include "bench.h"
#include "tailcall_bench.skel.h"

static struct ctx {
	struct tailcall_bench *skel;
	struct bpf_link *link;
	int map_fd;
	int ncpus;
	unsigned int percpu_size;
} ctx;

static void tailcall_measure(struct bench_res *res)
{
	__u32 key = 0;
	__u8 *values;
	__u64 total_hits = 0;

	values = calloc(ctx.ncpus, ctx.percpu_size);
	if (!values)
		return;

	if (bpf_map_lookup_elem(ctx.map_fd, &key, values) != 0)
		return;

	for (int i = 0; i < ctx.ncpus; i++)
		total_hits += *(__u64 *)(values + i * ctx.percpu_size);

	res->hits = total_hits;
	free(values);
}

static void *tailcall_producer(void *input)
{
	unsigned long arg = 0;

	while (true) {
		/* Toggle the argument between 0 and 1 on every iteration */
		syscall(__NR_getpgid, arg & 1);
		arg++;
	}

	return NULL;
}

static void tailcall_setup(void)
{
	int main_fd, target_fd, jmp_map_fd;
	__u32 key1 = 1;

	ctx.skel = tailcall_bench__open();
	if (!ctx.skel)
		exit(1);

	ctx.skel->data->my_pid = getpid();
	ctx.ncpus = libbpf_num_possible_cpus();

	if (tailcall_bench__load(ctx.skel))
		exit(1);

	jmp_map_fd = bpf_map__fd(ctx.skel->maps.jmp_table);
	ctx.map_fd = bpf_map__fd(ctx.skel->maps.pcpu_hits_map);
	ctx.percpu_size = bpf_map__value_size(ctx.skel->maps.pcpu_hits_map);

	if (ctx.map_fd < 0 || jmp_map_fd < 0)
		exit(1);

	main_fd = bpf_program__fd(ctx.skel->progs.tailcall_bench_main);
	target_fd = bpf_program__fd(ctx.skel->progs.tailcall_bench_target);

	/* Map key 1 directly to the final target program */
	bpf_map_update_elem(jmp_map_fd, &key1, &target_fd, BPF_ANY);

	ctx.link = bpf_program__attach(ctx.skel->progs.tailcall_bench_main);
	if (!ctx.link)
		exit(1);
}

const struct bench bench_tailcall = {
	.name = "tailcall",
	.setup = tailcall_setup,
	.producer_thread = tailcall_producer,
	.measure = tailcall_measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
};
