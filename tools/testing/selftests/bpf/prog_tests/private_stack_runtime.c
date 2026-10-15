// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "private_stack_runtime.h"
#include "private_stack_runtime.skel.h"

void test_private_stack_runtime(void)
{
#if defined(__riscv) && __riscv_xlen == 64
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
	);
	struct private_stack_runtime *skel;
	struct bpf_link *trace = NULL, *ops = NULL;
	cpu_set_t saved, single;
	int cpu, err, tested = 0;

	/*
	 * Two independent halves. RUN_TESTS() validates the __jited patterns
	 * through the test loader, which builds its own object from the ELF
	 * bytes. The half below loads a separate skeleton to check the runtime
	 * values and the CPU the program reported, which disassembly patterns
	 * cannot express.
	 */
	RUN_TESTS(private_stack_runtime);

	if (!ASSERT_OK(sched_getaffinity(0, sizeof(saved), &saved), "getaffinity"))
		return;

	skel = private_stack_runtime__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	if (!skel->rodata->has_stack_args) {
		test__skip();
		goto out;
	}
	skel->rodata->target_tgid = getpid();
	if (!ASSERT_OK(private_stack_runtime__load(skel), "load"))
		goto out;

	trace = bpf_program__attach_raw_tracepoint(skel->progs.private_args, "sys_enter");
	if (!ASSERT_OK_PTR(trace, "attach_tracepoint"))
		goto out;

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, &saved))
			continue;
		CPU_ZERO(&single);
		CPU_SET(cpu, &single);
		if (!ASSERT_OK(sched_setaffinity(0, sizeof(single), &single), "setaffinity"))
			break;

		err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.kernel_args), &opts);
		if (!ASSERT_OK(err, "kernel_args") || !ASSERT_EQ(opts.retval, 0, "retval"))
			break;
		syscall(__NR_getpgid, 0);
		ASSERT_EQ(skel->bss->private_result.value, 324 + getpid(), "private_value");
		ASSERT_EQ(skel->bss->private_result.first, 29, "private_first");
		ASSERT_EQ(skel->bss->private_result.last, 324, "private_last");
		ASSERT_EQ(skel->bss->private_result.cpu, cpu, "private_cpu");
		ASSERT_EQ(skel->bss->kernel_result.value, 324 + getpid(), "kernel_value");
		ASSERT_EQ(skel->bss->kernel_result.first, 29, "kernel_first");
		ASSERT_EQ(skel->bss->kernel_result.last, 324, "kernel_last");
		ASSERT_EQ(skel->bss->kernel_result.cpu, cpu, "kernel_cpu");
		tested++;
	}
	ASSERT_GT(tested, 0, "tested_cpus");

	ops = bpf_map__attach_struct_ops(skel->maps.zero_stack_ops);
	if (!ASSERT_OK_PTR(ops, "attach_zero_stack"))
		goto out;
	ASSERT_OK(trigger_module_test_read(256), "trigger_zero_stack");
	ASSERT_EQ(skel->bss->zero_calls, 1, "zero_stack_calls");
out:
	bpf_link__destroy(ops);
	bpf_link__destroy(trace);
	private_stack_runtime__destroy(skel);
	ASSERT_OK(sched_setaffinity(0, sizeof(saved), &saved), "restore_affinity");
#else
	test__skip();
#endif
}
