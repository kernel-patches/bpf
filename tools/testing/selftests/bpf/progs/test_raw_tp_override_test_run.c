// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u32 flag = 0;

/**
 * This program overrides raw_tp_override_probe handler in
 * tracepoint bpf_testmode_test_raw_tp_null_tp.
 */
SEC("raw_tp.o/bpf_testmod_test_write_bare_tp:raw_tp_override_probe")
int BPF_PROG(tp_override, struct task_struct *task, char *comm)
{
	flag = 1;
	return 0;
}

char _license[] SEC("license") = "GPL";
