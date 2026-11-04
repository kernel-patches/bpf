// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EBUSY 16

char _license[] SEC("license") = "GPL";

/* The test process; bpftool runs as its child or grandchild via popen(). */
int test_tgid;
/* 1-based batch lookup to fail, -1 to fail all of them, 0 for none. */
int fail_batch;
int batch_calls;
int elem_calls;

static bool is_test_bpftool(void)
{
	struct task_struct *task = bpf_get_current_task_btf();

	return BPF_CORE_READ(task, real_parent, tgid) == test_tgid ||
	       BPF_CORE_READ(task, real_parent, real_parent, tgid) == test_tgid;
}

SEC("fmod_ret/security_bpf")
int BPF_PROG(count_bpftool_lookups, int cmd, union bpf_attr *attr,
	     unsigned int size, bool kernel)
{
	if (kernel || !is_test_bpftool())
		return 0;

	if (cmd == BPF_MAP_LOOKUP_ELEM) {
		elem_calls++;
	} else if (cmd == BPF_MAP_LOOKUP_BATCH) {
		batch_calls++;
		/* Trigger fallback rather than end-of-iteration (-ENOENT). */
		if (fail_batch < 0 || fail_batch == batch_calls)
			return -EBUSY;
	}
	return 0;
}
