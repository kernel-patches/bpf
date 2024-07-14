#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "../bpf_testmod/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

struct cgroup *bpf_cgroup_acquire(struct cgroup *p) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;

/* This test struct_ops BPF programs returning referenced kptr. The verifier should
 * reject programs returning a referenced kptr of the wrong type.
 */
SEC("struct_ops/test_return_ref_kptr")
struct task_struct *BPF_PROG(test_return_ref_kptr, int dummy,
			     struct task_struct *task, struct cgroup *cgrp)
{
	struct task_struct *ret;

	ret = (struct task_struct *)bpf_cgroup_acquire(cgrp);
	bpf_task_release(task);

	return ret;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_kptr_return = {
	.test_return_ref_kptr = (void *)test_return_ref_kptr,
};
