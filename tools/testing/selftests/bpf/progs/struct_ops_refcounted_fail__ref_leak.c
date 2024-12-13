#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "../bpf_testmod/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops/test_refcounted")
int BPF_PROG(test_refcounted, int dummy,
	     struct task_struct *task)
{
	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_ref_acquire = {
	.test_refcounted = (void *)test_refcounted,
};
