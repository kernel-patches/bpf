#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "../bpf_testmod/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

extern void bpf_task_release(struct task_struct *p) __ksym;

__noinline int subprog_release(__u64 *ctx __arg_ctx)
{
	struct task_struct *task = (struct task_struct *)ctx[1];
	int dummy = (int)ctx[0];

	bpf_task_release(task);

	return dummy + 1;
}

SEC("struct_ops/test_refcounted")
int test_refcounted(unsigned long long *ctx)
{
	struct task_struct *task = (struct task_struct *)ctx[1];

	bpf_task_release(task);

	return subprog_release(ctx);
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_ref_acquire = {
	.test_refcounted = (void *)test_refcounted,
};
