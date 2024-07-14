#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "../bpf_testmod/bpf_testmod.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

extern void bpf_task_release(struct task_struct *p) __ksym;

/* This is a test BPF program that uses struct_ops to access a referenced
 * kptr argument. This is a test for the verifier to ensure that it
 * 1) recongnizes the task as a referenced object (i.e., ref_obj_id > 0), and
 * 2) the same reference can be acquired from multiple paths as long as it
 *    has not been released.
 *
 * test_refcounted() is equivalent to the C code below. It is written in assembly
 * to avoid reads from task (i.e., getting referenced kptrs to task) being merged
 * into single path by the compiler.
 *
 * int test_refcounted(int dummy, struct task_struct *task)
 * {
 *         if (dummy % 2)
 *                 bpf_task_release(task);
 *         else
 *                 bpf_task_release(task);
 *         return 0;
 * }
 */
SEC("struct_ops/test_refcounted")
int test_refcounted(unsigned long long *ctx)
{
	asm volatile ("					\
	/* r6 = dummy */				\
	r6 = *(u64 *)(r1 + 0x0);			\
	/* if (r6 & 0x1 != 0) */			\
	r6 &= 0x1;					\
	if r6 == 0 goto l0_%=;				\
	/* r1 = task */					\
	r1 = *(u64 *)(r1 + 0x8);			\
	call %[bpf_task_release];			\
	goto l1_%=;					\
l0_%=:	/* r1 = task */					\
	r1 = *(u64 *)(r1 + 0x8);			\
	call %[bpf_task_release];			\
l1_%=:	/* return 0 */					\
"	:
	: __imm(bpf_task_release)
	: __clobber_all);
	return 0;
}

/* BTF FUNC records are not generated for kfuncs referenced
 * from inline assembly. These records are necessary for
 * libbpf to link the program. The function below is a hack
 * to ensure that BTF FUNC records are generated.
 */
void __btf_root(void)
{
	bpf_task_release(NULL);
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_refcounted = {
	.test_refcounted = (void *)test_refcounted,
};


