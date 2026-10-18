// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/*
 * llvm lowers unwinding to plain insns:
 *   ret                      r3 = 0; exit
 *   invoke foo unwind pad    call foo; if r3 != 0 goto pad
 *   resume                   r0 = 0; r3 = 1; exit
 * and puts this tag on the functions that say something in r3.
 * The tests spell the insns out, so they don't depend on llvm version.
 */
#define __unwind __attribute__((btf_decl_tag("unwind")))

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} prog_array SEC(".maps");

/*
 * The verifier removes 'if r3 != 0' when it knows r3. To have it at run time
 * the tests pass skb->len, which is 64, or skb->len - 64.
 *
 * r1 == 0: returns 7, otherwise unwinds
 */
__naked __noinline __used __unwind
static unsigned long may_unwind(void)
{
	asm volatile (
		"if r1 != 0 goto 1f;"
		"r0 = 7;"
		"r3 = 0;"
		"exit;"
	"1:"
		"r0 = 0;"
		"r3 = 1;"
		"exit;"
	);
}

/* owns nothing: its pad only resumes */
__naked __noinline __used __unwind
static unsigned long passes_on(void)
{
	asm volatile (
		"call may_unwind;"
		"if r3 != 0 goto 1f;"
		"r0 += 1;"
		"r3 = 0;"
		"exit;"
	"1:"
		"r0 = 0;"
		"r3 = 1;"
		"exit;"
	);
}

__naked __noinline __used __unwind
unsigned long global_returns(void)
{
	asm volatile (
		"r0 = 7;"
		"r3 = 0;"
		"exit;"
	);
}

__naked __noinline __used __unwind
unsigned long global_unwinds(void)
{
	asm volatile (
		"r0 = 0;"
		"r3 = 1;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: the callee returns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int callee_returns(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"r1 -= 64;"
		"call may_unwind;"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len))
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: the callee unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(42)
__naked int callee_unwinds(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"call may_unwind;"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len))
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: return through two frames")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(8)
__naked int two_frames_return(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"r1 -= 64;"
		"call passes_on;"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len))
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: unwind through two frames")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(42)
__naked int two_frames_unwind(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"call passes_on;"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len))
		: __clobber_all
	);
}

/* 'if r3 != 0' makes r3 precise. The chain goes into the callee through its exit. */
SEC("tc")
__description("unwind: precision of r3 is tracked into the callee")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("mark_precise: frame0: regs=r3 stack= before 12: (95) exit")
__msg("mark_precise: frame1: regs=r3 stack= before 11: (b7) r3 = 1")
__naked int r3_precision(void)
{
	asm volatile (
		"r1 = 1;"
		"call may_unwind;"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("unwind: the pad drops what the frame owns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success
__naked int pad_unlocks(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call %[bpf_get_prandom_u32];"
		"r1 = r0;"
		"call may_unwind;"
		"if r3 != 0 goto 1f;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
	"1:"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock),
		  __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: the pad is checked like any other code")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_rcu_read_lock-ed region")
__naked int pad_forgets_to_unlock(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call %[bpf_get_prandom_u32];"
		"r1 = r0;"
		"call may_unwind;"
		"if r3 != 0 goto 1f;"
		"call %[bpf_rcu_read_unlock];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock),
		  __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/* The verifier doesn't look into a global subprog at the call: it may unwind. */
SEC("tc")
__description("unwind: r3 is unknown after a call to a global subprog")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_rcu_read_lock-ed region")
__naked int global_pad_forgets_to_unlock(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call global_returns;"
		"if r3 != 0 goto 1f;"
		"call %[bpf_rcu_read_unlock];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: a global subprog returns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int calls_global_returns(void)
{
	asm volatile (
		"call global_returns;"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("unwind: a global subprog unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(42)
__naked int calls_global_unwinds(void)
{
	asm volatile (
		"call global_unwinds;"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		::: __clobber_all
	);
}

__naked __noinline __used
static unsigned long no_tag(void)
{
	asm volatile (
		"r0 = 0;"
		"r3 = 0;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: r3 is not readable after a call to a subprog without the tag")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("R3 !read_ok")
__naked int callee_has_no_tag(void)
{
	asm volatile (
		"call no_tag;"
		"if r3 != 0 goto 1f;"
	"1:"
		"exit;"
		::: __clobber_all
	);
}

__naked __noinline __used __unwind
static unsigned long r3_not_set(void)
{
	asm volatile (
		"r0 = 0;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: static subprog doesn't set r3")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("R3 !read_ok")
__naked int static_r3_not_set(void)
{
	asm volatile (
		"call r3_not_set;"
		"exit;"
		::: __clobber_all
	);
}

__naked __noinline __used __unwind
static unsigned long r3_is_pointer(void)
{
	asm volatile (
		"r0 = 0;"
		"r3 = r10;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: static subprog leaves a pointer in r3")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("At subprogram exit the register R3 is not a scalar value (fp)")
__naked int static_r3_is_pointer(void)
{
	asm volatile (
		"call r3_is_pointer;"
		"exit;"
		::: __clobber_all
	);
}

__naked __noinline __used __unwind
unsigned long global_r3_not_set(void)
{
	asm volatile (
		"r0 = 0;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: global subprog doesn't set r3")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("R3 !read_ok")
__naked int calls_global_r3_not_set(void)
{
	asm volatile (
		"call global_r3_not_set;"
		"exit;"
		::: __clobber_all
	);
}

__naked __noinline __used __unwind
unsigned long global_r3_is_pointer(void)
{
	asm volatile (
		"r0 = 0;"
		"r3 = r10;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: global subprog leaves a pointer in r3")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("At subprogram exit the register R3 is not a scalar value (fp)")
__naked int calls_global_r3_is_pointer(void)
{
	asm volatile (
		"call global_r3_is_pointer;"
		"exit;"
		::: __clobber_all
	);
}

/* The helper that calls a callback doesn't look at r3. */
__naked __noinline __used __unwind
static unsigned long cb_returns(void)
{
	asm volatile (
		"r0 = 0;"
		"r3 = 0;"
		"exit;"
	);
}

__naked __noinline __used __unwind
static unsigned long cb_unwinds(void)
{
	asm volatile (
		"r0 = 0;"
		"r3 = 1;"
		"exit;"
	);
}

__naked __noinline __used __unwind
static unsigned long cb_r3_not_set(void)
{
	asm volatile (
		"r0 = 0;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: callback returns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(3)
__naked int callback_returns(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[cb_returns];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm_ptr(cb_returns),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind: callback unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("callback cannot unwind")
__naked int callback_unwinds(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind: callback doesn't set r3")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("callback cannot unwind")
__naked int callback_r3_not_set(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[cb_r3_not_set];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm_ptr(cb_r3_not_set),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Both return to the caller of the subprog with whatever is in r3. */
__naked __noinline __used __unwind
static unsigned long does_tail_call(void)
{
	asm volatile (
		"r2 = %[prog_array] ll;"
		"r3 = 0;"
		"call %[bpf_tail_call];"
		"r0 = 0;"
		"r3 = 0;"
		"exit;"
		:
		: __imm(bpf_tail_call),
		  __imm_addr(prog_array)
	);
}

SEC("tc")
__description("unwind: tail call in a subprog that can unwind")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("tail call or ld_abs in a subprog that can unwind")
__naked int tail_call_in_subprog(void)
{
	asm volatile (
		"call does_tail_call;"
		"exit;"
		::: __clobber_all
	);
}

__naked __noinline __used __unwind
static unsigned long does_ld_abs(void)
{
	asm volatile (
		"r6 = r1;"
		"r0 = *(u8*)skb[0];"
		"r3 = 0;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: ld_abs in a subprog that can unwind")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("tail call or ld_abs in a subprog that can unwind")
__naked int ld_abs_in_subprog(void)
{
	asm volatile (
		"call does_ld_abs;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * JITs don't emit 'if r3 != 0 goto pad' after a call. It becomes an extable entry.
 * An exit with r3 != 0 looks its return address up there.
 */
SEC("tc")
__description("unwind: jit: no branch after the call")
__success __retval(42)
__load_if_JITed()
__arch_x86_64
__jited("	callq	0x{{.*}}")
__jited("	movl	$0x7, %eax")
__jited("...")
__jited("	movl	$0x1, %edx")
__jited("	pushq	%rax")
__jited("	pushq	%rsi")
__jited("	pushq	%rdx")
__jited("	movq	0x8(%rbp), %rdi")
__jited("	callq	0x{{.*}}")
__jited("	movq	%rax, 0x8(%rbp)")
__jited("	popq	%rdx")
__jited("	popq	%rsi")
__jited("	popq	%rax")
__arch_arm64
__jited("	bl	{{.*}}")
__jited("	mov	x8, x0")
__jited("	mov	x8, #0x7")
__jited("...")
__jited("	mov	x2, #0x1")
__jited("	stp	x8, x1, [sp, #-0x10]!")
__jited("	stp	x2, xzr, [sp, #-0x10]!")
__jited("	ldr	x17, [x29, #0x8]")
__jited("...")
__jited("	str	x17, [x29, #0x8]")
__jited("	ldp	x2, xzr, [sp], #0x10")
__jited("	ldp	x8, x1, [sp], #0x10")
__naked int jit_no_branch(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"call may_unwind;"
		"if r3 != 0 goto 1f;"
		"r0 = 7;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len))
		: __clobber_all
	);
}

/* The exit cannot tell what is in r3 */
__naked __noinline __used __unwind
static unsigned long r3_from_r1(void)
{
	asm volatile (
		"r0 = 0;"
		"r3 = r1;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: jit: exit looks at r3, returns")
__success __retval(7)
__load_if_JITed()
__arch_x86_64
__jited("	movq	%rdi, %rdx")
__jited("	testq	%rdx, %rdx")
__jited("	je	{{.*}}")
__jited("	pushq	%rax")
__arch_arm64
__jited("	mov	x2, x0")
__jited("	cbz	x2, {{.*}}")
__jited("	stp	x8, x1, [sp, #-0x10]!")
__naked int jit_exit_looks_at_r3_returns(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"r1 -= 64;"
		"call r3_from_r1;"
		"if r3 != 0 goto 1f;"
		"r0 = 7;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len))
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: jit: exit looks at r3, unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(42)
__naked int jit_exit_looks_at_r3_unwinds(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"call r3_from_r1;"
		"if r3 != 0 goto 1f;"
		"r0 = 7;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len))
		: __clobber_all
	);
}

/* Something else jumps to the branch, so it has to be there */
SEC("tc")
__description("unwind: jit: the branch is a jump target")
__success
__load_if_JITed()
__arch_x86_64
__jited("	movl	$0x1, %edi")
__jited("	callq	0x{{.*}}")
__jited("{{.*}}	testq	%rdx, %rdx")
__jited("	jne	{{.*}}")
__arch_arm64
__jited("	mov	x0, #0x1")
__jited("	bl	{{.*}}")
__jited("	mov	x8, x0")
__jited("{{.*}}	cmp	x2, #0x0")
__jited("	b.ne	{{.*}}")
__naked int jit_branch_is_jump_target(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		"r3 = 0;"
		"if r0 == 0 goto 2f;"
		"r1 = 1;"
		"call may_unwind;"
	"2:"
		"if r3 != 0 goto 1f;"
		"r0 = 7;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/*
 * BTF FUNC records are not generated for kfuncs referenced
 * from inline assembly. These records are necessary for
 * libbpf to link the program. The function below is a hack
 * to ensure that BTF FUNC records are generated.
 */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
}

char _license[] SEC("license") = "GPL";
