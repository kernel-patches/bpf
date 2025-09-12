// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_arena_common.h"

#if (defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_x86) || \
	(defined(__TARGET_ARCH_riscv) && __riscv_xlen == 64) || \
	defined(__TARGET_ARCH_arm) || defined(__TARGET_ARCH_s390) || \
	defined(__TARGET_ARCH_loongarch)) && \
	__clang_major__ >= 18

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

SEC("syscall")
__description("ldsx_disasm")
__success
__arch_x86_64
__jited("movslq	0x10(%rax,%r12), %r14")
__jited("movswq	0x18(%rax,%r12), %r14")
__jited("movsbq	0x20(%rax,%r12), %r14")
__jited("movslq	0x10(%rdi,%r12), %r15")
__jited("movswq	0x18(%rdi,%r12), %r15")
__jited("movsbq	0x20(%rdi,%r12), %r15")
__arch_arm64
__jited("add	x11, x7, x28")
__jited("ldrsw	x21, [x11, #0x10]")
__jited("add	x11, x7, x28")
__jited("ldrsh	x21, [x11, #0x18]")
__jited("add	x11, x7, x28")
__jited("ldrsb	x21, [x11, #0x20]")
__jited("add	x11, x0, x28")
__jited("ldrsw	x22, [x11, #0x10]")
__jited("add	x11, x0, x28")
__jited("ldrsh	x22, [x11, #0x18]")
__jited("add	x11, x0, x28")
__jited("ldrsb	x22, [x11, #0x20]")
__naked void arena_ldsx_disasm(void *ctx)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"r2 = 0;"
	"r3 = 1;"
	"r4 = %[numa_no_node];"
	"r5 = 0;"
	"call %[bpf_arena_alloc_pages];"
	"r0 = addr_space_cast(r0, 0x0, 0x1);"
	"r1 = r0;"
	"r8 = *(s32 *)(r0 + 16);"
	"r8 = *(s16 *)(r0 + 24);"
	"r8 = *(s8  *)(r0 + 32);"
	"r9 = *(s32 *)(r1 + 16);"
	"r9 = *(s16 *)(r1 + 24);"
	"r9 = *(s8  *)(r1 + 32);"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_arena_alloc_pages),
	   __imm_addr(arena),
	   __imm_const(numa_no_node, NUMA_NO_NODE)
	:  __clobber_all
	);
}

SEC("syscall")
__description("ldsx_exception")
__success __retval(0)
__arch_x86_64
__arch_arm64
__naked void arena_ldsx_exception(void *ctx)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"r0 = 0xdeadbeef;"
	"r0 = addr_space_cast(r0, 0x0, 0x1);"
	"r1 = 0x3fe;"
	"*(u64 *)(r0 + 0) = r1;"
	"r0 = *(s8 *)(r0 + 0);"
	"exit;"
	:
	:  __imm_addr(arena)
	:  __clobber_all
	);
}

SEC("syscall")
__description("ldsx_s8")
__success __retval(-1)
__arch_x86_64
__arch_arm64
__naked void arena_ldsx_s8(void *ctx)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"r2 = 0;"
	"r3 = 1;"
	"r4 = %[numa_no_node];"
	"r5 = 0;"
	"call %[bpf_arena_alloc_pages];"
	"r0 = addr_space_cast(r0, 0x0, 0x1);"
	"r1 = 0x3fe;"
	"*(u64 *)(r0 + 0) = r1;"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	"r0 = *(s8 *)(r0 + 0);"
#else
	"r0 = *(s8 *)(r0 + 7);"
#endif
	"r0 >>= 1;"
	"exit;"
	:: __imm(bpf_arena_alloc_pages),
	   __imm_addr(arena),
	   __imm_const(numa_no_node, NUMA_NO_NODE)
	:  __clobber_all
	);
}

SEC("syscall")
__description("ldsx_s16")
__success __retval(-1)
__arch_x86_64
__arch_arm64
__naked void arena_ldsx_s16(void *ctx)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"r2 = 0;"
	"r3 = 1;"
	"r4 = %[numa_no_node];"
	"r5 = 0;"
	"call %[bpf_arena_alloc_pages];"
	"r0 = addr_space_cast(r0, 0x0, 0x1);"
	"r1 = 0x3fffe;"
	"*(u64 *)(r0 + 0) = r1;"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	"r0 = *(s16 *)(r0 + 0);"
#else
	"r0 = *(s16 *)(r0 + 6);"
#endif
	"r0 >>= 1;"
	"exit;"
	:: __imm(bpf_arena_alloc_pages),
	   __imm_addr(arena),
	   __imm_const(numa_no_node, NUMA_NO_NODE)
	:  __clobber_all
	);
}

SEC("syscall")
__description("ldsx_s32")
__success __retval(-1)
__arch_x86_64
__arch_arm64
__naked void arena_ldsx_s32(void *ctx)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"r2 = 0;"
	"r3 = 1;"
	"r4 = %[numa_no_node];"
	"r5 = 0;"
	"call %[bpf_arena_alloc_pages];"
	"r0 = addr_space_cast(r0, 0x0, 0x1);"
	"r1 = 0xfffffffe;"
	"*(u64 *)(r0 + 0) = r1;"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	"r0 = *(s32 *)(r0 + 0);"
#else
	"r0 = *(s32 *)(r0 + 4);"
#endif
	"r0 >>= 1;"
	"exit;"
	:: __imm(bpf_arena_alloc_pages),
	   __imm_addr(arena),
	   __imm_const(numa_no_node, NUMA_NO_NODE)
	:  __clobber_all
	);
}

/* to retain debug info for BTF generation */
void kfunc_root(void)
{
	bpf_arena_alloc_pages(0, 0, 0, 0, 0);
}

#else

SEC("socket")
__description("cpuv4 is not supported by compiler or jit, use a dummy test")
__success
int dummy_test(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
