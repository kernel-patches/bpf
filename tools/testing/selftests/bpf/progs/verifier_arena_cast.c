// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

struct task_struct {};
struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;

#ifdef __TARGET_ARCH_arm64
#define ARENA_VM_START (1ull << 32)
#else
#define ARENA_VM_START (1ull << 44)
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 4);
	__ulong(map_extra, ARENA_VM_START);
} arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, long long);
} hash SEC(".maps");

/* BTF FUNC records are not generated for kfuncs referenced from inline assembly */
void __kfunc_btf_root(void)
{
	bpf_task_release(bpf_task_acquire(0));
}

/* dst = addr_space_cast(src, 0, 1) */
#define CAST_KERN(dst, src) \
	BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, BPF_ADDR_SPACE_CAST, 1)
/* dst = addr_space_cast(src, 1, 0) */
#define CAST_USER(dst, src) \
	BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, BPF_ADDR_SPACE_CAST, 1 << 16)

/* r0 = the element of the hash map or NULL. There is one after the update. */
#define UPDATE_AND_LOOKUP				\
	"r1 = 0;"					\
	"*(u32 *)(r10 - 4) = r1;"			\
	"r1 = 7;"					\
	"*(u64 *)(r10 - 16) = r1;"			\
	"r1 = %[hash] ll;"				\
	"r2 = r10;"					\
	"r2 += -4;"					\
	"r3 = r10;"					\
	"r3 += -16;"					\
	"r4 = 0;"					\
	"call %[bpf_map_update_elem];"			\
	"r1 = %[hash] ll;"				\
	"r2 = r10;"					\
	"r2 += -4;"					\
	"call %[bpf_map_lookup_elem];"

SEC("syscall")
__description("arena cast: a pointer to map value, it's a move")
__success __retval(7)
__xlated("r6 = r0")
__xlated("r0 = *(u64 *)(r6 +0)")
__naked void map_value(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	UPDATE_AND_LOOKUP
	"if r0 == 0 goto 1f;"
	".8byte %[cast_r6_r0];"
	"r0 = *(u64 *)(r6 + 0);"
"1:"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm_addr(hash),
	  __imm(bpf_map_update_elem),
	  __imm(bpf_map_lookup_elem),
	  __imm_insn(cast_r6_r0, CAST_KERN(BPF_REG_6, BPF_REG_0))
	: __clobber_all);
}

SEC("syscall")
__description("arena cast: a pointer to map value into the same register, it's removed")
__success __retval(7)
__xlated("r7 = r0")
__xlated("r0 = *(u64 *)(r0 +0)")
__xlated("exit")
__naked void map_value_same_reg(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	UPDATE_AND_LOOKUP
	"if r0 == 0 goto 1f;"
	"r7 = r0;"
	".8byte %[cast_r0_r0];"
	"r0 = *(u64 *)(r0 + 0);"
"1:"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm_addr(hash),
	  __imm(bpf_map_update_elem),
	  __imm(bpf_map_lookup_elem),
	  __imm_insn(cast_r0_r0, CAST_KERN(BPF_REG_0, BPF_REG_0))
	: __clobber_all);
}

SEC("syscall")
__description("arena cast: bounds of map value are checked after the cast")
__failure __msg("invalid access to map value, value_size=8 off=8 size=8")
__naked void map_value_bounds(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	UPDATE_AND_LOOKUP
	"if r0 == 0 goto 1f;"
	".8byte %[cast_r6_r0];"
	"r0 = *(u64 *)(r6 + 8);"
"1:"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm_addr(hash),
	  __imm(bpf_map_update_elem),
	  __imm(bpf_map_lookup_elem),
	  __imm_insn(cast_r6_r0, CAST_KERN(BPF_REG_6, BPF_REG_0))
	: __clobber_all);
}

SEC("syscall")
__description("arena cast: a pointer that may be NULL has to be checked after the cast")
__failure __msg("R6 invalid mem access 'map_value_or_null'")
__naked void map_value_or_null(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	UPDATE_AND_LOOKUP
	".8byte %[cast_r6_r0];"
	"r0 = *(u64 *)(r6 + 0);"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm_addr(hash),
	  __imm(bpf_map_update_elem),
	  __imm(bpf_map_lookup_elem),
	  __imm_insn(cast_r6_r0, CAST_KERN(BPF_REG_6, BPF_REG_0))
	: __clobber_all);
}

SEC("syscall")
__description("arena cast: NULL check of the pointer is for its copy too")
__success __retval(7)
__naked void map_value_null_check_of_src(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	UPDATE_AND_LOOKUP
	".8byte %[cast_r6_r0];"
	"if r0 == 0 goto 1f;"
	"r0 = *(u64 *)(r6 + 0);"
"1:"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm_addr(hash),
	  __imm(bpf_map_update_elem),
	  __imm(bpf_map_lookup_elem),
	  __imm_insn(cast_r6_r0, CAST_KERN(BPF_REG_6, BPF_REG_0))
	: __clobber_all);
}

SEC("tc")
__description("arena cast: a pointer to ctx")
__success __log_level(2)
__msg("R6=ctx()")
__naked void ctx(void)
{
	asm volatile (
	"r2 = %[arena] ll;"
	".8byte %[cast_r6_r1];"
	"r0 = *(u32 *)(r6 + %[len]);"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm_const(len, offsetof(struct __sk_buff, len)),
	  __imm_insn(cast_r6_r1, CAST_KERN(BPF_REG_6, BPF_REG_1))
	: __clobber_all);
}

SEC("syscall")
__description("arena cast: a pointer to task_struct")
__success __log_level(2)
__msg("R6=trusted_ptr_task_struct()")
__naked void btf_id(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"call %[bpf_get_current_task_btf];"
	".8byte %[cast_r6_r0];"
	"r0 = *(u32 *)(r6 + 0);"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm(bpf_get_current_task_btf),
	  __imm_insn(cast_r6_r0, CAST_KERN(BPF_REG_6, BPF_REG_0))
	: __clobber_all);
}

SEC("syscall")
__description("arena cast: a reference is released through the copy")
__success __retval(0)
__naked void ref_released(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"call %[bpf_get_current_task_btf];"
	"r1 = r0;"
	"call %[bpf_task_acquire];"
	"if r0 == 0 goto 1f;"
	".8byte %[cast_r1_r0];"
	"call %[bpf_task_release];"
"1:"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm(bpf_get_current_task_btf),
	  __imm(bpf_task_acquire),
	  __imm(bpf_task_release),
	  __imm_insn(cast_r1_r0, CAST_KERN(BPF_REG_1, BPF_REG_0))
	: __clobber_all);
}

SEC("syscall")
__description("arena cast: a reference doesn't go away")
__failure __msg("Unreleased reference")
__naked void ref_leaked(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"call %[bpf_get_current_task_btf];"
	"r1 = r0;"
	"call %[bpf_task_acquire];"
	"if r0 == 0 goto 1f;"
	".8byte %[cast_r0_r0];"
"1:"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm(bpf_get_current_task_btf),
	  __imm(bpf_task_acquire),
	  __imm_insn(cast_r0_r0, CAST_KERN(BPF_REG_0, BPF_REG_0))
	: __clobber_all);
}

SEC("syscall")
__description("arena cast: a number")
__success __log_level(2)
__msg("R6=arena")
__xlated("w6 = w6")
__naked void number(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"r6 = %[addr] ll;"
	".8byte %[cast_r6_r6];"
	"r0 = *(u64 *)(r6 + 0);"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm_const(addr, ARENA_VM_START),
	  __imm_insn(cast_r6_r6, CAST_KERN(BPF_REG_6, BPF_REG_6))
	: __clobber_all);
}

/* static analysis of the stack doesn't follow the pointer through the cast */
SEC("syscall")
__description("arena cast: a pointer to stack")
__success __retval(7) __log_level(2)
__msg("R6=fp-8")
__naked void stack(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"r6 = r10;"
	"r6 += -8;"
	".8byte %[cast_r6_r6];"
	"r0 = 7;"
	"*(u64 *)(r6 + 0) = r0;"
	"r0 = *(u64 *)(r10 - 8);"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm_insn(cast_r6_r6, CAST_KERN(BPF_REG_6, BPF_REG_6))
	: __clobber_all);
}

SEC("syscall")
__description("arena cast: a pointer is spilled through the cast of a pointer to stack")
__success
__naked void spill_through_cast(void)
{
	asm volatile (
	"r2 = %[arena] ll;"
	"r6 = r10;"
	"r6 += -8;"
	".8byte %[cast_r6_r6];"
	"*(u64 *)(r6 + 0) = r1;"
	"r2 = *(u64 *)(r10 - 8);"
	/* it's ctx */
	"r0 = *(u32 *)(r2 + 0);"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm_insn(cast_r6_r6, CAST_KERN(BPF_REG_6, BPF_REG_6))
	: __clobber_all);
}

static __naked __noinline __used long writes_through_cast(long p)
{
	asm volatile (
	".8byte %[cast_r1_r1];"
	"r0 = 7;"
	"*(u64 *)(r1 + 0) = r0;"
	"r0 = 0;"
	"exit;"
	:
	: __imm_insn(cast_r1_r1, CAST_KERN(BPF_REG_1, BPF_REG_1))
	: __clobber_all);
}

SEC("syscall")
__description("arena cast: the callee writes to the stack of the caller")
__success __retval(7)
__naked void callee_writes(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"r0 = 0;"
	"*(u64 *)(r10 - 8) = r0;"
	"r1 = r10;"
	"r1 += -8;"
	"call writes_through_cast;"
	"r0 = *(u64 *)(r10 - 8);"
	"exit;"
	:
	: __imm_addr(arena)
	: __clobber_all);
}

static __naked __noinline __used long reads_through_cast(long p)
{
	asm volatile (
	"r6 = r1;"
	/* a place where what is not live is forgotten */
	"call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto +0;"
	".8byte %[cast_r6_r6];"
	"r0 = *(u64 *)(r6 + 0);"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm_insn(cast_r6_r6, CAST_KERN(BPF_REG_6, BPF_REG_6))
	: __clobber_all);
}

SEC("syscall")
__description("arena cast: the callee reads the stack of the caller")
__success __retval(5)
__naked void callee_reads(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"r0 = 5;"
	"*(u64 *)(r10 - 8) = r0;"
	"r1 = r10;"
	"r1 += -8;"
	"call reads_through_cast;"
	"exit;"
	:
	: __imm_addr(arena)
	: __clobber_all);
}

SEC("tc")
__description("arena cast: a number and a pointer at the same insn")
__failure __msg("same addr_space_cast insn cannot be used with a number and with a pointer")
__naked void number_and_pointer(void)
{
	asm volatile (
	"r2 = %[arena] ll;"
	"r6 = r1;"
	"call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 1f;"
	"r6 = 4096;"
"1:"
	".8byte %[cast_r6_r6];"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm(bpf_get_prandom_u32),
	  __imm_insn(cast_r6_r6, CAST_KERN(BPF_REG_6, BPF_REG_6))
	: __clobber_all);
}

SEC("tc")
__description("arena cast: a pointer and a number at the same insn")
__failure __msg("same addr_space_cast insn cannot be used with a number and with a pointer")
__naked void pointer_and_number(void)
{
	asm volatile (
	"r2 = %[arena] ll;"
	"r6 = 4096;"
	"r7 = r1;"
	"call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 1f;"
	"r6 = r7;"
"1:"
	".8byte %[cast_r6_r6];"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm(bpf_get_prandom_u32),
	  __imm_insn(cast_r6_r6, CAST_KERN(BPF_REG_6, BPF_REG_6))
	: __clobber_all);
}

SEC("tc")
__description("arena cast: the cast to as(1) of a pointer is a number")
__success __log_level(2)
__msg("R6=scalar()")
__naked void cast_user(void)
{
	asm volatile (
	"r2 = %[arena] ll;"
	".8byte %[cast_r6_r1];"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm_insn(cast_r6_r1, CAST_USER(BPF_REG_6, BPF_REG_1))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
