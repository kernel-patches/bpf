// SPDX-License-Identifier: GPL-2.0

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

extern int bpf_strcmp(const char *s1__ign, const char *s2__ign) __ksym;
extern bool bpf_dynptr_is_null(const struct bpf_dynptr *p) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} kfunc_return_map SEC(".maps");

static const char string_a[] = "a";
static const char string_b[] = "b";

void __kfunc_btf_root(void)
{
	struct bpf_dynptr ptr = {};

	bpf_strcmp(string_a, string_b);
	bpf_dynptr_is_null(&ptr);
}

SEC("syscall")
__flag(BPF_F_SLEEPABLE)
__success __retval(0)
__arch_x86_32
__naked void kfunc_bool_return_zero_extended(void)
{
	asm volatile ("					\
	r0 = 0;						\
	*(u32 *)(r10 - 4) = r0;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = %[kfunc_return_map] ll;			\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto 1f;				\
	r1 = r0;					\
	r2 = 8;						\
	r3 = 0;						\
	r4 = r10;					\
	r4 += -24;					\
	call %[bpf_dynptr_from_mem];			\
	if r0 != 0 goto 1f;				\
	r0 = 0x100000000 ll;				\
	r1 = r10;					\
	r1 += -24;					\
	call bpf_dynptr_is_null;				\
	r0 >>= 32;					\
	exit;						\
1:	r0 = 2;						\
	exit;						\
"	:
	: __imm_addr(kfunc_return_map),
	  __imm(bpf_map_lookup_elem),
	  __imm(bpf_dynptr_from_mem)
	: __clobber_all);
}

SEC("syscall")
__flag(BPF_F_SLEEPABLE)
__success __retval(-1)
__arch_x86_32
__naked void kfunc_int_return_sign_extended(void)
{
	asm volatile ("					\
	r0 = 0;						\
	r1 = %[string_a] ll;				\
	r2 = %[string_b] ll;				\
	call bpf_strcmp;				\
	r0 >>= 32;					\
	exit;						\
"	:
	: __imm_addr(string_a),
	  __imm_addr(string_b)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
