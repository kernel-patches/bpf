// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} map_array SEC(".maps");

SEC("socket")
__description("invalid map type for tail call")
__failure __msg("expected prog array map for tail call")
__failure_unpriv
__naked void invalid_map_for_tail_call(void)
{
	asm volatile ("			\
	r2 = %[map_array] ll;	\
	r3 = 0;				\
	call %[bpf_tail_call];		\
	exit;				\
"	:
	: __imm(bpf_tail_call),
	  __imm_addr(map_array)
	: __clobber_all);
}


SEC("xdp")
__description("XDP pkt read allowed after tail call")
__success __retval(0) __flag(BPF_F_ANY_ALIGNMENT)
__naked void xdp_legal_after_tail_call(void)
{
        asm volatile ("                                 \
        r2 = *(u32*)(r1 + %[xdp_md_data]);              \
        r3 = *(u32*)(r1 + %[xdp_md_data_end]);          \
        r9 = r2;                                        \
	r9 += 8;                                        \
        if r9 > r3 goto l0_%=;                          \
	r2 = %[map_array] ll;	                        \
	r3 = 0;				                \
	call %[bpf_tail_call];                          \
        r0 = *(u64*)(r9 - 8);                           \
l0_%=:  r0 = 0;                                         \
        exit;                                           \
"       :
        : __imm_const(xdp_md_data, offsetof(struct xdp_md, data)),
          __imm_const(xdp_md_data_end, offsetof(struct xdp_md, data_end)),
	  __imm(bpf_tail_call),
	  __imm_addr(map_array)
        : __clobber_all);
}

char _license[] SEC("license") = "GPL";
