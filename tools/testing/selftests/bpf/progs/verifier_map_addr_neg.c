// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define MAX_ENTRIES 11

struct test_val {
	unsigned int index;
	int foo[MAX_ENTRIES];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, long long);
	__type(value, struct test_val);
} map_hash_48b SEC(".maps");

SEC("socket")
__description("perform illegal arithmetic operation on map type register")
__failure __msg("R0 negation operator =- on pointer")
__failure_unpriv
__naked void test_map_addr_neg(void)
{
	asm volatile("			\
	r0 = %[map_hash_48b] ll;	\
	r0 = -r0;			\
	exit;				\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_hash_48b)
	: __clobber_all);
}

char LICENSE[] SEC("license") = "GPL";
