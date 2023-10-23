// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "../bpf_testmod/bpf_testmod_kfunc.h"
#include "bpf_misc.h"

struct val {
	int d;
	struct prog_test_ref_kfunc __kptr *ref_ptr;
};

struct val2 {
	char c;
	struct val v;
};

struct val_holder {
	int e;
	struct val2 first[2];
	int f;
	struct val second[2];
};

struct array_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct val);
	__uint(max_entries, 10);
} array_map SEC(".maps");

struct array_map2 {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct val2);
	__uint(max_entries, 10);
} array_map2 SEC(".maps");

__hidden struct val array[25];
__hidden struct val double_array[5][5];
__hidden struct val_holder double_holder_array[2][2];

/* Some tests need their own section to force separate bss arraymap,
 * otherwise above arrays wouldn't have btf_field_info either
 */
#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))
private(A) struct val array_too_big[300];

private(B) struct val exactly_max_fields[256];
private(B) int ints[50];

SEC("tc")
__success __retval(0)
int test_arraymap(void *ctx)
{
	struct prog_test_ref_kfunc *p;
	unsigned long dummy = 0;
	struct val *v;
	int idx = 0;

	v = bpf_map_lookup_elem(&array_map, &idx);
	if (!v)
		return 1;

	p = bpf_kfunc_call_test_acquire(&dummy);
	if (!p)
		return 2;

	p = bpf_kptr_xchg(&v->ref_ptr, p);
	if (p) {
		bpf_kfunc_call_test_release(p);
		return 3;
	}

	return 0;
}

SEC("tc")
__success __retval(0)
int test_arraymap2(void *ctx)
{
	struct prog_test_ref_kfunc *p;
	unsigned long dummy = 0;
	struct val2 *v;
	int idx = 0;

	v = bpf_map_lookup_elem(&array_map2, &idx);
	if (!v)
		return 1;

	p = bpf_kfunc_call_test_acquire(&dummy);
	if (!p)
		return 2;

	p = bpf_kptr_xchg(&v->v.ref_ptr, p);
	if (p) {
		bpf_kfunc_call_test_release(p);
		return 3;
	}

	return 0;
}

/* elem must be contained within some mapval so it can be used as
 * bpf_kptr_xchg's first param
 */
static __always_inline int test_array_xchg(struct val *elem)
{
	struct prog_test_ref_kfunc *p;
	unsigned long dummy = 0;

	p = bpf_kfunc_call_test_acquire(&dummy);
	if (!p)
		return 1;

	p = bpf_kptr_xchg(&elem->ref_ptr, p);
	if (p) {
		bpf_kfunc_call_test_release(p);
		return 2;
	}

	return 0;
}

SEC("tc")
__success __retval(0)
int test_array(void *ctx)
{
	return test_array_xchg(&array[10]);
}

SEC("tc")
__success __retval(0)
int test_double_array(void *ctx)
{
	/* array -> array -> struct -> kptr */
	return test_array_xchg(&double_array[4][3]);
}

SEC("tc")
__success __retval(0)
int test_double_holder_array_first(void *ctx)
{
	/* array -> array -> struct -> array -> struct -> struct -> kptr */
	return test_array_xchg(&double_holder_array[1][1].first[1].v);
}

SEC("tc")
__success __retval(0)
int test_double_holder_array_second(void *ctx)
{
	/* array -> array -> struct -> array -> struct -> kptr */
	return test_array_xchg(&double_holder_array[1][1].second[1]);
}

SEC("tc")
__success __retval(0)
int test_exactly_max_fields(void *ctx)
{
	/* Edge case where verifier finds BTF_FIELDS_MAX fields. It should be
	 * safe to examine .bss.B's other array, and .bss.B will have a valid
	 * btf_record if no more fields are found
	 */
	return test_array_xchg(&exactly_max_fields[255]);
}

SEC("tc")
__failure __msg("map '.bss.A' has no valid kptr")
int test_array_fail__too_big(void *ctx)
{
	/* array_too_big's btf_record parsing will fail due to the
	 * number of btf_field_infos being > BTF_FIELDS_MAX
	 */
	return test_array_xchg(&array_too_big[50]);
}

char _license[] SEC("license") = "GPL";
