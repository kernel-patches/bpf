// SPDX-License-Identifier: GPL-2.0
/* Converted from tools/testing/selftests/bpf/verifier/helper_restricted.c */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct val {
	int cnt;
	struct bpf_spin_lock l;
};

struct bpf_res_spin_lock {
	__u32 val;
};

struct res_val {
	int cnt;
	struct bpf_res_spin_lock l;
};

extern int bpf_res_spin_lock(struct bpf_res_spin_lock *lock) __ksym;
extern void bpf_res_spin_unlock(struct bpf_res_spin_lock *lock) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct val);
} map_spin_lock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct res_val);
} map_res_spin_lock SEC(".maps");

static __always_inline int use_res_spin_lock(void)
{
	struct res_val *val;
	int key = 0;

	val = bpf_map_lookup_elem(&map_res_spin_lock, &key);
	if (!val)
		return 0;
	if (bpf_res_spin_lock(&val->l))
		return 0;
	val->cnt++;
	bpf_res_spin_unlock(&val->l);
	return 0;
}

SEC("kprobe")
__description("bpf_ktime_get_coarse_ns is forbidden in BPF_PROG_TYPE_KPROBE")
__failure __msg("program of this type cannot use helper bpf_ktime_get_coarse_ns")
__naked void in_bpf_prog_type_kprobe_1(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_coarse_ns];		\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_ktime_get_coarse_ns)
	: __clobber_all);
}

SEC("tracepoint")
__description("bpf_ktime_get_coarse_ns is forbidden in BPF_PROG_TYPE_TRACEPOINT")
__failure __msg("program of this type cannot use helper bpf_ktime_get_coarse_ns")
__naked void in_bpf_prog_type_tracepoint_1(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_coarse_ns];		\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_ktime_get_coarse_ns)
	: __clobber_all);
}

SEC("perf_event")
__description("bpf_ktime_get_coarse_ns is forbidden in BPF_PROG_TYPE_PERF_EVENT")
__failure __msg("program of this type cannot use helper bpf_ktime_get_coarse_ns")
__naked void bpf_prog_type_perf_event_1(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_coarse_ns];		\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_ktime_get_coarse_ns)
	: __clobber_all);
}

SEC("raw_tracepoint")
__description("bpf_ktime_get_coarse_ns is forbidden in BPF_PROG_TYPE_RAW_TRACEPOINT")
__failure __msg("program of this type cannot use helper bpf_ktime_get_coarse_ns")
__naked void bpf_prog_type_raw_tracepoint_1(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_coarse_ns];		\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_ktime_get_coarse_ns)
	: __clobber_all);
}

SEC("kprobe")
__description("bpf_spin_lock is forbidden in BPF_PROG_TYPE_KPROBE")
__failure __msg("tracing progs cannot use bpf_spin_lock yet")
__naked void in_bpf_prog_type_kprobe_3(void)
{
	asm volatile ("					\
	r2 = r10;					\
	r2 += -8;					\
	r1 = 0;						\
	*(u64*)(r2 + 0) = r1;				\
	r1 = %[map_spin_lock] ll;			\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l0_%=;				\
	r1 = r0;					\
	call %[bpf_spin_lock];				\
l0_%=:	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm(bpf_spin_lock),
	  __imm_addr(map_spin_lock)
	: __clobber_all);
}

SEC("tracepoint")
__description("bpf_spin_lock is forbidden in BPF_PROG_TYPE_TRACEPOINT")
__failure __msg("tracing progs cannot use bpf_spin_lock yet")
__naked void in_bpf_prog_type_tracepoint_3(void)
{
	asm volatile ("					\
	r2 = r10;					\
	r2 += -8;					\
	r1 = 0;						\
	*(u64*)(r2 + 0) = r1;				\
	r1 = %[map_spin_lock] ll;			\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l0_%=;				\
	r1 = r0;					\
	call %[bpf_spin_lock];				\
l0_%=:	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm(bpf_spin_lock),
	  __imm_addr(map_spin_lock)
	: __clobber_all);
}

SEC("perf_event")
__description("bpf_spin_lock is forbidden in BPF_PROG_TYPE_PERF_EVENT")
__failure __msg("tracing progs cannot use bpf_spin_lock yet")
__naked void bpf_prog_type_perf_event_3(void)
{
	asm volatile ("					\
	r2 = r10;					\
	r2 += -8;					\
	r1 = 0;						\
	*(u64*)(r2 + 0) = r1;				\
	r1 = %[map_spin_lock] ll;			\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l0_%=;				\
	r1 = r0;					\
	call %[bpf_spin_lock];				\
l0_%=:	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm(bpf_spin_lock),
	  __imm_addr(map_spin_lock)
	: __clobber_all);
}

SEC("raw_tracepoint")
__description("bpf_spin_lock is forbidden in BPF_PROG_TYPE_RAW_TRACEPOINT")
__failure __msg("tracing progs cannot use bpf_spin_lock yet")
__naked void bpf_prog_type_raw_tracepoint_3(void)
{
	asm volatile ("					\
	r2 = r10;					\
	r2 += -8;					\
	r1 = 0;						\
	*(u64*)(r2 + 0) = r1;				\
	r1 = %[map_spin_lock] ll;			\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l0_%=;				\
	r1 = r0;					\
	call %[bpf_spin_lock];				\
l0_%=:	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm(bpf_spin_lock),
	  __imm_addr(map_spin_lock)
	: __clobber_all);
}

SEC("kprobe")
__description("bpf_res_spin_lock is allowed in BPF_PROG_TYPE_KPROBE")
__success
int res_spin_lock_bpf_prog_type_kprobe(void *ctx)
{
	return use_res_spin_lock();
}

SEC("tracepoint")
__description("bpf_res_spin_lock is allowed in BPF_PROG_TYPE_TRACEPOINT")
__success
int res_spin_lock_bpf_prog_type_tracepoint(void *ctx)
{
	return use_res_spin_lock();
}

SEC("perf_event")
__description("bpf_res_spin_lock is allowed in BPF_PROG_TYPE_PERF_EVENT")
__success
int res_spin_lock_bpf_prog_type_perf_event(void *ctx)
{
	return use_res_spin_lock();
}

SEC("raw_tracepoint")
__description("bpf_res_spin_lock is allowed in BPF_PROG_TYPE_RAW_TRACEPOINT")
__success
int res_spin_lock_bpf_prog_type_raw_tracepoint(void *ctx)
{
	return use_res_spin_lock();
}

char _license[] SEC("license") = "GPL";
