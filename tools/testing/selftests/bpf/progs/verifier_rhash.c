// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, __u64);
} map_rhash SEC(".maps");

SEC("kprobe")
__description("rhash map is forbidden in BPF_PROG_TYPE_KPROBE")
__failure __msg("tracing progs cannot use resizable hash maps yet")
__naked void rhash_forbidden_in_kprobe(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u64*)(r10 - 8) = r1;"
	"r2 = r10;"
	"r2 += -8;"
	"r1 = %[map_rhash] ll;"
	"call %[bpf_map_lookup_elem];"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_rhash)
	: __clobber_all);
}

SEC("tracepoint")
__description("rhash map is forbidden in BPF_PROG_TYPE_TRACEPOINT")
__failure __msg("tracing progs cannot use resizable hash maps yet")
__naked void rhash_forbidden_in_tracepoint(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u64*)(r10 - 8) = r1;"
	"r2 = r10;"
	"r2 += -8;"
	"r1 = %[map_rhash] ll;"
	"call %[bpf_map_lookup_elem];"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_rhash)
	: __clobber_all);
}

SEC("perf_event")
__description("rhash map is forbidden in BPF_PROG_TYPE_PERF_EVENT")
__failure __msg("tracing progs cannot use resizable hash maps yet")
__naked void rhash_forbidden_in_perf_event(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u64*)(r10 - 8) = r1;"
	"r2 = r10;"
	"r2 += -8;"
	"r1 = %[map_rhash] ll;"
	"call %[bpf_map_lookup_elem];"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_rhash)
	: __clobber_all);
}

SEC("raw_tracepoint")
__description("rhash map is forbidden in BPF_PROG_TYPE_RAW_TRACEPOINT")
__failure __msg("tracing progs cannot use resizable hash maps yet")
__naked void rhash_forbidden_in_raw_tp(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u64*)(r10 - 8) = r1;"
	"r2 = r10;"
	"r2 += -8;"
	"r1 = %[map_rhash] ll;"
	"call %[bpf_map_lookup_elem];"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_rhash)
	: __clobber_all);
}

/* Positive test: socket filter programs CAN use rhash maps */
SEC("socket")
__description("rhash map is allowed in BPF_PROG_TYPE_SOCKET_FILTER")
__success
__naked void rhash_allowed_in_socket(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u64*)(r10 - 8) = r1;"
	"r2 = r10;"
	"r2 += -8;"
	"r1 = %[map_rhash] ll;"
	"call %[bpf_map_lookup_elem];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_rhash)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
