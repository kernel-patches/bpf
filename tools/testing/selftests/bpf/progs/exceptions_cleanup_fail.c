// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "bpf_misc.h"
#include "bpf_experimental.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8);
} ringbuf SEC(".maps");

SEC("?tc")
__failure __msg("Unreleased reference")
int reject_with_reference(void *ctx)
{
	struct { int i; } *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__failure __msg("frame_desc: merge: failed to merge old and new frame desc entry")
int reject_slot_with_distinct_ptr(struct __sk_buff *ctx)
{
    void *p;

    if (ctx->len) {
        p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    } else {
        p = bpf_obj_new(typeof(struct { int i; }));
    }
    bpf_throw(0);
    return !p;
}

SEC("?tc")
__failure __msg("frame_desc: merge: failed to merge old and new frame desc entry")
int reject_slot_with_distinct_ptr_old(struct __sk_buff *ctx)
{
    void *p;

    if (ctx->len) {
        p = bpf_obj_new(typeof(struct { int i; }));
    } else {
        p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    }
    bpf_throw(0);
    return !p;
}

SEC("?tc")
__failure __msg("frame_desc: merge: failed to merge old and new frame desc entry")
int reject_slot_with_misc_vs_ptr(struct __sk_buff *ctx)
{
    void *p = (void *)bpf_ktime_get_ns();

    if (ctx->protocol)
        p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    bpf_throw(0);
    return !p;
}

SEC("?tc")
__failure __msg("Unreleased reference")
int reject_slot_with_misc_vs_ptr_old(struct __sk_buff *ctx)
{
    void *p = bpf_ringbuf_reserve(&ringbuf, 8, 0);

    if (ctx->protocol)
        p = (void *)bpf_ktime_get_ns();
    bpf_throw(0);
    return !p;
}

SEC("?tc")
__failure __msg("frame_desc: merge: failed to merge old and new frame desc entry")
int reject_slot_with_invalid_vs_ptr(struct __sk_buff *ctx)
{
    asm volatile (
       "r7 = r1;                        \
        r1 = %[ringbuf] ll;             \
        r2 = 8;                         \
        r3 = 0;                         \
        r4 = *(u32 *)(r7 + 0);          \
        r6 = *(u64 *)(r10 - 8);         \
        if r4 == 0 goto jump;           \
        call %[bpf_ringbuf_reserve];    \
        r6 = r0;                        \
    jump:                               \
        r0 = 0;                         \
        r1 = 0;                         \
        call bpf_throw;                 \
    " : : __imm(bpf_ringbuf_reserve),
          __imm_addr(ringbuf)
      : "memory");
    return 0;
}

SEC("?tc")
__failure __msg("Unreleased reference")
int reject_slot_with_invalid_vs_ptr_old(struct __sk_buff *ctx)
{
    asm volatile (
       "r7 = r1;                        \
        r1 = %[ringbuf] ll;             \
        r2 = 8;                         \
        r3 = 0;                         \
        call %[bpf_ringbuf_reserve];    \
        r6 = r0;                        \
        r4 = *(u32 *)(r7 + 0);          \
        if r4 == 0 goto jump2;          \
        r6 = *(u64 *)(r10 - 8);         \
    jump2:                              \
        r0 = 0;                         \
        r1 = 0;                         \
        call bpf_throw;                 \
    " : : __imm(bpf_ringbuf_reserve),
          __imm_addr(ringbuf)
      : "memory");
    return 0;
}

SEC("?tc")
__failure __msg("Unreleased reference")
int reject_slot_with_zero_vs_ptr(struct __sk_buff *ctx)
{
    asm volatile (
       "r7 = *(u32 *)(r1 + 0);          \
        r1 = %[ringbuf] ll;             \
        r2 = 8;                         \
        r3 = 0;                         \
        call %[bpf_ringbuf_reserve];    \
        *(u64 *)(r10 - 8) = r0;         \
        r0 = 0;                         \
        if r7 != 0 goto jump3;          \
        *(u64 *)(r10 - 8) = r0;         \
    jump3:                              \
        r0 = 0;                         \
        r1 = 0;                         \
        call bpf_throw;                 \
    " : : __imm(bpf_ringbuf_reserve),
          __imm_addr(ringbuf)
      : "memory");
    return 0;
}

char _license[] SEC("license") = "GPL";
