// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

struct sample {
	int pid;
	int seq;
	long value;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 4096);
} user_ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2);
} ringbuf SEC(".maps");

static int map_value;

static long
bad_access1(struct bpf_dynptr *dynptr, void *context)
{
	const struct sample *sample;

	sample = bpf_dynptr_data(dynptr - 1, 0, sizeof(*sample));
	bpf_printk("Was able to pass bad pointer %lx\n", (__u64)dynptr - 1);

	return 0;
}

/* A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
 * not be able to read before the pointer.
 */
SEC("?raw_tp")
__failure __msg("negative offset dynptr_ptr ptr")
int user_ringbuf_callback_bad_access1(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf, bad_access1, NULL, 0);

	return 0;
}

static long
bad_access2(struct bpf_dynptr *dynptr, void *context)
{
	const struct sample *sample;

	sample = bpf_dynptr_data(dynptr + 1, 0, sizeof(*sample));
	bpf_printk("Was able to pass bad pointer %lx\n", (__u64)dynptr + 1);

	return 0;
}

/* A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
 * not be able to read past the end of the pointer.
 */
SEC("?raw_tp")
__failure __msg("dereference of modified dynptr_ptr ptr")
int user_ringbuf_callback_bad_access2(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf, bad_access2, NULL, 0);

	return 0;
}

static long
write_forbidden(struct bpf_dynptr *dynptr, void *context)
{
	*((long *)dynptr) = 0;

	return 0;
}

/* A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
 * not be able to write to that pointer.
 */
SEC("?raw_tp")
__failure __msg("invalid mem access 'dynptr_ptr'")
int user_ringbuf_callback_write_forbidden(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf, write_forbidden, NULL, 0);

	return 0;
}

static long
null_context_write(struct bpf_dynptr *dynptr, void *context)
{
	*((__u64 *)context) = 0;

	return 0;
}

/* A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
 * not be able to write to that pointer.
 */
SEC("?raw_tp")
__failure __msg("invalid mem access 'scalar'")
int user_ringbuf_callback_null_context_write(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf, null_context_write, NULL, 0);

	return 0;
}

static long
null_context_read(struct bpf_dynptr *dynptr, void *context)
{
	__u64 id = *((__u64 *)context);

	bpf_printk("Read id %lu\n", id);

	return 0;
}

/* A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
 * not be able to write to that pointer.
 */
SEC("?raw_tp")
__failure __msg("invalid mem access 'scalar'")
int user_ringbuf_callback_null_context_read(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf, null_context_read, NULL, 0);

	return 0;
}

static long
try_discard_dynptr(struct bpf_dynptr *dynptr, void *context)
{
	bpf_ringbuf_discard_dynptr(dynptr, 0);

	return 0;
}

/* A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
 * not be able to read past the end of the pointer.
 */
SEC("?raw_tp")
__failure __msg("CONST_PTR_TO_DYNPTR cannot be released")
int user_ringbuf_callback_discard_dynptr(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf, try_discard_dynptr, NULL, 0);

	return 0;
}

static long
try_submit_dynptr(struct bpf_dynptr *dynptr, void *context)
{
	bpf_ringbuf_submit_dynptr(dynptr, 0);

	return 0;
}

/* A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
 * not be able to read past the end of the pointer.
 */
SEC("?raw_tp")
__failure __msg("CONST_PTR_TO_DYNPTR cannot be released")
int user_ringbuf_callback_submit_dynptr(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf, try_submit_dynptr, NULL, 0);

	return 0;
}

static long
invalid_drain_callback_return(struct bpf_dynptr *dynptr, void *context)
{
	return 2;
}

/* A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
 * not be able to write to that pointer.
 */
SEC("?raw_tp")
__failure __msg("At callback return the register R0 has ")
int user_ringbuf_callback_invalid_return(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf, invalid_drain_callback_return, NULL, 0);

	return 0;
}

static long
try_reinit_dynptr_mem(struct bpf_dynptr *dynptr, void *context)
{
	bpf_dynptr_from_mem(&map_value, 4, 0, dynptr);
	return 0;
}

static long
try_reinit_dynptr_ringbuf(struct bpf_dynptr *dynptr, void *context)
{
	bpf_ringbuf_reserve_dynptr(&ringbuf, 8, 0, dynptr);
	return 0;
}

SEC("?raw_tp")
__failure __msg("Dynptr has to be an uninitialized dynptr")
int user_ringbuf_callback_reinit_dynptr_mem(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf, try_reinit_dynptr_mem, NULL, 0);
	return 0;
}

SEC("?raw_tp")
__failure __msg("Dynptr has to be an uninitialized dynptr")
int user_ringbuf_callback_reinit_dynptr_ringbuf(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf, try_reinit_dynptr_ringbuf, NULL, 0);
	return 0;
}

__noinline long global_call_bpf_dynptr_data(struct bpf_dynptr *dynptr)
{
	bpf_dynptr_data(dynptr, 0xA, 0xA);
	return 0;
}

static long callback_adjust_bpf_dynptr_reg_off(struct bpf_dynptr *dynptr,
					       void *ctx)
{
	global_call_bpf_dynptr_data(dynptr += 1024);
	return 0;
}

SEC("?raw_tp")
__failure __msg("dereference of modified dynptr_ptr ptr R1 off=16384 disallowed")
int user_ringbuf_callback_const_ptr_to_dynptr_reg_off(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf,
			       callback_adjust_bpf_dynptr_reg_off, NULL, 0);
	return 0;
}

/* The sample goes back to the producer as soon as the callback returns. */
struct dynptr_ctx {
	struct bpf_dynptr *saved;
};

static long callback_park_dynptr(struct bpf_dynptr *dynptr, void *context)
{
	struct dynptr_ctx *c = context;

	c->saved = dynptr;
	return 0;
}

SEC("?raw_tp")
__failure __msg("the callback that owned this value returned")
int user_ringbuf_callback_park_dynptr(void *ctx)
{
	struct dynptr_ctx c = {};
	char buf[8] = {};

	bpf_user_ringbuf_drain(&user_ringbuf, callback_park_dynptr, &c, 0);
	if (c.saved)
		bpf_dynptr_read(buf, sizeof(buf), c.saved, 0, 0);
	return buf[0];
}

struct slice_ctx {
	char *p;
};

static long callback_park_data_slice(struct bpf_dynptr *dynptr, void *context)
{
	struct slice_ctx *c = context;

	c->p = bpf_dynptr_data(dynptr, 0, 8);
	return 0;
}

SEC("?raw_tp")
__failure __msg("the callback that owned this value returned")
int user_ringbuf_callback_park_data_slice(void *ctx)
{
	struct slice_ctx c = {};

	bpf_user_ringbuf_drain(&user_ringbuf, callback_park_data_slice, &c, 0);
	if (c.p)
		return c.p[0];
	return 0;
}

static long callback_park_kfunc_slice(struct bpf_dynptr *dynptr, void *context)
{
	struct slice_ctx *c = context;

	c->p = bpf_dynptr_slice(dynptr, 0, NULL, 8);
	return 0;
}

SEC("?raw_tp")
__failure __msg("the callback that owned this value returned")
int user_ringbuf_callback_park_kfunc_slice(void *ctx)
{
	struct slice_ctx c = {};

	bpf_user_ringbuf_drain(&user_ringbuf, callback_park_kfunc_slice, &c, 0);
	if (c.p)
		return c.p[0];
	return 0;
}

struct clone_ctx {
	struct bpf_dynptr clone;
	__u64 armed;
};

static long callback_park_clone(struct bpf_dynptr *dynptr, void *context)
{
	struct clone_ctx *c = context;

	bpf_dynptr_clone(dynptr, &c->clone);
	c->armed = 1;
	return 0;
}

SEC("?raw_tp")
__failure __msg("Expected an initialized dynptr as R3")
int user_ringbuf_callback_park_clone(void *ctx)
{
	struct clone_ctx c = {};
	char buf[8] = {};

	bpf_user_ringbuf_drain(&user_ringbuf, callback_park_clone, &c, 0);
	if (c.armed)
		bpf_dynptr_read(buf, sizeof(buf), &c.clone, 0, 0);
	return buf[0];
}

SEC("?raw_tp")
__failure __msg("Expected an initialized dynptr as R1")
int user_ringbuf_callback_park_clone_then_slice(void *ctx)
{
	struct clone_ctx c = {};
	char *p;

	bpf_user_ringbuf_drain(&user_ringbuf, callback_park_clone, &c, 0);
	if (c.armed) {
		p = bpf_dynptr_data(&c.clone, 0, 8);
		if (p)
			return p[0];
	}
	return 0;
}

static long callback_park_inner(struct bpf_dynptr *dynptr, void *context)
{
	struct dynptr_ctx *c = context;

	c->saved = dynptr;
	return 0;
}

/* An inner drain's dynptr must not escape into the outer callback either. */
static long callback_park_outer(struct bpf_dynptr *dynptr, void *context)
{
	struct dynptr_ctx inner = {};
	char buf[8] = {};

	bpf_user_ringbuf_drain(&user_ringbuf, callback_park_inner, &inner, 0);
	if (inner.saved)
		bpf_dynptr_read(buf, sizeof(buf), inner.saved, 0, 0);
	return buf[0] ? 1 : 0;
}

SEC("?raw_tp")
__failure __msg("the callback that owned this value returned")
int user_ringbuf_callback_nested_park_inner(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf, callback_park_outer, NULL, 0);
	return 0;
}
