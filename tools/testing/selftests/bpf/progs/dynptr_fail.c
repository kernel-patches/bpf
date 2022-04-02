// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bpf_dynptr);
} array_map SEC(".maps");

struct sample {
	int pid;
	long value;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} ringbuf SEC(".maps");

int err = 0;
int val;

/* A dynptr can't be used after bpf_free has been called on it */
SEC("raw_tp/sys_nanosleep")
int use_after_free(void *ctx)
{
	struct bpf_dynptr ptr = {};
	char read_data[64] = {};

	bpf_malloc(8, &ptr);

	bpf_dynptr_read(read_data, sizeof(read_data), &ptr, 0);

	bpf_free(&ptr);

	/* this should fail */
	bpf_dynptr_read(read_data, sizeof(read_data), &ptr, 0);

	return 0;
}

/* Every bpf_malloc call must have a corresponding bpf_free call */
SEC("raw_tp/sys_nanosleep")
int missing_free(void *ctx)
{
	struct bpf_dynptr mem;

	bpf_malloc(8, &mem);

	/* missing a call to bpf_free(&mem) */

	return 0;
}

/* A non-malloc-ed dynptr can't be freed */
SEC("raw_tp/sys_nanosleep")
int invalid_free1(void *ctx)
{
	struct bpf_dynptr ptr;
	__u32 x = 0;

	bpf_dynptr_from_mem(&x, sizeof(x), &ptr);

	/* this should fail */
	bpf_free(&ptr);

	return 0;
}

/* A data slice from a dynptr can't be freed */
SEC("raw_tp/sys_nanosleep")
int invalid_free2(void *ctx)
{
	struct bpf_dynptr ptr;
	void *data;

	bpf_malloc(8, &ptr);

	data = bpf_dynptr_data(&ptr, 0, 8);

	/* this should fail */
	bpf_free(data);

	return 0;
}

/*
 * Can't bpf_malloc an existing malloc-ed bpf_dynptr that hasn't been
 * freed yet
 */
SEC("raw_tp/sys_nanosleep")
int malloc_twice(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_malloc(8, &ptr);

	/* this should fail */
	bpf_malloc(2, &ptr);

	bpf_free(&ptr);

	return 0;
}

/*
 * Can't access a ring buffer record after submit or discard has been called
 * on the dynptr
 */
SEC("raw_tp/sys_nanosleep")
int ringbuf_invalid_access(void *ctx)
{
	struct bpf_dynptr ptr;
	struct sample *sample;

	err = bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(*sample), 0, &ptr);
	sample = bpf_dynptr_data(&ptr, 0, sizeof(*sample));
	if (!sample)
		goto done;

	sample->pid = 123;

	bpf_ringbuf_submit_dynptr(&ptr, 0);

	/* this should fail */
	err = sample->pid;

	return 0;

done:
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}

/* Can't call non-dynptr ringbuf APIs on a dynptr ringbuf sample */
SEC("raw_tp/sys_nanosleep")
int ringbuf_invalid_api(void *ctx)
{
	struct bpf_dynptr ptr;
	struct sample *sample;

	err = bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(*sample), 0, &ptr);
	sample = bpf_dynptr_data(&ptr, 0, sizeof(*sample));
	if (!sample)
		goto done;

	sample->pid = 123;

	/* invalid API use. need to use dynptr API to submit/discard */
	bpf_ringbuf_submit(sample, 0);

	return 0;

done:
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}

/* Can't access memory outside a ringbuf record range */
SEC("raw_tp/sys_nanosleep")
int ringbuf_out_of_bounds(void *ctx)
{
	struct bpf_dynptr ptr;
	struct sample *sample;

	err = bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(*sample), 0, &ptr);
	sample = bpf_dynptr_data(&ptr, 0, sizeof(*sample));
	if (!sample)
		goto done;

	/* Can't access beyond sample range */
	*(__u8 *)((void *)sample + sizeof(*sample)) = 123;

	bpf_ringbuf_submit_dynptr(&ptr, 0);

	return 0;

done:
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}

/* Can't add a dynptr to a map */
SEC("raw_tp/sys_nanosleep")
int invalid_map_call1(void *ctx)
{
	struct bpf_dynptr ptr = {};
	char buf[64] = {};
	int key = 0;

	err = bpf_dynptr_from_mem(buf, sizeof(buf), &ptr);

	/* this should fail */
	bpf_map_update_elem(&array_map, &key, &ptr, 0);

	return 0;
}

/* Can't add a struct with an embedded dynptr to a map */
SEC("raw_tp/sys_nanosleep")
int invalid_map_call2(void *ctx)
{
	struct info {
		int x;
		struct bpf_dynptr ptr;
	};
	struct info x;
	int key = 0;

	bpf_malloc(8, &x.ptr);

	/* this should fail */
	bpf_map_update_elem(&array_map, &key, &x, 0);

	return 0;
}

/* Can't pass in a dynptr as an arg to a helper function that doesn't take in a
 * dynptr argument
 */
SEC("raw_tp/sys_nanosleep")
int invalid_helper1(void *ctx)
{
	struct bpf_dynptr ptr = {};

	bpf_malloc(8, &ptr);

	/* this should fail */
	bpf_strncmp((const char *)&ptr, sizeof(ptr), "hello!");

	bpf_free(&ptr);

	return 0;
}

/* A dynptr can't be passed into a helper function at a non-zero offset */
SEC("raw_tp/sys_nanosleep")
int invalid_helper2(void *ctx)
{
	struct bpf_dynptr ptr = {};
	char read_data[64] = {};
	__u64 x = 0;

	bpf_dynptr_from_mem(&x, sizeof(x), &ptr);

	/* this should fail */
	bpf_dynptr_read(read_data, sizeof(read_data), (void *)&ptr + 8, 0);

	return 0;
}

/* A data slice can't be accessed out of bounds */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int data_slice_out_of_bounds(void *ctx)
{
	struct bpf_dynptr ptr = {};
	void *data;

	bpf_malloc(8, &ptr);

	data = bpf_dynptr_data(&ptr, 0, 8);
	if (!data)
		goto done;

	/* can't index out of bounds of the data slice */
	val = *((char *)data + 8);

done:
	bpf_free(&ptr);
	return 0;
}

/* A data slice can't be used after it's freed */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int data_slice_use_after_free(void *ctx)
{
	struct bpf_dynptr ptr = {};
	void *data;

	bpf_malloc(8, &ptr);

	data = bpf_dynptr_data(&ptr, 0, 8);
	if (!data)
		goto done;

	bpf_free(&ptr);

	/* this should fail */
	val = *(__u8 *)data;

done:
	bpf_free(&ptr);
	return 0;
}

/*
 * A bpf_dynptr can't be written directly to by the bpf program,
 * only through dynptr helper functions
 */
SEC("raw_tp/sys_nanosleep")
int invalid_write1(void *ctx)
{
	struct bpf_dynptr ptr = {};
	__u8 x = 0;

	bpf_malloc(8, &ptr);

	/* this should fail */
	memcpy(&ptr, &x, sizeof(x));

	bpf_free(&ptr);

	return 0;
}

/*
 * A bpf_dynptr at a non-zero offset can't be written directly to by the bpf program,
 * only through dynptr helper functions
 */
SEC("raw_tp/sys_nanosleep")
int invalid_write2(void *ctx)
{
	struct bpf_dynptr ptr = {};
	char read_data[64] = {};
	__u8 x = 0, y = 0;

	bpf_dynptr_from_mem(&x, sizeof(x), &ptr);

	/* this should fail */
	memcpy((void *)&ptr, &y, sizeof(y));

	bpf_dynptr_read(read_data, sizeof(read_data), &ptr, 0);

	return 0;
}

/* A non-const write into a dynptr is not permitted */
SEC("raw_tp/sys_nanosleep")
int invalid_write3(void *ctx)
{
	struct bpf_dynptr ptr = {};
	char stack_buf[16];
	unsigned long len;
	__u8 x = 0;

	bpf_malloc(8, &ptr);

	memcpy(stack_buf, &val, sizeof(val));
	len = stack_buf[0] & 0xf;

	/* this should fail */
	memcpy((void *)&ptr + len, &x, sizeof(x));

	bpf_free(&ptr);

	return 0;
}

static int invalid_write4_callback(__u32 index, void *data)
{
	/* this should fail */
	*(__u32 *)data = 123;

	bpf_free(data);

	return 0;
}

/* An invalid write can't occur in a callback function */
SEC("raw_tp/sys_nanosleep")
int invalid_write4(void *ctx)
{
	struct bpf_dynptr ptr;
	__u64 x = 0;

	bpf_dynptr_from_mem(&x, sizeof(x), &ptr);

	bpf_loop(10, invalid_write4_callback, &ptr, 0);

	return 0;
}

/* A globally-defined bpf_dynptr can't be used (it must reside as a stack frame) */
struct bpf_dynptr global_dynptr;
SEC("raw_tp/sys_nanosleep")
int global(void *ctx)
{
	/* this should fail */
	bpf_malloc(4, &global_dynptr);

	bpf_free(&global_dynptr);

	return 0;
}

/* A direct read should fail */
SEC("raw_tp/sys_nanosleep")
int invalid_read1(void *ctx)
{
	struct bpf_dynptr ptr = {};
	__u32 x = 2;

	bpf_dynptr_from_mem(&x, sizeof(x), &ptr);

	/* this should fail */
	val = *(int *)&ptr;

	return 0;
}

/* A direct read at an offset should fail */
SEC("raw_tp/sys_nanosleep")
int invalid_read2(void *ctx)
{
	struct bpf_dynptr ptr = {};
	char read_data[64] = {};
	__u64 x = 0;

	bpf_dynptr_from_mem(&x, sizeof(x), &ptr);

	/* this should fail */
	bpf_dynptr_read(read_data, sizeof(read_data), (void *)&ptr + 1, 0);

	return 0;
}

/* A direct read at an offset into the lower stack slot should fail */
SEC("raw_tp/sys_nanosleep")
int invalid_read3(void *ctx)
{
	struct bpf_dynptr ptr = {};
	struct bpf_dynptr ptr2 = {};
	__u32 x = 2;

	bpf_dynptr_from_mem(&x, sizeof(x), &ptr);
	bpf_dynptr_from_mem(&x, sizeof(x), &ptr2);

	/* this should fail */
	memcpy(&val, (void *)&ptr + 8, sizeof(val));

	return 0;
}

/* Calling bpf_dynptr_from_mem on an offset should fail */
SEC("raw_tp/sys_nanosleep")
int invalid_offset(void *ctx)
{
	struct bpf_dynptr ptr = {};
	__u64 x = 0;

	/* this should fail */
	bpf_dynptr_from_mem(&x, sizeof(x), &ptr + 1);

	return 0;
}

/* A malloc can't be freed twice */
SEC("raw_tp/sys_nanosleep")
int free_twice(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_malloc(8, &ptr);

	bpf_free(&ptr);

	/* this second free should fail */
	bpf_free(&ptr);

	return 0;
}

static int free_twice_callback_fn(__u32 index, void *data)
{
	/* this should fail */
	bpf_free(data);
	val = index;
	return 0;
}

/* Test that freeing a malloc twice, where the 2nd free happens within a
 * calback function, fails
 */
SEC("raw_tp/sys_nanosleep")
int free_twice_callback(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_malloc(8, &ptr);

	bpf_free(&ptr);

	bpf_loop(10, free_twice_callback_fn, &ptr, 0);

	return 0;
}

static int missing_free_callback_fn(__u32 index, void *data)
{
	struct bpf_dynptr ptr;

	bpf_malloc(8, &ptr);

	val = index;

	/* missing bpf_free(&ptr) */

	return 0;
}

/* Any dynptr initialized within a callback must be freed */
SEC("raw_tp/sys_nanosleep")
int missing_free_callback(void *ctx)
{
	bpf_loop(10, missing_free_callback_fn, NULL, 0);
	return 0;
}

