// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct test_info {
	int x;
	struct bpf_dynptr ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bpf_dynptr);
} array_map1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct test_info);
} array_map2 SEC(".maps");

struct sample {
	int pid;
	long value;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} ringbuf SEC(".maps");

int err = 0;
int val;

/* Every bpf_dynptr_alloc call must have a corresponding bpf_dynptr_put call */
SEC("?raw_tp/sys_nanosleep")
int missing_put(void *ctx)
{
	struct bpf_dynptr mem;

	bpf_dynptr_alloc(8, 0, &mem);

	/* missing a call to bpf_dynptr_put(&mem) */

	return 0;
}

static int missing_put_callback_fn(__u32 index, void *data)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_alloc(8, 0, &ptr);

	val = index;

	/* missing bpf_dynptr_put(&ptr) */

	return 0;
}

/* Any dynptr initialized within a callback must have bpf_dynptr_put called */
SEC("?raw_tp/sys_nanosleep")
int missing_put_callback(void *ctx)
{
	bpf_loop(10, missing_put_callback_fn, NULL, 0);
	return 0;
}

/* A non-alloc-ed dynptr can't be used by bpf_dynptr_put */
SEC("?raw_tp/sys_nanosleep")
int put_nonalloc(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_ringbuf_reserve_dynptr(&ringbuf, val, 0, &ptr);

	/* this should fail */
	bpf_dynptr_put(&ptr);

	return 0;
}

/* A data slice from a dynptr can't be used by bpf_dynptr_put */
SEC("?raw_tp/sys_nanosleep")
int put_data_slice(void *ctx)
{
	struct bpf_dynptr ptr;
	void *data;

	bpf_dynptr_alloc(8, 0, &ptr);

	data = bpf_dynptr_data(&ptr, 0, 8);
	if (!data)
		goto done;

	/* this should fail */
	bpf_dynptr_put(data);

done:
	bpf_dynptr_put(&ptr);
	return 0;
}

/* Can't call bpf_dynptr_put on a non-initialized dynptr */
SEC("?raw_tp/sys_nanosleep")
int put_uninit_dynptr(void *ctx)
{
	struct bpf_dynptr ptr;

	/* this should fail */
	bpf_dynptr_put(&ptr);

	return 0;
}

/* A dynptr can't be used after bpf_dynptr_put has been called on it */
SEC("?raw_tp/sys_nanosleep")
int use_after_put(void *ctx)
{
	struct bpf_dynptr ptr = {};
	char read_data[64] = {};

	bpf_dynptr_alloc(8, 0, &ptr);

	bpf_dynptr_read(read_data, sizeof(read_data), &ptr, 0);

	bpf_dynptr_put(&ptr);

	/* this should fail */
	bpf_dynptr_read(read_data, sizeof(read_data), &ptr, 0);

	return 0;
}

/*
 * Can't bpf_dynptr_alloc an existing allocated bpf_dynptr that bpf_dynptr_put
 * hasn't been called on yet
 */
SEC("?raw_tp/sys_nanosleep")
int alloc_twice(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_alloc(8, 0, &ptr);

	/* this should fail */
	bpf_dynptr_alloc(2, 0, &ptr);

	bpf_dynptr_put(&ptr);

	return 0;
}

/*
 * Can't access a ring buffer record after submit or discard has been called
 * on the dynptr
 */
SEC("?raw_tp/sys_nanosleep")
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
SEC("?raw_tp/sys_nanosleep")
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

done:
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}

/* Can't access memory outside a ringbuf record range */
SEC("?raw_tp/sys_nanosleep")
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
SEC("?raw_tp/sys_nanosleep")
int add_dynptr_to_map1(void *ctx)
{
	struct bpf_dynptr ptr = {};
	int key = 0;

	err = bpf_dynptr_alloc(sizeof(val), 0, &ptr);

	/* this should fail */
	bpf_map_update_elem(&array_map1, &key, &ptr, 0);

	bpf_dynptr_put(&ptr);

	return 0;
}

/* Can't add a struct with an embedded dynptr to a map */
SEC("?raw_tp/sys_nanosleep")
int add_dynptr_to_map2(void *ctx)
{
	struct test_info x;
	int key = 0;

	bpf_dynptr_alloc(sizeof(val), 0, &x.ptr);

	/* this should fail */
	bpf_map_update_elem(&array_map2, &key, &x, 0);

	return 0;
}

/* Can't pass in a dynptr as an arg to a helper function that doesn't take in a
 * dynptr argument
 */
SEC("?raw_tp/sys_nanosleep")
int invalid_helper1(void *ctx)
{
	struct bpf_dynptr ptr = {};

	bpf_dynptr_alloc(8, 0, &ptr);

	/* this should fail */
	bpf_strncmp((const char *)&ptr, sizeof(ptr), "hello!");

	bpf_dynptr_put(&ptr);

	return 0;
}

/* A dynptr can't be passed into a helper function at a non-zero offset */
SEC("?raw_tp/sys_nanosleep")
int invalid_helper2(void *ctx)
{
	struct bpf_dynptr ptr = {};
	char read_data[64] = {};

	bpf_dynptr_alloc(sizeof(val), 0, &ptr);

	/* this should fail */
	bpf_dynptr_read(read_data, sizeof(read_data), (void *)&ptr + 8, 0);

	bpf_dynptr_put(&ptr);

	return 0;
}

/* A data slice can't be accessed out of bounds */
SEC("?raw_tp/sys_nanosleep")
int data_slice_out_of_bounds(void *ctx)
{
	struct bpf_dynptr ptr = {};
	void *data;

	bpf_dynptr_alloc(8, 0, &ptr);

	data = bpf_dynptr_data(&ptr, 0, 8);
	if (!data)
		goto done;

	/* can't index out of bounds of the data slice */
	val = *((char *)data + 8);

done:
	bpf_dynptr_put(&ptr);
	return 0;
}

/* A data slice can't be used after bpf_dynptr_put is called */
SEC("?raw_tp/sys_nanosleep")
int data_slice_use_after_put(void *ctx)
{
	struct bpf_dynptr ptr = {};
	void *data;

	bpf_dynptr_alloc(8, 0, &ptr);

	data = bpf_dynptr_data(&ptr, 0, 8);
	if (!data)
		goto done;

	bpf_dynptr_put(&ptr);

	/* this should fail */
	val = *(__u8 *)data;

done:
	bpf_dynptr_put(&ptr);
	return 0;
}

/* A bpf_dynptr can't be used as a dynptr if it's been written into */
SEC("?raw_tp/sys_nanosleep")
int invalid_write1(void *ctx)
{
	struct bpf_dynptr ptr = {};
	__u8 x = 0;

	bpf_dynptr_alloc(8, 0, &ptr);

	memcpy(&ptr, &x, sizeof(x));

	/* this should fail */
	bpf_dynptr_put(&ptr);

	return 0;
}

/*
 * A bpf_dynptr can't be used as a dynptr if an offset into it has been
 * written into
 */
SEC("?raw_tp/sys_nanosleep")
int invalid_write2(void *ctx)
{
	struct bpf_dynptr ptr = {};
	char read_data[64] = {};
	__u8 x = 0, y = 0;

	bpf_dynptr_alloc(sizeof(x), 0, &ptr);

	memcpy((void *)&ptr + 8, &y, sizeof(y));

	/* this should fail */
	bpf_dynptr_read(read_data, sizeof(read_data), &ptr, 0);

	bpf_dynptr_put(&ptr);

	return 0;
}

/*
 * A bpf_dynptr can't be used as a dynptr if a non-const offset into it
 * has been written into
 */
SEC("?raw_tp/sys_nanosleep")
int invalid_write3(void *ctx)
{
	struct bpf_dynptr ptr = {};
	char stack_buf[16];
	unsigned long len;
	__u8 x = 0;

	bpf_dynptr_alloc(8, 0, &ptr);

	memcpy(stack_buf, &val, sizeof(val));
	len = stack_buf[0] & 0xf;

	memcpy((void *)&ptr + len, &x, sizeof(x));

	/* this should fail */
	bpf_dynptr_put(&ptr);

	return 0;
}

static int invalid_write4_callback(__u32 index, void *data)
{
	*(__u32 *)data = 123;

	return 0;
}

/* If the dynptr is written into in a callback function, it should
 * be invalidated as a dynptr
 */
SEC("?raw_tp/sys_nanosleep")
int invalid_write4(void *ctx)
{
	struct bpf_dynptr ptr;
	__u64 x = 0;

	bpf_dynptr_alloc(sizeof(x), 0, &ptr);

	bpf_loop(10, invalid_write4_callback, &ptr, 0);

	/* this should fail */
	bpf_dynptr_put(&ptr);

	return 0;
}

/* A globally-defined bpf_dynptr can't be used (it must reside as a stack frame) */
struct bpf_dynptr global_dynptr;
SEC("?raw_tp/sys_nanosleep")
int global(void *ctx)
{
	/* this should fail */
	bpf_dynptr_alloc(4, 0, &global_dynptr);

	bpf_dynptr_put(&global_dynptr);

	return 0;
}

/* A direct read should fail */
SEC("?raw_tp/sys_nanosleep")
int invalid_read1(void *ctx)
{
	struct bpf_dynptr ptr = {};
	__u32 x = 2;

	bpf_dynptr_alloc(sizeof(x), 0, &ptr);

	/* this should fail */
	val = *(int *)&ptr;

	bpf_dynptr_put(&ptr);

	return 0;
}

/* A direct read at an offset should fail */
SEC("?raw_tp/sys_nanosleep")
int invalid_read2(void *ctx)
{
	struct bpf_dynptr ptr = {};
	char read_data[64] = {};
	__u64 x = 0;

	bpf_dynptr_alloc(sizeof(x), 0, &ptr);

	/* this should fail */
	bpf_dynptr_read(read_data, sizeof(read_data), (void *)&ptr + 1, 0);

	bpf_dynptr_put(&ptr);

	return 0;
}

/* A direct read at an offset into the lower stack slot should fail */
SEC("?raw_tp/sys_nanosleep")
int invalid_read3(void *ctx)
{
	struct bpf_dynptr ptr1 = {};
	struct bpf_dynptr ptr2 = {};

	bpf_dynptr_alloc(sizeof(val), 0, &ptr1);
	bpf_dynptr_alloc(sizeof(val), 0, &ptr2);

	/* this should fail */
	memcpy(&val, (void *)&ptr1 + 8, sizeof(val));

	bpf_dynptr_put(&ptr1);
	bpf_dynptr_put(&ptr2);

	return 0;
}

/* Calling bpf_dynptr_alloc on an offset should fail */
SEC("?raw_tp/sys_nanosleep")
int invalid_offset(void *ctx)
{
	struct bpf_dynptr ptr = {};

	/* this should fail */
	bpf_dynptr_alloc(sizeof(val), 0, &ptr + 1);

	bpf_dynptr_put(&ptr);

	return 0;
}

/* Can't call bpf_dynptr_put twice */
SEC("?raw_tp/sys_nanosleep")
int put_twice(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_alloc(8, 0, &ptr);

	bpf_dynptr_put(&ptr);

	/* this second put should fail */
	bpf_dynptr_put(&ptr);

	return 0;
}

static int put_twice_callback_fn(__u32 index, void *data)
{
	/* this should fail */
	bpf_dynptr_put(data);
	val = index;
	return 0;
}

/* Test that calling bpf_dynptr_put twice, where the 2nd put happens within a
 * calback function, fails
 */
SEC("?raw_tp/sys_nanosleep")
int put_twice_callback(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_alloc(8, 0, &ptr);

	bpf_dynptr_put(&ptr);

	bpf_loop(10, put_twice_callback_fn, &ptr, 0);

	return 0;
}

/* Can't access memory in a zero-slice */
SEC("?raw_tp/sys_nanosleep")
int zero_slice_access(void *ctx)
{
	struct bpf_dynptr ptr;
	void *data;

	bpf_dynptr_alloc(0, 0, &ptr);

	data = bpf_dynptr_data(&ptr, 0, 0);
	if (!data)
		goto done;

	/* this should fail */
	*(__u8 *)data = 23;

	val = *(__u8 *)data;

done:
	bpf_dynptr_put(&ptr);
	return 0;
}
