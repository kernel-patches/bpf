// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "errno.h"

char _license[] SEC("license") = "GPL";

int pid;
int err;
int val;

struct sample {
	int pid;
	int seq;
	long value;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} ringbuf SEC(".maps");

SEC("tp/syscalls/sys_enter_nanosleep")
int test_basic(void *ctx)
{
	char write_data[64] = "hello there, world!!";
	char read_data[64] = {}, buf[64] = {};
	struct bpf_dynptr ptr = {};
	int i;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	err = bpf_dynptr_alloc(sizeof(write_data), 0, &ptr);

	/* Write data into the dynptr */
	err = err ?: bpf_dynptr_write(&ptr, 0, write_data, sizeof(write_data));

	/* Read the data that was written into the dynptr */
	err = err ?: bpf_dynptr_read(read_data, sizeof(read_data), &ptr, 0);

	/* Ensure the data we read matches the data we wrote */
	for (i = 0; i < sizeof(read_data); i++) {
		if (read_data[i] != write_data[i]) {
			err = 1;
			break;
		}
	}

	bpf_dynptr_put(&ptr);
	return 0;
}

SEC("tp/syscalls/sys_enter_nanosleep")
int test_data_slice(void *ctx)
{
	struct bpf_dynptr ptr;
	__u32 alloc_size = 16;
	void *data;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	/* test passing in an invalid flag */
	err = bpf_dynptr_alloc(alloc_size, 1, &ptr);
	if (err != -EINVAL) {
		err = 1;
		goto done;
	}
	bpf_dynptr_put(&ptr);

	err = bpf_dynptr_alloc(alloc_size, 0, &ptr);
	if (err)
		goto done;

	/* Try getting a data slice that is out of range */
	data = bpf_dynptr_data(&ptr, alloc_size + 1, 1);
	if (data) {
		err = 2;
		goto done;
	}

	/* Try getting more bytes than available */
	data = bpf_dynptr_data(&ptr, 0, alloc_size + 1);
	if (data) {
		err = 3;
		goto done;
	}

	data = bpf_dynptr_data(&ptr, 0, sizeof(int));
	if (!data) {
		err = 4;
		goto done;
	}

	*(__u32 *)data = 999;

	err = bpf_probe_read_kernel(&val, sizeof(val), data);
	if (err)
		goto done;

	if (val != *(int *)data)
		err = 5;

done:
	bpf_dynptr_put(&ptr);
	return 0;
}

static int ringbuf_callback(__u32 index, void *data)
{
	struct sample *sample;

	struct bpf_dynptr *ptr = (struct bpf_dynptr *)data;

	sample = bpf_dynptr_data(ptr, 0, sizeof(*sample));
	if (!sample)
		err = 2;
	else
		sample->pid += val;

	return 0;
}

SEC("tp/syscalls/sys_enter_nanosleep")
int test_ringbuf(void *ctx)
{
	struct bpf_dynptr ptr;
	struct sample *sample;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	val = 100;

	/* check that you can reserve a dynamic size reservation */
	err = bpf_ringbuf_reserve_dynptr(&ringbuf, val, 0, &ptr);

	sample = err ? NULL : bpf_dynptr_data(&ptr, 0, sizeof(*sample));
	if (!sample) {
		err = 1;
		goto done;
	}

	sample->pid = 123;

	/* Can pass dynptr to callback functions */
	bpf_loop(10, ringbuf_callback, &ptr, 0);

	bpf_ringbuf_submit_dynptr(&ptr, 0);

	return 0;

done:
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_nanosleep")
int test_alloc_zero_bytes(void *ctx)
{
	struct bpf_dynptr ptr;
	void *data;
	__u8 x = 0;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	err = bpf_dynptr_alloc(0, 0, &ptr);
	if (err)
		goto done;

	err = bpf_dynptr_write(&ptr, 0, &x, sizeof(x));
	if (err != -E2BIG) {
		err = 1;
		goto done;
	}

	err = bpf_dynptr_read(&x, sizeof(x), &ptr, 0);
	if (err != -E2BIG) {
		err = 2;
		goto done;
	}
	err = 0;

	/* try to access memory we don't have access to */
	data = bpf_dynptr_data(&ptr, 0, 1);
	if (data) {
		err = 3;
		goto done;
	}

	data = bpf_dynptr_data(&ptr, 0, 0);
	if (!data) {
		err = 4;
		goto done;
	}

done:
	bpf_dynptr_put(&ptr);
	return 0;
}
