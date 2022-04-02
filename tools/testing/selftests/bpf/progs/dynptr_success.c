// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

int pid = 0;
int err = 0;
int val;

struct sample {
	int pid;
	int seq;
	long value;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} ringbuf SEC(".maps");

SEC("tp/syscalls/sys_enter_nanosleep")
int prog_success(void *ctx)
{
	char buf[64] = {};
	char write_data[64] = "hello there, world!!";
	struct bpf_dynptr ptr = {}, mem = {};
	__u8 mem_allocated = 0;
	char read_data[64] = {};
	__u32 val = 0;
	void *data;
	int i;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	err = bpf_dynptr_from_mem(buf, sizeof(buf), &ptr);
	if (err)
		goto done;

	/* Write data into the dynptr */
	err = bpf_dynptr_write(&ptr, 0, write_data, sizeof(write_data));
	if (err)
		goto done;

	/* Read the data that was written into the dynptr */
	err = bpf_dynptr_read(read_data, sizeof(read_data), &ptr, 0);
	if (err)
		goto done;

	/* Ensure the data we read matches the data we wrote */
	for (i = 0; i < sizeof(read_data); i++) {
		if (read_data[i] != write_data[i]) {
			err = 1;
			goto done;
		}
	}

done:
	if (mem_allocated)
		bpf_free(&mem);
	return 0;
}

SEC("tp/syscalls/sys_enter_nanosleep")
int prog_success_data_slice(void *ctx)
{
	struct bpf_dynptr mem;
	void *data;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	err = bpf_malloc(16, &mem);
	if (err)
		goto done;

	data = bpf_dynptr_data(&mem, 0, sizeof(__u32));
	if (!data)
		goto done;

	*(__u32 *)data = 999;

	err = bpf_probe_read_kernel(&val, sizeof(val), data);
	if (err)
		goto done;

	if (val != *(__u32 *)data)
		err = 2;

done:
	bpf_free(&mem);
	return 0;
}

static int ringbuf_callback(__u32 index, void *data)
{
	struct sample *sample;

	struct bpf_dynptr *ptr = (struct bpf_dynptr *)data;

	sample = bpf_dynptr_data(ptr, 0, sizeof(*sample));
	if (!sample)
		return 0;

	sample->pid += val;

	return 0;
}

SEC("tp/syscalls/sys_enter_nanosleep")
int prog_success_ringbuf(void *ctx)
{
	struct bpf_dynptr ptr;
	void *data;
	struct sample *sample;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	/* check that you can reserve a dynamic size reservation */
	err = bpf_ringbuf_reserve_dynptr(&ringbuf, val, 0, &ptr);
	if (err)
		goto done;

	sample = bpf_dynptr_data(&ptr, 0, sizeof(*sample));
	if (!sample)
		goto done;

	sample->pid = 123;

	/* Can pass dynptr to callback functions */
	bpf_loop(10, ringbuf_callback, &ptr, 0);

	bpf_ringbuf_submit_dynptr(&ptr, 0);

	return 0;

done:
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}
