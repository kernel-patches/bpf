// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

int iter_content_match = 0;
int iter_step_match = 0;

SEC("syscall")
int bpf_iter_dynptr_buffer_fit(const void *ctx)
{
	struct bpf_iter_dynptr dynptr_it;
	struct bpf_dynptr ptr;

	char write_data[5] = {'a', 'b', 'c', 'd', 'e'};
	char read_data1[2], read_data2[3];
	int *read_len, offset;

	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(write_data), 0, &ptr);

	bpf_dynptr_write(&ptr, 0, write_data, sizeof(write_data), 0);

	bpf_iter_dynptr_new(&dynptr_it, &ptr, 0, read_data1, sizeof(read_data1));

	read_len = bpf_iter_dynptr_next(&dynptr_it);
	offset = bpf_iter_dynptr_get_last_offset(&dynptr_it);

	if (read_len == NULL) {
		iter_step_match = -1;
		goto out;
	}

	if (*read_len != sizeof(read_data1)) {
		iter_step_match = -1;
		goto out;
	}

	if (offset != 0) {
		iter_step_match = -1;
		goto out;
	}

	if (read_data1[0] != write_data[0] || read_data1[1] != write_data[1]) {
		iter_content_match = -1;
		goto out;
	}

	bpf_iter_dynptr_set_buffer(&dynptr_it, read_data2, sizeof(read_data2));

	read_len = bpf_iter_dynptr_next(&dynptr_it);
	offset = bpf_iter_dynptr_get_last_offset(&dynptr_it);

	if (read_len == NULL) {
		iter_step_match = -1;
		goto out;
	}

	if (*read_len != sizeof(read_data2)) {
		iter_step_match = -1;
		goto out;
	}

	if (offset != 2) {
		iter_step_match = -1;
		goto out;
	}

	if (read_data2[0] != write_data[2] || read_data2[1] != write_data[3] ||
	   read_data2[2] != write_data[4]) {
		iter_content_match = -1;
		goto out;
	}

	read_len = bpf_iter_dynptr_next(&dynptr_it);
	if (read_len != NULL)
		iter_step_match = -1;
out:
	bpf_iter_dynptr_destroy(&dynptr_it);
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}

SEC("syscall")
int bpf_iter_dynptr_buffer_remain(const void *ctx)
{
	struct bpf_iter_dynptr dynptr_it;
	struct bpf_dynptr ptr;

	char write_data[1] = {'a'};
	char read_data[2];
	int *read_len, offset;

	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(write_data), 0, &ptr);

	bpf_dynptr_write(&ptr, 0, write_data, sizeof(write_data), 0);

	bpf_iter_dynptr_new(&dynptr_it, &ptr, 0, read_data, sizeof(read_data));

	read_len = bpf_iter_dynptr_next(&dynptr_it);
	offset = bpf_iter_dynptr_get_last_offset(&dynptr_it);

	if (read_len == NULL) {
		iter_step_match = -1;
		goto out;
	}

	if (*read_len != 1) {
		iter_step_match = -1;
		goto out;
	}

	if (offset != 0) {
		iter_step_match = -1;
		goto out;
	}

	if (read_data[0] != write_data[0]) {
		iter_content_match = -1;
		goto out;
	}

	read_len = bpf_iter_dynptr_next(&dynptr_it);
	if (read_len != NULL)
		iter_step_match = -1;
out:
	bpf_iter_dynptr_destroy(&dynptr_it);
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}
