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

SEC("raw_tp/sys_enter")
__failure __msg("Expected an initialized dynptr as arg #2")
int bpf_iter_dynptr_new_uninit_dynptr(void *ctx)
{
	struct bpf_iter_dynptr dynptr_it;
	struct bpf_dynptr ptr;
	char read_data[5];

	bpf_iter_dynptr_new(&dynptr_it, &ptr, 0, read_data, sizeof(read_data));

	return 0;
}

SEC("raw_tp/sys_enter")
__failure __msg("arg#3 arg#4 memory, len pair leads to invalid memory access")
int bpf_iter_dynptr_new_null_buffer(void *ctx)
{
	struct bpf_iter_dynptr dynptr_it;
	struct bpf_dynptr ptr;
	char *read_data = NULL;

	bpf_ringbuf_reserve_dynptr(&ringbuf, 10, 0, &ptr);

	bpf_iter_dynptr_new(&dynptr_it, &ptr, 0, read_data, 10);

	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}

SEC("raw_tp/sys_enter")
__failure __msg("expected an initialized iter_dynptr as arg #1")
int bpf_iter_dynptr_next_uninit_iter(void *ctx)
{
	struct bpf_iter_dynptr dynptr_it;

	bpf_iter_dynptr_next(&dynptr_it);

	return 0;
}

SEC("raw_tp/sys_enter")
__failure __msg("expected an initialized iter_dynptr as arg #1")
int bpf_iter_dynptr_get_last_offset_uninit_iter(void *ctx)
{
	struct bpf_iter_dynptr dynptr_it;

	bpf_iter_dynptr_get_last_offset(&dynptr_it);

	return 0;
}

SEC("raw_tp/sys_enter")
__failure __msg("expected an initialized iter_dynptr as arg #1")
int bpf_iter_dynptr_set_buffer_uninit_iter(void *ctx)
{
	struct bpf_iter_dynptr dynptr_it;
	char read_data[5];

	bpf_iter_dynptr_set_buffer(&dynptr_it, read_data, sizeof(read_data));

	return 0;
}

SEC("raw_tp/sys_enter")
__failure __msg("arg#1 arg#2 memory, len pair leads to invalid memory access")
int bpf_iter_dynptr_set_buffer_null_buffer(void *ctx)
{
	struct bpf_iter_dynptr dynptr_it;
	struct bpf_dynptr ptr;
	char *null_data = NULL;
	char read_data[5];

	bpf_ringbuf_reserve_dynptr(&ringbuf, 10, 0, &ptr);

	bpf_iter_dynptr_new(&dynptr_it, &ptr, 0, read_data, sizeof(read_data));

	bpf_iter_dynptr_set_buffer(&dynptr_it, null_data, 10);

	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}

SEC("raw_tp/sys_enter")
__failure __msg("expected an initialized iter_dynptr as arg #1")
int bpf_iter_dynptr_destroy_uninit_iter(void *ctx)
{
	struct bpf_iter_dynptr dynptr_it;

	bpf_iter_dynptr_destroy(&dynptr_it);

	return 0;
}
