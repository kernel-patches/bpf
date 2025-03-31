// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} ringbuf SEC(".maps");

struct value {
	struct bpf_stream_elem_batch __kptr *batch;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct value);
	__uint(max_entries, 1);
} array SEC(".maps");

int written_size;
int written_count;
int stream_id;
int prog_id;

#define ENOENT 2
#define EAGAIN 11
#define EFAULT 14

SEC("syscall")
int bpftool_dump_prog_stream(void *ctx)
{
	struct bpf_stream_elem_batch *elem_batch;
	struct bpf_stream_elem *elem;
	struct bpf_stream *stream;
	bool cont = false;
	struct value *v;
	bool ret = 0;

	stream = bpf_prog_stream_get(BPF_STDERR, prog_id);
	if (!stream)
		return ENOENT;

	v = bpf_map_lookup_elem(&array, &(int){0});

	if (v->batch)
		elem_batch = bpf_kptr_xchg(&v->batch, NULL);
	else
		elem_batch = bpf_stream_next_elem_batch(stream);
	if (!elem_batch)
		goto end;

	bpf_repeat(BPF_MAX_LOOPS) {
		struct bpf_dynptr dst_dptr, src_dptr;
		int size;

		elem = bpf_stream_next_elem(elem_batch);
		if (!elem)
			break;
		size = elem->mem_slice.len;

		if (bpf_dynptr_from_mem_slice(&elem->mem_slice, 0, &src_dptr))
			ret = EFAULT;
		if (bpf_ringbuf_reserve_dynptr(&ringbuf, size, 0, &dst_dptr))
			ret = EFAULT;
		if (bpf_dynptr_copy(&dst_dptr, 0, &src_dptr, 0, size))
			ret = EFAULT;
		bpf_ringbuf_submit_dynptr(&dst_dptr, 0);

		written_count++;
		written_size += size;

		bpf_stream_free_elem(elem);

		/* Probe and exit if no more space, probe for twice the typical size.*/
		if (bpf_ringbuf_reserve_dynptr(&ringbuf, 2048, 0, &dst_dptr))
			cont = true;
		bpf_ringbuf_discard_dynptr(&dst_dptr, 0);

		if (ret || cont)
			break;
	}

	if (cont)
		elem_batch = bpf_kptr_xchg(&v->batch, elem_batch);
	if (elem_batch)
		bpf_stream_free_elem_batch(elem_batch);
end:
	bpf_prog_stream_put(stream);

	return ret ?: (cont ? EAGAIN : 0);
}

char _license[] SEC("license") = "GPL";
