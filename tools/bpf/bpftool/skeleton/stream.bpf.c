// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} ringbuf SEC(".maps");

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
	struct bpf_stream_elem *elem;
	struct bpf_stream *stream;
	bool cont = false;
	bool ret = 0;

	stream = bpf_prog_stream_get(stream_id, prog_id);
	if (!stream)
		return ENOENT;

	bpf_repeat(BPF_MAX_LOOPS) {
		struct bpf_dynptr dst_dptr, src_dptr;
		int size;

		elem = bpf_stream_next_elem(stream);
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

		/* Probe and exit if no more space, probe for twice the typical size. */
		if (bpf_ringbuf_reserve_dynptr(&ringbuf, 2048, 0, &dst_dptr))
			cont = true;
		bpf_ringbuf_discard_dynptr(&dst_dptr, 0);

		if (ret || cont)
			break;
	}

	bpf_prog_stream_put(stream);

	return ret ? ret : (cont ? EAGAIN : 0);
}

char _license[] SEC("license") = "Dual BSD/GPL";
