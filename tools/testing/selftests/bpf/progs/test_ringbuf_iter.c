// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(map_flags, BPF_F_RB_OVERWRITE);
} ringbuf_ow SEC(".maps");

/*
 * Context of the producer programs, which are run with
 * bpf_prog_test_run_opts(). Every 8-byte word of a record holds its sequence
 * number, so that the consumer can check all of its data.
 */
struct produce_args {
	__u64 seq;		/* in: first sequence number, out: next one */
	__u32 count;		/* records to produce */
	__u32 size;		/* record size in bytes */
	__u32 discard_mod;	/* discard records whose seq is a multiple of this, 0: none */
	__u32 flags;		/* submit/discard flags, e.g. BPF_RB_NO_WAKEUP */
	__u32 produced;		/* out: records produced */
};

static __always_inline int produce(void *map, struct produce_args *args)
{
	__u32 size = args->size, words = size / 8;
	__u64 seq = args->seq;
	struct bpf_dynptr ptr;
	int i, j;

	bpf_for(i, 0, args->count) {
		if (bpf_ringbuf_reserve_dynptr(map, size, 0, &ptr)) {
			bpf_ringbuf_discard_dynptr(&ptr, 0);
			continue;
		}
		bpf_for(j, 0, words)
			bpf_dynptr_write(&ptr, j * 8, &seq, 8, 0);
		if (args->discard_mod && seq % args->discard_mod == 0)
			bpf_ringbuf_discard_dynptr(&ptr, args->flags);
		else
			bpf_ringbuf_submit_dynptr(&ptr, args->flags);
		args->produced++;
		seq++;
	}
	args->seq = seq;
	return 0;
}

SEC("syscall")
int produce_normal(struct produce_args *args)
{
	return produce(&ringbuf, args);
}

SEC("syscall")
int produce_overwrite(struct produce_args *args)
{
	return produce(&ringbuf_ow, args);
}
