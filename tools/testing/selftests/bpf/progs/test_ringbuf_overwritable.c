// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct sample {
	int count;
	/*
	 * filler size will be computed to have 8 samples in a 4096 bytes long
	 * buffer.
	 */
	char filler[4096 / 8 - sizeof(int) - BPF_RINGBUF_HDR_SZ];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(map_flags, BFP_F_RB_OVERWRITABLE);
} ringbuf SEC(".maps");

/* inputs */
int pid = 0;

/* outputs */
long avail_data = 0;
long ring_size = 0;
long cons_pos = 0;
long prod_pos = 0;

static int count;

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int test_ringbuf_overwritable(void *ctx)
{
	int cur_pid = bpf_get_current_pid_tgid() >> 32;
	struct sample *sample;

	if (cur_pid != pid)
		return 0;

	sample = bpf_ringbuf_reserve(&ringbuf, sizeof(*sample), 0);
	if (!sample)
		return 0;

	__sync_fetch_and_add(&count, 1);
	sample->count = count;

	bpf_printk("count: %d\n", count);

	bpf_ringbuf_submit(sample, 0);

	avail_data = bpf_ringbuf_query(&ringbuf, BPF_RB_AVAIL_DATA);
	ring_size = bpf_ringbuf_query(&ringbuf, BPF_RB_RING_SIZE);
	cons_pos = bpf_ringbuf_query(&ringbuf, BPF_RB_CONS_POS);
	prod_pos = bpf_ringbuf_query(&ringbuf, BPF_RB_PROD_POS);

	return 0;
}
