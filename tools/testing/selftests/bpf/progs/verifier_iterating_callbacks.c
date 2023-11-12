// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 8);
} ringbuf SEC(".maps");

struct vm_area_struct;
struct bpf_map;

struct buf_context {
	char *buf;
};

struct num_context {
	__u64 i;
	__u64 j;
};

__u8 choice_arr[2] = { 0, 1 };

static int unsafe_on_2nd_iter_cb(__u32 idx, struct buf_context *ctx)
{
	if (idx == 0) {
		ctx->buf = (char *)(0xDEAD);
		return 0;
	}

	if (bpf_probe_read_user(ctx->buf, 8, (void *)(0xBADC0FFEE)))
		return 1;

	return 0;
}

SEC("?raw_tp")
__failure __msg("R1 type=scalar expected=fp")
int unsafe_on_2nd_iter(void *unused)
{
	char buf[4];
	struct buf_context loop_ctx = { .buf = buf };

	bpf_loop(100, unsafe_on_2nd_iter_cb, &loop_ctx, 0);
	return 0;
}

static int unsafe_on_zero_iter_cb(__u32 idx, struct num_context *ctx)
{
	ctx->i = 0;
	return 0;
}

SEC("?raw_tp")
__failure __msg("invalid access to map value, value_size=2 off=32 size=1")
int unsafe_on_zero_iter(void *unused)
{
	struct num_context loop_ctx = { .i = 32 };

	bpf_loop(100, unsafe_on_zero_iter_cb, &loop_ctx, 0);
	return choice_arr[loop_ctx.i];
}

static int widening_cb(__u32 idx, struct num_context *ctx)
{
	++ctx->i;
	return 0;
}

SEC("?raw_tp")
__success
int widening(void *unused)
{
	struct num_context loop_ctx = { .i = 0, .j = 1 };

	bpf_loop(100, widening_cb, &loop_ctx, 0);
	/* loop_ctx.j is not changed during callback iteration,
	 * verifier should not apply widening to it.
	 */
	return choice_arr[loop_ctx.j];
}

static int loop_detection_cb(__u32 idx, struct num_context *ctx)
{
	for (;;) {}
	return 0;
}

SEC("?raw_tp")
__failure __msg("infinite loop detected")
int loop_detection(void *unused)
{
	struct num_context loop_ctx = { .i = 0 };

	bpf_loop(100, loop_detection_cb, &loop_ctx, 0);
	return 0;
}

static __always_inline __u64 oob_state_machine(struct num_context *ctx)
{
	switch (ctx->i) {
	case 0:
		ctx->i = 1;
		break;
	case 1:
		ctx->i = 32;
		break;
	}
	return 0;
}

static __u64 for_each_map_elem_cb(struct bpf_map *map, __u32 *key, __u64 *val, void *data)
{
	return oob_state_machine(data);
}

SEC("?raw_tp")
__failure __msg("invalid access to map value, value_size=2 off=32 size=1")
int unsafe_for_each_map_elem(void *unused)
{
	struct num_context loop_ctx = { .i = 0 };

	bpf_for_each_map_elem(&map, for_each_map_elem_cb, &loop_ctx, 0);
	return choice_arr[loop_ctx.i];
}

static __u64 ringbuf_drain_cb(struct bpf_dynptr *dynptr, void *data)
{
	return oob_state_machine(data);
}

SEC("?raw_tp")
__failure __msg("invalid access to map value, value_size=2 off=32 size=1")
int unsafe_ringbuf_drain(void *unused)
{
	struct num_context loop_ctx = { .i = 0 };

	bpf_user_ringbuf_drain(&ringbuf, ringbuf_drain_cb, &loop_ctx, 0);
	return choice_arr[loop_ctx.i];
}

static __u64 find_vma_cb(struct task_struct *task, struct vm_area_struct *vma, void *data)
{
	return oob_state_machine(data);
}

SEC("?raw_tp")
__failure __msg("invalid access to map value, value_size=2 off=32 size=1")
int unsafe_find_vma(void *unused)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct num_context loop_ctx = { .i = 0 };

	bpf_find_vma(task, 0, find_vma_cb, &loop_ctx, 0);
	return choice_arr[loop_ctx.i];
}

static int iter_limit_cb(__u32 idx, struct num_context *ctx)
{
	ctx->i++;
	return 0;
}

SEC("?raw_tp")
__success
int bpf_loop_iter_limit_ok(void *unused)
{
	struct num_context ctx = { .i = 0 };

	bpf_loop(1, iter_limit_cb, &ctx, 0);
	return choice_arr[ctx.i];
}

SEC("?raw_tp")
__failure __msg("invalid access to map value, value_size=2 off=2 size=1")
int bpf_loop_iter_limit_overflow(void *unused)
{
	struct num_context ctx = { .i = 0 };

	bpf_loop(2, iter_limit_cb, &ctx, 0);
	return choice_arr[ctx.i];
}

static int iter_limit_level2a_cb(__u32 idx, struct num_context *ctx)
{
	ctx->i += 100;
	return 0;
}

static int iter_limit_level2b_cb(__u32 idx, struct num_context *ctx)
{
	ctx->i += 10;
	return 0;
}

static int iter_limit_level1_cb(__u32 idx, struct num_context *ctx)
{
	ctx->i += 1;
	bpf_loop(1, iter_limit_level2a_cb, ctx, 0);
	bpf_loop(1, iter_limit_level2b_cb, ctx, 0);
	return 0;
}

SEC("?raw_tp")
__success __log_level(2)
/* Check that last verified exit from the program visited each
 * callback expected number of times: one visit per callback for each
 * top level bpf_loop call.
 */
__msg("r1 = *(u64 *)(r10 -16)       ; R1_w=111111 R10=fp0 fp-16=111111")
/* Ensure that read above is the last one by checking that there are
 * no more reads for ctx.i.
 */
__not_msg("r1 = *(u64 *)(r10 -16)	; R1_w=")
int bpf_loop_iter_limit_nested(void *unused)
{
	struct num_context ctx = { .i = 0 };

	bpf_loop(1, iter_limit_level1_cb, &ctx, 0);
	ctx.i *= 1000;
	bpf_loop(1, iter_limit_level1_cb, &ctx, 0);
	return choice_arr[ctx.i % 2];
}

char _license[] SEC("license") = "GPL";
