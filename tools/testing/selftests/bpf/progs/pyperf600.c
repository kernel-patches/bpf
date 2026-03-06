// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#define STACK_MAX_LEN 600
/* Full unroll of 600 iterations will have total
 * program size close to 298k insns and this may
 * cause BPF_JMP insn out of 16-bit integer range.
 * So limit the unroll size to 150 so the
 * total program size is around 80k insns but
 * the loop will still execute 600 times.
 */
#define UNROLL_COUNT 150
#define PYPERF_CUSTOM_ON_EVENT
#include "pyperf.h"

SEC("raw_tracepoint/kfree_skb")
int on_event(struct bpf_raw_tracepoint_args *ctx)
{
	return __on_event(ctx);
}
