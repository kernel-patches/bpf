// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_test_utils.h"

int classifier_0(struct __sk_buff *skb);
int classifier_1(struct __sk_buff *skb);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(__u32));
	__array(values, void (void));
} jmp_table SEC(".maps") = {
	.values = {
		[0] = (void *) &classifier_0,
		[1] = (void *) &classifier_1,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} arraymap SEC(".maps");

__auxiliary
SEC("tc")
int classifier_0(struct __sk_buff *skb)
{
	return 0;
}

static __noinline
int subprog_tail1(struct __sk_buff *skb)
{
	int ret = 0;

	bpf_tail_call_static(skb, &jmp_table, 1);
	barrier_var(ret);
	return ret;
}

__auxiliary
SEC("tc")
int classifier_1(struct __sk_buff *skb)
{
	int ret;

	ret = subprog_tail1(skb);
	__sink(ret);
	return 0;
}

static __noinline
int subprog_tail0(struct __sk_buff *skb)
{
	int ret;

	ret = subprog_tail1(skb);
	barrier_var(ret);
	return ret;
}

static __noinline
int callback_loop_1(int index, void **cb_ctx)
{
	int ret = 0;

	bpf_tail_call_static(*cb_ctx, &jmp_table, 0);
	barrier_var(ret);
	return ret;
}

static __noinline
int callback_loop_2(int index, void **cb_ctx)
{
	int ret;

	ret = subprog_tail1(*cb_ctx);
	barrier_var(ret);
	return ret ? 1 : 0;
}

static __noinline
int callback_for_each(void *map, __u32 *key, __u64 *val, void **cb_ctx)
{
	int ret;

	ret = subprog_tail0(*cb_ctx);
	barrier_var(ret);
	return ret ? 1 : 0;
}
/* callback involving tail call directly is rejected */
SEC("tc")
__failure __msg("callback unexpected regs 1")
int tailcall_direct_callback(struct __sk_buff *skb)
{
	clobber_regs_stack();

	bpf_loop(1, callback_loop_1, &skb, 0);
	return 0;
}

/* callback involving 1 subprog with tail call is rejected */
SEC("tc")
__failure __msg("cannot tail call within callback")
int tailcall_bpf2bpf_callback_1(struct __sk_buff *skb)
{
	clobber_regs_stack();

	bpf_loop(1, callback_loop_2, &skb, 0);
	return 0;
}

/* callback involving 2 subprogs with tail call is rejected */
SEC("tc")
__failure __msg("cannot tail call within callback")
int tailcall_bpf2bpf_callback_2(struct __sk_buff *skb)
{
	clobber_regs_stack();

	bpf_for_each_map_elem(&arraymap, callback_for_each, &skb, 0);
	return 0;
}

char __license[] SEC("license") = "GPL";
