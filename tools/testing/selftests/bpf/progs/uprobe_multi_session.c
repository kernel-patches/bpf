// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

__u64 uprobe_multi_func_1_addr = 0;
__u64 uprobe_multi_func_2_addr = 0;
__u64 uprobe_multi_func_3_addr = 0;

__u64 uprobe_multi_func_1_result = 0;
__u64 uprobe_multi_func_2_result = 0;
__u64 uprobe_multi_func_3_result = 0;

__u64 uretprobe_multi_func_1_result = 0;
__u64 uretprobe_multi_func_2_result = 0;
__u64 uretprobe_multi_func_3_result = 0;

int pid = 0;
int child_pid = 0;

static int uprobe_multi_check(void *ctx, bool is_return)
{
	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 1;

	__u64 addr = bpf_get_func_ip(ctx);

#define SET(__var, __addr) ({	\
	if (addr == __addr)	\
		__var += 1;	\
})

	if (is_return) {
		SET(uretprobe_multi_func_1_result, uprobe_multi_func_1_addr);
		SET(uretprobe_multi_func_2_result, uprobe_multi_func_2_addr);
		SET(uretprobe_multi_func_3_result, uprobe_multi_func_3_addr);
	} else {
		SET(uprobe_multi_func_1_result, uprobe_multi_func_1_addr);
		SET(uprobe_multi_func_2_result, uprobe_multi_func_2_addr);
		SET(uprobe_multi_func_3_result, uprobe_multi_func_3_addr);
	}

#undef SET

	if ((addr == uprobe_multi_func_2_addr) ||
	    (addr == uprobe_multi_func_3_addr))
		return 1;

	return 0;
}

SEC("uprobe.session//proc/self/exe:uprobe_multi_func_*")
int uprobe(struct pt_regs *ctx)
{
	return uprobe_multi_check(ctx, bpf_session_is_return());
}
