// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

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
bool test_cookie = false;

static void uprobe_multi_check(void *ctx, bool is_return)
{
	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return;

	__u64 cookie = test_cookie ? bpf_get_attach_cookie(ctx) : 0;
	__u64 addr = bpf_get_func_ip(ctx);

#define SET(__var, __addr, __cookie) ({			\
	if (addr == __addr &&				\
	   (!test_cookie || (cookie == __cookie)))	\
		__var = 1;				\
})

	if (is_return) {
		SET(uretprobe_multi_func_1_result, uprobe_multi_func_1_addr, 2);
		SET(uretprobe_multi_func_2_result, uprobe_multi_func_2_addr, 3);
		SET(uretprobe_multi_func_3_result, uprobe_multi_func_3_addr, 1);
	} else {
		SET(uprobe_multi_func_1_result, uprobe_multi_func_1_addr, 3);
		SET(uprobe_multi_func_2_result, uprobe_multi_func_2_addr, 1);
		SET(uprobe_multi_func_3_result, uprobe_multi_func_3_addr, 2);
	}

#undef SET
}

SEC("uprobe.multi//proc/self/exe:uprobe_multi_func_*")
int test_uprobe(struct pt_regs *ctx)
{
	uprobe_multi_check(ctx, false);
	return 0;
}

SEC("uretprobe.multi//proc/self/exe:uprobe_multi_func_*")
int test_uretprobe(struct pt_regs *ctx)
{
	uprobe_multi_check(ctx, true);
	return 0;
}
