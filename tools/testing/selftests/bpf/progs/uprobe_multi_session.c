// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

__u64 uprobe_multi_func_1_addr = 0;
__u64 uprobe_multi_func_2_addr = 0;
__u64 uprobe_multi_func_3_addr = 0;

__u64 uprobe_session_result[3];

int pid = 0;

static int uprobe_multi_check(void *ctx, bool is_return)
{
	const __u64 funcs[] = {
		uprobe_multi_func_1_addr,
		uprobe_multi_func_2_addr,
		uprobe_multi_func_3_addr,
	};
	unsigned int i;
	__u64 addr;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 1;

	addr = bpf_get_func_ip(ctx);

	for (i = 0; i < ARRAY_SIZE(funcs); i++) {
		if (funcs[i] == addr) {
			uprobe_session_result[i]++;
			break;
                }
        }

	if ((addr == uprobe_multi_func_1_addr) ||
	    (addr == uprobe_multi_func_3_addr))
		return 1;

	return 0;
}

SEC("uprobe.session//proc/self/exe:uprobe_multi_func_*")
int uprobe(struct pt_regs *ctx)
{
	return uprobe_multi_check(ctx, bpf_session_is_return());
}
