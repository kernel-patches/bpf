// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATH_LEN	256
#define TEST_FILES_NUM		2

pid_t monitor_pid = 0;

__u32 bpf_called_cnt = 0;
char bpf_paths_close[TEST_FILES_NUM][MAX_PATH_LEN] = {0};

SEC("kprobe/filp_close")
int test_bpf_file_to_path(struct pt_regs *regs)
{
	void *file = NULL;
	pid_t cur_pid = bpf_get_current_pid_tgid() >> 32;

	if (cur_pid != monitor_pid)
		return 0;

	if (bpf_called_cnt >= TEST_FILES_NUM)
		return 0;

	file = (void *)PT_REGS_PARM1(regs);
	bpf_file_d_path(file, bpf_paths_close[bpf_called_cnt++], MAX_PATH_LEN);

	return 0;
}

char _license[] SEC("license") = "GPL";
