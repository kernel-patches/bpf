// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

uint32_t tid = 0;
int num_unknown_tid = 0;
int num_known_tid = 0;
void *user_ptr = 0;

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	static char info[] = "    === END ===";

	if (task == (void *)0) {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	if (task->pid != (pid_t)tid)
		num_unknown_tid++;
	else
		num_known_tid++;

	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "    tgid      gid\n");

	BPF_SEQ_PRINTF(seq, "%8d %8d\n", task->tgid, task->pid);
	return 0;
}

int num_expected_failure_copy_from_user_task = 0;
int num_expected_failure_copy_from_user_task_str = 0;
int num_success_copy_from_user_task = 0;
int num_success_copy_from_user_task_str = 0;

SEC("iter.s/task")
int dump_task_sleepable(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	static const char info[] = "    === END ===";
	struct pt_regs *regs;
	char task_str1[10] = "aaaaaaaaaa";
	char task_str2[10], task_str3[10];
	char task_str4[20] = "aaaaaaaaaaaaaaaaaaaa";
	void *ptr;
	uint32_t user_data = 0;
	int ret;

	if (task == (void *)0) {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	/* Read an invalid pointer and ensure we get an error */
	ptr = NULL;
	ret = bpf_copy_from_user_task(&user_data, sizeof(uint32_t), ptr, task, 0);
	if (ret) {
		++num_expected_failure_copy_from_user_task;
	} else {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	/* Try to read the contents of the task's instruction pointer from the
	 * remote task's address space.
	 */
	regs = (struct pt_regs *)bpf_task_pt_regs(task);
	if (regs == (void *)0) {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}
	ptr = (void *)PT_REGS_IP(regs);

	ret = bpf_copy_from_user_task(&user_data, sizeof(uint32_t), ptr, task, 0);
	if (ret) {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	++num_success_copy_from_user_task;

	/* Read an invalid pointer and ensure we get an error */
	ptr = NULL;
	ret = bpf_copy_from_user_task_str((char *)task_str1, sizeof(task_str1), ptr, task, 0);
	if (ret >= 0 || task_str1[9] != 'a') {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	/* Read an invalid pointer and ensure we get error with pad zeros flag */
	ptr = NULL;
	ret = bpf_copy_from_user_task_str((char *)task_str1, sizeof(task_str1), ptr, task, BPF_F_PAD_ZEROS);
	if (ret >= 0 || task_str1[9] != '\0') {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	++num_expected_failure_copy_from_user_task_str;

	/* Same length as the string */
	ret = bpf_copy_from_user_task_str((char *)task_str2, 10, user_ptr, task, 0);
	if (bpf_strncmp(task_str2, 10, "test_data\0") != 0 || ret != 10) {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	/* Shorter length than the string */
	ret = bpf_copy_from_user_task_str((char *)task_str3, 9, user_ptr, task, 0);
	if (bpf_strncmp(task_str3, 9, "test_dat\0") != 0 || ret != 9) {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	/* Longer length than the string */
	ret = bpf_copy_from_user_task_str((char *)task_str4, 20, user_ptr, task, 0);
	if (bpf_strncmp(task_str4, 10, "test_data\0") != 0 || ret != 10 || task_str4[sizeof(task_str4) - 1] != 'a') {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	/* Longer length than the string with pad zeros flag */
	ret = bpf_copy_from_user_task_str((char *)task_str4, 20, user_ptr, task, BPF_F_PAD_ZEROS);
	if (bpf_strncmp(task_str4, 10, "test_data\0") != 0 || ret != 10 || task_str4[sizeof(task_str4) - 1] != '\0') {
		BPF_SEQ_PRINTF(seq, "%s\n", info);
		return 0;
	}

	++num_success_copy_from_user_task_str;

	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "    tgid      gid     data\n");

	BPF_SEQ_PRINTF(seq, "%8d %8d %8d\n", task->tgid, task->pid, user_data);
	return 0;
}
