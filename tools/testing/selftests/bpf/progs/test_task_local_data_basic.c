#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "task_local_data.h"

struct task_local_data_offsets {
	short value1;
	short value2;
	short test_basic_value3;
	short test_basic_value4;
};

pid_t target_tid = 0;
int test_value1 = 0;
struct test_struct test_value2;
int test_value3 = 0;
struct test_struct test_value4;

SEC("tp/syscalls/sys_enter_getuid")
int prog_init(void *ctx)
{
	struct bpf_task_local_data tld;
	struct task_struct *task;
	int err;

	task = bpf_get_current_task_btf();
	if (task->pid != target_tid)
		return 0;

	err = bpf_tld_init(task, &tld);
	if (err)
		return 0;

	bpf_tld_init_var(&tld, value1);
	bpf_tld_init_var(&tld, value2);
	bpf_tld_init_var(&tld, test_basic_value3);
	bpf_tld_init_var(&tld, test_basic_value4);

	return 0;
}

SEC("tp/syscalls/sys_enter_gettid")
int prog_main(void *ctx)
{
	struct bpf_task_local_data tld;
	struct test_struct *struct_p;
	struct task_struct *task;
	int err, *int_p;

	task = bpf_get_current_task_btf();
	if (task->pid != target_tid)
		return 0;

	err = bpf_tld_init(task, &tld);
	if (err)
		return 0;

	int_p = bpf_tld_lookup(&tld, value1, sizeof(int));
	if (int_p)
		test_value1 = *int_p;

	struct_p = bpf_tld_lookup(&tld, value2, sizeof(struct test_struct));
	if (struct_p)
		test_value2 = *struct_p;

	int_p = bpf_tld_lookup(&tld, test_basic_value3, sizeof(int));
	if (int_p)
		test_value3 = *int_p;

	struct_p = bpf_tld_lookup(&tld, test_basic_value4, sizeof(struct test_struct));
	if (struct_p)
		test_value4 = *struct_p;

	return 0;
}

char _license[] SEC("license") = "GPL";

