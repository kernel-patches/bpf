// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>

#include "task_local_data.bpf.h"

struct tld_keys {
	tld_key_t value1;
	tld_key_t value2;
	tld_key_t value_not_exist;
};

struct test_struct {
	unsigned long a;
	unsigned long b;
	unsigned long c;
	unsigned long d;
};

int test_value1;
struct test_struct test_value2;

SEC("syscall")
int task_init(void *ctx)
{
	struct tld_object tld_obj;
	struct task_struct *task;
	int err;

	task = bpf_get_current_task_btf();
	err = tld_object_init(task, &tld_obj);
	if (err)
		return 1;

	if (!tld_fetch_key(&tld_obj, "value1", value1))
		return 2;

	if (!tld_fetch_key(&tld_obj, "value2", value2))
		return 3;

	if (tld_fetch_key(&tld_obj, "value_not_exist", value_not_exist))
		return 6;

	return 0;
}

SEC("syscall")
int task_main(void *ctx)
{
	struct tld_object tld_obj;
	struct test_struct *struct_p;
	struct task_struct *task;
	int err, *int_p;

	task = bpf_get_current_task_btf();
	err = tld_object_init(task, &tld_obj);
	if (err)
		return 1;

	int_p = tld_get_data(&tld_obj, value1, sizeof(int));
	if (int_p)
		test_value1 = *int_p;
	else
		return 2;

	struct_p = tld_get_data(&tld_obj, value2, sizeof(struct test_struct));
	if (struct_p)
		test_value2 = *struct_p;
	else
		return 3;

	int_p = tld_get_data(&tld_obj, value_not_exist, sizeof(int));
	if (int_p)
		return 4;

	return 0;
}

char _license[] SEC("license") = "GPL";

