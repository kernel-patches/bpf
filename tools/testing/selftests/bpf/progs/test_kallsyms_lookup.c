// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Google LLC. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

extern const void schedule __ksym;

#define SYMBOL_NAME_LEN			10
char name[SYMBOL_NAME_LEN];
char name_invalid[SYMBOL_NAME_LEN];

#define SYMBOL_TRUNCATED_NAME_LEN	6
char name_truncated[SYMBOL_TRUNCATED_NAME_LEN];

#define MODULE_NAME_LEN			64
char module_name[MODULE_NAME_LEN];

long schedule_ret;
long sched_ret;
long invalid_ret;

SEC("raw_tp/sys_enter")
int handler(const void *ctx)
{
	schedule_ret = bpf_kallsyms_lookup((__u64)&schedule,
					   name, SYMBOL_NAME_LEN,
					   module_name, MODULE_NAME_LEN);
	invalid_ret = bpf_kallsyms_lookup(0,
					  name_invalid, SYMBOL_NAME_LEN,
					  module_name, MODULE_NAME_LEN);
	sched_ret = bpf_kallsyms_lookup((__u64)&schedule, name_truncated,
					SYMBOL_TRUNCATED_NAME_LEN,
					module_name, MODULE_NAME_LEN);
	return 0;
}

char _license[] SEC("license") = "GPL";
