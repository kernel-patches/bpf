// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 CrowdStrike */
/* Test module for duplicate kprobe symbol handling */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

/* Duplicate symbol to test kprobe attachment with duplicate symbols.
 * This creates a duplicate of the syscall wrapper used in attach_probe tests.
 * The libbpf fix should handle this by preferring the vmlinux symbol.
 * This function should NEVER be called - kprobes should attach to vmlinux version.
 */
#ifdef __x86_64__
int __x64_sys_nanosleep(void);
noinline int __x64_sys_nanosleep(void)
#elif defined(__s390x__)
int __s390x_sys_nanosleep(void);
noinline int __s390x_sys_nanosleep(void)
#elif defined(__aarch64__)
int __arm64_sys_nanosleep(void);
noinline int __arm64_sys_nanosleep(void)
#elif defined(__riscv)
int __riscv_sys_nanosleep(void);
noinline int __riscv_sys_nanosleep(void)
#else
int sys_nanosleep(void);
noinline int sys_nanosleep(void)
#endif
{
	WARN_ONCE(1, "bpf_testmod_dup_sym: dummy nanosleep symbol called - this should never execute!\n");
	return -EINVAL;
}

static int __init bpf_testmod_dup_sym_init(void)
{
	pr_info("bpf_testmod_dup_sym: loaded (duplicate symbol test module)\n");
	return 0;
}

static void __exit bpf_testmod_dup_sym_exit(void)
{
	pr_info("bpf_testmod_dup_sym: unloaded\n");
}

module_init(bpf_testmod_dup_sym_init);
module_exit(bpf_testmod_dup_sym_exit);

MODULE_AUTHOR("Andrey Grodzovsky");
MODULE_DESCRIPTION("BPF selftest duplicate symbol module");
MODULE_LICENSE("GPL");
