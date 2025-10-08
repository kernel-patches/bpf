// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025, Oracle and/or its affiliates. */
/*
 * Provide extra kernel BTF information for use by BPF tools.
 *
 * Can be built as a module to support cases where vmlinux .BTF.extra
 * section size in the vmlinux image is too much.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

static int __init btf_extra_init(void)
{
	return 0;
}
subsys_initcall(btf_extra_init);

static void __exit btf_extra_exit(void)
{
}
module_exit(btf_extra_exit);

MODULE_DESCRIPTION("Extra BTF information");
MODULE_LICENSE("GPL v2");
