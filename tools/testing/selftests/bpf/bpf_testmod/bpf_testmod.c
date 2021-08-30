// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
#include <linux/error-injection.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/percpu-defs.h>
#include <linux/sysfs.h>
#include <linux/tracepoint.h>
#include "bpf_testmod.h"

#define CREATE_TRACE_POINTS
#include "bpf_testmod-events.h"

DEFINE_PER_CPU(int, bpf_testmod_ksym_percpu) = 123;

noinline void
bpf_testmod_test_mod_kfunc(int i)
{
	pr_info("mod kfunc i=%d\n", i);
}

noinline ssize_t
bpf_testmod_test_read(struct file *file, struct kobject *kobj,
		      struct bin_attribute *bin_attr,
		      char *buf, loff_t off, size_t len)
{
	struct bpf_testmod_test_read_ctx ctx = {
		.buf = buf,
		.off = off,
		.len = len,
	};

	trace_bpf_testmod_test_read(current, &ctx);

	return -EIO; /* always fail */
}
EXPORT_SYMBOL(bpf_testmod_test_read);
ALLOW_ERROR_INJECTION(bpf_testmod_test_read, ERRNO);

noinline ssize_t
bpf_testmod_test_write(struct file *file, struct kobject *kobj,
		      struct bin_attribute *bin_attr,
		      char *buf, loff_t off, size_t len)
{
	struct bpf_testmod_test_write_ctx ctx = {
		.buf = buf,
		.off = off,
		.len = len,
	};

	trace_bpf_testmod_test_write_bare(current, &ctx);

	return -EIO; /* always fail */
}
EXPORT_SYMBOL(bpf_testmod_test_write);
ALLOW_ERROR_INJECTION(bpf_testmod_test_write, ERRNO);

static struct bin_attribute bin_attr_bpf_testmod_file __ro_after_init = {
	.attr = { .name = "bpf_testmod", .mode = 0666, },
	.read = bpf_testmod_test_read,
	.write = bpf_testmod_test_write,
};

BTF_SET_START(bpf_testmod_kfunc_ids)
BTF_ID(func, bpf_testmod_test_mod_kfunc)
BTF_SET_END(bpf_testmod_kfunc_ids)

static DEFINE_KFUNC_BTF_SET(&bpf_testmod_kfunc_ids, bpf_testmod_kfunc_btf_set);

static int bpf_testmod_init(void)
{
	int ret;

	ret = sysfs_create_bin_file(kernel_kobj, &bin_attr_bpf_testmod_file);
	if (ret)
		return ret;
	register_raw_tp_kfunc_btf_set(&bpf_testmod_kfunc_btf_set);
	return 0;
}

static void bpf_testmod_exit(void)
{
	unregister_raw_tp_kfunc_btf_set(&bpf_testmod_kfunc_btf_set);
	return sysfs_remove_bin_file(kernel_kobj, &bin_attr_bpf_testmod_file);
}

module_init(bpf_testmod_init);
module_exit(bpf_testmod_exit);

MODULE_AUTHOR("Andrii Nakryiko");
MODULE_DESCRIPTION("BPF selftests module");
MODULE_LICENSE("Dual BSD/GPL");

