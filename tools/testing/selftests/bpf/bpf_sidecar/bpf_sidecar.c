// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
#include <linux/error-injection.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/tracepoint.h>
#include "bpf_sidecar.h"

#define CREATE_TRACE_POINTS
#include "bpf_sidecar-events.h"

static noinline ssize_t
bpf_sidecar_test_read(struct file *file, struct kobject *kobj,
		      struct bin_attribute *bin_attr,
		      char *buf, loff_t off, size_t len)
{
	struct bpf_sidecar_test_read_ctx ctx = {
		.buf = buf,
		.off = off,
		.len = len,
	};

	trace_bpf_sidecar_test_read(current, &ctx);

	return -EIO; /* always fail */
}
ALLOW_ERROR_INJECTION(bpf_sidecar_test_read, ERRNO);

static struct bin_attribute bin_attr_bpf_sidecar_file __ro_after_init = {
	.attr = { .name = "bpf_sidecar", .mode = 0444, },
	.read = bpf_sidecar_test_read,
};

static int bpf_sidecar_init(void)
{
	return sysfs_create_bin_file(kernel_kobj, &bin_attr_bpf_sidecar_file);
}

static void bpf_sidecar_exit(void)
{
	return sysfs_remove_bin_file(kernel_kobj, &bin_attr_bpf_sidecar_file);
}

module_init(bpf_sidecar_init);
module_exit(bpf_sidecar_exit);

MODULE_AUTHOR("Andrii Nakryiko");
MODULE_DESCRIPTION("BPF selftests sidecar module");
MODULE_LICENSE("Dual BSD/GPL");

