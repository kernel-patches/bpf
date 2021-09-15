// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
#include <linux/error-injection.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/percpu-defs.h>
#include <linux/sysfs.h>
#include <linux/tracepoint.h>
#include <linux/string.h>
#include <linux/bpf_dummy_ops.h>
#include "bpf_testmod.h"

#define CREATE_TRACE_POINTS
#include "bpf_testmod-events.h"

typedef int (*dummy_ops_test_fn)(struct bpf_dummy_ops *ops,
				 const char *buf, size_t cnt);
struct dummy_ops_test {
	const char *name;
	dummy_ops_test_fn fn;
};

static struct kobject *bpf_test_kobj;

DEFINE_PER_CPU(int, bpf_testmod_ksym_percpu) = 123;

noinline int bpf_testmod_loop_test(int n)
{
	int i, sum = 0;

	/* the primary goal of this test is to test LBR. Create a lot of
	 * branches in the function, so we can catch it easily.
	 */
	for (i = 0; i < n; i++)
		sum += i;
	return sum;
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

	/* This is always true. Use the check to make sure the compiler
	 * doesn't remove bpf_testmod_loop_test.
	 */
	if (bpf_testmod_loop_test(101) > 100)
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

static int dummy_ops_chk_ret(struct bpf_dummy_ops *ops,
			     const char *buf, size_t cnt)
{
	int exp;
	int err;

	if (cnt <= 1)
		return -EINVAL;

	if (kstrtoint(buf + 1, 0, &exp))
		return -EINVAL;

	err = ops->init(NULL);
	if (err != exp)
		return -EINVAL;

	return 0;
}

static int dummy_ops_chk_ret_by_ptr(struct bpf_dummy_ops *ops,
				    const char *buf, size_t cnt)
{
	int exp;
	int err;
	struct bpf_dummy_ops_state state;

	if (cnt <= 1)
		return -EINVAL;

	if (kstrtoint(buf + 1, 0, &exp))
		return -EINVAL;

	memset(&state, 0, sizeof(state));
	err = ops->init(&state);
	if (err || state.val != exp)
		return -EINVAL;

	return 0;
}

static const struct dummy_ops_test tests[] = {
	{.name = "init_1", .fn = dummy_ops_chk_ret},
	{.name = "init_2", .fn = dummy_ops_chk_ret_by_ptr},
};

static const struct dummy_ops_test *dummy_ops_find_test(const char *buf,
							size_t cnt)
{
	char *c;
	size_t nm_len;
	unsigned int i;

	/*
	 * There may be test-specific string (e.g, return value)
	 * after the name of test. The delimiter is one space.
	 */
	c = strchr(buf, ' ');
	if (c)
		nm_len = c - buf;
	else
		nm_len = cnt;
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (nm_len >= strlen(tests[i].name) &&
		    !strncmp(buf, tests[i].name, nm_len))
			return &tests[i];
	}

	return NULL;
}

static ssize_t dummy_ops_ctl_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t cnt)
{
	struct bpf_dummy_ops *ops = bpf_get_dummy_ops();
	const struct dummy_ops_test *test;
	size_t nm_len;
	int err;

	/* dummy struct_ops is disabled, so always return success */
	if (!ops)
		return cnt;
	if (IS_ERR(ops))
		return PTR_ERR(ops);

	test = dummy_ops_find_test(buf, cnt);
	if (!test) {
		err = -EINVAL;
		goto out;
	}

	nm_len = strlen(test->name);
	err = test->fn(ops, buf + nm_len, cnt - nm_len);
	if (!err)
		err = cnt;
out:
	bpf_put_dummy_ops(ops);
	return err;
}

static struct kobj_attribute dummy_ops_ctl = __ATTR_WO(dummy_ops_ctl);

static struct attribute *bpf_test_attrs[] = {
	&dummy_ops_ctl.attr,
	NULL,
};

static const struct attribute_group bpf_test_attr_group = {
	.attrs = bpf_test_attrs,
};

static int bpf_testmod_init(void)
{
	int err;

	bpf_test_kobj = kobject_create_and_add("bpf_test", kernel_kobj);
	if (!bpf_test_kobj) {
		err = -ENOMEM;
		goto out;
	}

	err = sysfs_create_group(bpf_test_kobj, &bpf_test_attr_group);
	if (err)
		goto put_out;

	err = sysfs_create_bin_file(kernel_kobj, &bin_attr_bpf_testmod_file);
	if (err)
		goto rm_grp_out;

	return 0;

rm_grp_out:
	sysfs_remove_group(bpf_test_kobj, &bpf_test_attr_group);
put_out:
	kobject_put(bpf_test_kobj);
	bpf_test_kobj = NULL;
out:
	return err;
}

static void bpf_testmod_exit(void)
{
	sysfs_remove_bin_file(kernel_kobj, &bin_attr_bpf_testmod_file);
	sysfs_remove_group(bpf_test_kobj, &bpf_test_attr_group);
	kobject_put(bpf_test_kobj);
}

module_init(bpf_testmod_init);
module_exit(bpf_testmod_exit);

MODULE_AUTHOR("Andrii Nakryiko");
MODULE_DESCRIPTION("BPF selftests module");
MODULE_LICENSE("Dual BSD/GPL");
