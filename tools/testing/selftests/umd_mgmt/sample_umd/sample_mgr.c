// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the UMD Manager.
 */
#include <linux/module.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/usermode_driver_mgmt.h>

#include "msgfmt.h"

struct umd_mgmt sample_mgmt_ops;
EXPORT_SYMBOL_GPL(sample_mgmt_ops);

struct dentry *sample_umd_dentry;

static int sample_write_common(u32 offset, bool test)
{
	struct sample_request *req;
	struct sample_reply *reply;
	int ret;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out;
	}

	reply = kzalloc(sizeof(*reply), GFP_KERNEL);
	if (!reply) {
		ret = -ENOMEM;
		goto out;
	}

	req->offset = offset;

	if (test)
		/* Lock is already taken. */
		ret = umd_send_recv(&sample_mgmt_ops.info, req, sizeof(*req),
				    reply, sizeof(*reply));
	else
		ret = umd_mgmt_send_recv(&sample_mgmt_ops, req, sizeof(*req),
					 reply, sizeof(*reply));
	if (ret < 0)
		goto out;

	if (reply->data[req->offset] != 1) {
		ret = -EINVAL;
		goto out;
	}
out:
	kfree(req);
	kfree(reply);

	return ret;
}

static ssize_t sample_umd_write(struct file *file, const char __user *buf,
				size_t datalen, loff_t *ppos)
{
	char offset_str[8];
	u32 offset;
	int ret;

	if (datalen >= sizeof(offset_str))
		return -EINVAL;

	ret = copy_from_user(offset_str, buf, datalen);
	if (ret < 0)
		return ret;

	offset_str[datalen] = '\0';

	ret = kstrtou32(offset_str, 10, &offset);
	if (ret < 0)
		return ret;

	if (offset >= sizeof(((struct sample_reply *)0)->data))
		return -EINVAL;

	ret = sample_write_common(offset, false);
	if (ret < 0)
		return ret;

	return datalen;
}

static const struct file_operations sample_umd_file_ops = {
	.write = sample_umd_write,
};

static int sample_post_start_umh(struct umd_mgmt *mgmt)
{
	return sample_write_common(0, true);
}

static int __init load_umh(void)
{
	mutex_init(&sample_mgmt_ops.lock);
	sample_mgmt_ops.info.tgid = NULL;
	sample_mgmt_ops.info.driver_name = "sample_umh";
	sample_mgmt_ops.post_start = sample_post_start_umh;
	sample_mgmt_ops.kmod = "sample_loader_kmod";
	sample_mgmt_ops.kmod_loaded = false;

	sample_umd_dentry = securityfs_create_file("sample_umd", 0200, NULL,
						   NULL, &sample_umd_file_ops);
	if (IS_ERR(sample_umd_dentry))
		return PTR_ERR(sample_umd_dentry);

	return 0;
}

static void __exit fini_umh(void)
{
	securityfs_remove(sample_umd_dentry);
}
module_init(load_umh);
module_exit(fini_umh);
MODULE_LICENSE("GPL");
