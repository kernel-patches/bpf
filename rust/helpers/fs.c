// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2024 Google LLC.
 */

#include <linux/fs.h>

__rust_helper struct file *rust_helper_get_file(struct file *f)
{
	return get_file(f);
}

__rust_helper unsigned int rust_helper_iminor(const struct inode *inode)
{
	return iminor(inode);
}
