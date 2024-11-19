// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/xattr.h>

__bpf_kfunc_start_defs();

/**
 * bpf_get_task_exe_file - get a reference on the exe_file struct file member of
 *                         the mm_struct that is nested within the supplied
 *                         task_struct
 * @task: task_struct of which the nested mm_struct exe_file member to get a
 * reference on
 *
 * Get a reference on the exe_file struct file member field of the mm_struct
 * nested within the supplied *task*. The referenced file pointer acquired by
 * this BPF kfunc must be released using bpf_put_file(). Failing to call
 * bpf_put_file() on the returned referenced struct file pointer that has been
 * acquired by this BPF kfunc will result in the BPF program being rejected by
 * the BPF verifier.
 *
 * Internally, this BPF kfunc leans on get_task_exe_file(), such that calling
 * bpf_get_task_exe_file() would be analogous to calling get_task_exe_file()
 * directly in kernel context.
 *
 * Return: A referenced struct file pointer to the exe_file member of the
 * mm_struct that is nested within the supplied *task*. On error, NULL is
 * returned.
 */
__bpf_kfunc struct file *bpf_get_task_exe_file(struct task_struct *task)
{
	return get_task_exe_file(task);
}

/**
 * bpf_put_file - put a reference on the supplied file
 * @file: file to put a reference on
 *
 * Put a reference on the supplied *file*. Only referenced file pointers may be
 * passed to this BPF kfunc. Attempting to pass an unreferenced file pointer, or
 * any other arbitrary pointer for that matter, will result in the BPF program
 * being rejected by the BPF verifier.
 */
__bpf_kfunc void bpf_put_file(struct file *file)
{
	fput(file);
}

/**
 * bpf_path_d_path - resolve the pathname for the supplied path
 * @path: path to resolve the pathname for
 * @buf: buffer to return the resolved pathname in
 * @buf__sz: length of the supplied buffer
 *
 * Resolve the pathname for the supplied *path* and store it in *buf*. This BPF
 * kfunc is the safer variant of the legacy bpf_d_path() helper and should be
 * used in place of bpf_d_path() whenever possible. It enforces KF_TRUSTED_ARGS
 * semantics, meaning that the supplied *path* must itself hold a valid
 * reference, or else the BPF program will be outright rejected by the BPF
 * verifier.
 *
 * Return: A positive integer corresponding to the length of the resolved
 * pathname in *buf*, including the NUL termination character. On error, a
 * negative integer is returned.
 */
__bpf_kfunc int bpf_path_d_path(struct path *path, char *buf, size_t buf__sz)
{
	int len;
	char *ret;

	if (!buf__sz)
		return -EINVAL;

	ret = d_path(path, buf, buf__sz);
	if (IS_ERR(ret))
		return PTR_ERR(ret);

	len = buf + buf__sz - ret;
	memmove(buf, ret, len);
	return len;
}

/**
 * bpf_get_dentry_xattr - get xattr of a dentry
 * @dentry: dentry to get xattr from
 * @name__str: name of the xattr
 * @value_p: output buffer of the xattr value
 *
 * Get xattr *name__str* of *dentry* and store the output in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefix "user." is allowed.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_get_dentry_xattr(struct dentry *dentry, const char *name__str,
				     struct bpf_dynptr *value_p)
{
	struct bpf_dynptr_kern *value_ptr = (struct bpf_dynptr_kern *)value_p;
	struct inode *inode = d_inode(dentry);
	u32 value_len;
	void *value;
	int ret;

	if (WARN_ON(!inode))
		return -EINVAL;

	if (strncmp(name__str, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
		return -EPERM;

	value_len = __bpf_dynptr_size(value_ptr);
	value = __bpf_dynptr_data_rw(value_ptr, value_len);
	if (!value)
		return -EINVAL;

	ret = inode_permission(&nop_mnt_idmap, inode, MAY_READ);
	if (ret)
		return ret;
	return __vfs_getxattr(dentry, inode, name__str, value, value_len);
}

/**
 * bpf_get_file_xattr - get xattr of a file
 * @file: file to get xattr from
 * @name__str: name of the xattr
 * @value_p: output buffer of the xattr value
 *
 * Get xattr *name__str* of *file* and store the output in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefix "user." is allowed.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_get_file_xattr(struct file *file, const char *name__str,
				   struct bpf_dynptr *value_p)
{
	struct dentry *dentry;

	dentry = file_dentry(file);
	return bpf_get_dentry_xattr(dentry, name__str, value_p);
}

/**
 * bpf_fget_task() - Get a pointer to the struct file corresponding to
 * the task file descriptor
 *
 * Note that this function acquires a reference to struct file.
 *
 * @task: the specified struct task_struct
 * @fd: the file descriptor
 *
 * @returns the corresponding struct file pointer if found,
 * otherwise returns NULL
 */
__bpf_kfunc struct file *bpf_fget_task(struct task_struct *task, unsigned int fd)
{
	struct file *file;

	file = fget_task(task, fd);
	return file;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_fs_kfunc_set_ids)
BTF_ID_FLAGS(func, bpf_get_task_exe_file,
	     KF_ACQUIRE | KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_put_file, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_path_d_path, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_get_dentry_xattr, KF_SLEEPABLE | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_get_file_xattr, KF_SLEEPABLE | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_fget_task, KF_ACQUIRE | KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_KFUNCS_END(bpf_fs_kfunc_set_ids)

static const struct btf_kfunc_id_set bpf_fs_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_fs_kfunc_set_ids,
};

static int __init bpf_fs_kfuncs_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &bpf_fs_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_fs_kfunc_set);
	return ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &bpf_fs_kfunc_set);
}

late_initcall(bpf_fs_kfuncs_init);
