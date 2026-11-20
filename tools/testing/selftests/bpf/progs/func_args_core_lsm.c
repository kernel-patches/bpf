// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

int monitored_pid;

/* int file_ioctl(struct file *file, unsigned int cmd, unsigned long arg) */
struct file_ioctl_args {
	__bpf_func_args_marker;
	/* out of order */
	unsigned long arg;

	int ret __bpf_func_ret;
	struct file *file;
	/* added: no such parameter */
	unsigned long added;
	/* missing: cmd isn't described */
} __bpf_func_args;

__u64 s_arg, s_ino;
int s_ret = -1, s_ret_exists = -1, s_added_exists = -1, s_calls;

SEC("lsm/file_ioctl")
int ioctl_struct(struct file_ioctl_args *args)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	s_calls++;
	s_arg = args->arg;
	s_ino = args->file->f_inode->i_ino;
	s_ret = args->ret;
	s_ret_exists = bpf_core_field_exists(args->ret);
	s_added_exists = bpf_core_field_exists(args->added);
	return 0;
}

/* A hypothetical future kernel in which file_ioctl()'s file parameter
 * points to a renamed struct: both variants are described with flavors,
 * and only one of them can match in a given kernel.
 */
struct vfs_file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));

struct file_ioctl_variant_args {
	__bpf_func_args_marker;
	struct vfs_file *file___new;
	struct file *file;
} __bpf_func_args;

__u64 v_ino, vm_ino;
int v_new_exists = -1, v_old_exists = -1, vm_new_exists = -1, vm_old_exists = -1;

SEC("lsm/file_ioctl")
int ioctl_variants(struct file_ioctl_variant_args *args)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	v_new_exists = bpf_core_field_exists(args->file___new);
	v_old_exists = bpf_core_field_exists(args->file);
	if (bpf_core_field_exists(args->file___new))
		v_ino = args->file___new->f_inode->i_ino;
	else if (bpf_core_field_exists(args->file))
		v_ino = args->file->f_inode->i_ino;
	return 0;
}

SEC("lsm/file_ioctl")
int BPF_PROG_CORE(ioctl_macro_variants, struct vfs_file *, file___new,
		  struct file *, file)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	vm_new_exists = bpf_func_arg_exists(file___new);
	vm_old_exists = bpf_func_arg_exists(file);
	if (bpf_func_arg_exists(file___new))
		vm_ino = file___new->f_inode->i_ino;
	else if (bpf_func_arg_exists(file))
		vm_ino = file->f_inode->i_ino;
	return 0;
}

__u64 m_arg, m_cmd, m_added = -1;
int m_ret = -1, m_ret_exists = -1, m_added_exists = -1, m_calls;

SEC("lsm/file_ioctl")
int BPF_PROG_CORE(ioctl_macro, unsigned long, arg, __bpf_func_ret int, ret,
		  unsigned long, added, unsigned int, cmd)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	m_calls++;
	m_arg = arg;
	m_cmd = cmd;
	m_added = added;
	m_added_exists = bpf_func_arg_exists(added);
	m_ret = ret;
	m_ret_exists = bpf_func_arg_exists(ret);
	return 0;
}

/* The reverse: a program written for the hypothetical kernel, describing
 * file with the new type and the current one with a flavor, so that only
 * the flavored member matches.
 */
struct file_ioctl_old_variant_args {
	__bpf_func_args_marker;
	struct vfs_file *file;
	struct file *file___old;
} __bpf_func_args;

__u64 o_ino, om_ino;
int o_new_exists = -1, o_old_exists = -1, om_new_exists = -1, om_old_exists = -1;

SEC("lsm/file_ioctl")
int ioctl_old_variant(struct file_ioctl_old_variant_args *args)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	o_new_exists = bpf_core_field_exists(args->file);
	o_old_exists = bpf_core_field_exists(args->file___old);
	if (bpf_core_field_exists(args->file))
		o_ino = args->file->f_inode->i_ino;
	else if (bpf_core_field_exists(args->file___old))
		o_ino = args->file___old->f_inode->i_ino;
	return 0;
}

SEC("lsm/file_ioctl")
int BPF_PROG_CORE(ioctl_macro_old_variant, struct vfs_file *, file,
		  struct file *, file___old)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	om_new_exists = bpf_func_arg_exists(file);
	om_old_exists = bpf_func_arg_exists(file___old);
	if (bpf_func_arg_exists(file))
		om_ino = file->f_inode->i_ino;
	else if (bpf_func_arg_exists(file___old))
		om_ino = file___old->f_inode->i_ino;
	return 0;
}
