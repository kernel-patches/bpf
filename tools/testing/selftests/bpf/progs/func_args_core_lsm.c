// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

int monitored_pid;

/* int file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
 *		     unsigned long prot)
 */
struct file_mprotect_args {
	__bpf_func_args_marker;
	/* out of order */
	unsigned long prot;

	int ret __bpf_func_ret;
	struct vm_area_struct *vma;
	/* added: no such parameter */
	unsigned long added;
	/* missing: reqprot isn't described */
} __bpf_func_args;

__u64 s_prot, s_vm_start, s_vm_end;
int s_ret = -1, s_ret_exists = -1, s_added_exists = -1, s_calls, s_supported = -1;

SEC("lsm/file_mprotect")
int mprotect_struct(struct file_mprotect_args *args)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	s_supported = bpf_func_args_supported(args);

	s_calls++;
	s_prot = args->prot;
	s_vm_start = args->vma->vm_start;
	s_vm_end = args->vma->vm_end;
	s_ret = args->ret;
	s_ret_exists = bpf_core_field_exists(args->ret);
	s_added_exists = bpf_core_field_exists(args->added);
	return 0;
}

/* A hypothetical future kernel in which file_mprotect()'s vma parameter
 * points to a renamed struct: both variants are described with flavors,
 * and only one of them can match in a given kernel.
 */
struct mm_area {
	unsigned long vm_start;
	unsigned long vm_end;
} __attribute__((preserve_access_index));

struct file_mprotect_variant_args {
	__bpf_func_args_marker;
	struct mm_area *vma___new;
	struct vm_area_struct *vma;
} __bpf_func_args;

__u64 v_vm_start, v_vm_end, vm_vm_start, vm_vm_end;
int v_new_exists = -1, v_old_exists = -1, vm_new_exists = -1, vm_old_exists = -1;

SEC("lsm/file_mprotect")
int mprotect_variants(struct file_mprotect_variant_args *args)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	v_new_exists = bpf_core_field_exists(args->vma___new);
	v_old_exists = bpf_core_field_exists(args->vma);
	if (bpf_core_field_exists(args->vma___new)) {
		v_vm_start = args->vma___new->vm_start;
		v_vm_end = args->vma___new->vm_end;
	} else if (bpf_core_field_exists(args->vma)) {
		v_vm_start = args->vma->vm_start;
		v_vm_end = args->vma->vm_end;
	}
	return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG_CORE(mprotect_macro_variants, struct mm_area *, vma___new,
		  struct vm_area_struct *, vma)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	vm_new_exists = bpf_func_arg_exists(vma___new);
	vm_old_exists = bpf_func_arg_exists(vma);
	if (bpf_func_arg_exists(vma___new)) {
		vm_vm_start = vma___new->vm_start;
		vm_vm_end = vma___new->vm_end;
	} else if (bpf_func_arg_exists(vma)) {
		vm_vm_start = vma->vm_start;
		vm_vm_end = vma->vm_end;
	}
	return 0;
}

__u64 m_prot, m_reqprot, m_added = -1;
int m_ret = -1, m_ret_exists = -1, m_added_exists = -1, m_calls, m_supported = -1;

SEC("lsm/file_mprotect")
int BPF_PROG_CORE(mprotect_macro, unsigned long, prot, __bpf_func_ret int, ret,
		  unsigned long, added, unsigned long, reqprot)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	m_supported = bpf_func_args_supported(ctx);

	m_calls++;
	m_prot = prot;
	m_reqprot = reqprot;
	m_added = added;
	m_added_exists = bpf_func_arg_exists(added);
	m_ret = ret;
	m_ret_exists = bpf_func_arg_exists(ret);
	return 0;
}

