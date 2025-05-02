// SPDX-License-Identifier: GPL-2.0
/*
 * Provide kernel BTF information for introspection and use by eBPF tools.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/mm.h>
#include <linux/io.h>

/* See scripts/link-vmlinux.sh, gen_btf() func for details */
extern char __start_BTF[];
extern char __stop_BTF[];

struct kobject *btf_kobj;

static int btf_vmlinux_mmap(struct file *filp, struct kobject *kobj,
			    const struct bin_attribute *attr,
			    struct vm_area_struct *vma)
{
	phys_addr_t start = virt_to_phys(__start_BTF);
	size_t btf_size = __stop_BTF - __start_BTF;
	size_t vm_size = vma->vm_end - vma->vm_start;
	unsigned long pfn = start >> PAGE_SHIFT;
	unsigned long pages = PAGE_ALIGN(btf_size) >> PAGE_SHIFT;

	if (kobj != btf_kobj)
		return -EINVAL;

	if (vma->vm_pgoff)
		return -EINVAL;

	if (vma->vm_flags & (VM_WRITE|VM_EXEC|VM_MAYSHARE))
		return -EACCES;

	if (pfn + pages < pfn)
		return -EINVAL;

	if (vm_size >> PAGE_SHIFT > pages)
		return -EINVAL;

	vm_flags_mod(vma, VM_DONTDUMP, VM_MAYEXEC|VM_MAYWRITE);
	return remap_pfn_range(vma, vma->vm_start, pfn, vm_size, vma->vm_page_prot);
}

static struct bin_attribute bin_attr_btf_vmlinux __ro_after_init = {
	.attr = { .name = "vmlinux", .mode = 0444, },
	.read_new = sysfs_bin_attr_simple_read,
	.mmap = btf_vmlinux_mmap,
};

static int __init btf_vmlinux_init(void)
{
	bin_attr_btf_vmlinux.private = __start_BTF;
	bin_attr_btf_vmlinux.size = __stop_BTF - __start_BTF;

	if (bin_attr_btf_vmlinux.size == 0)
		return 0;

	btf_kobj = kobject_create_and_add("btf", kernel_kobj);
	if (!btf_kobj)
		return -ENOMEM;

	return sysfs_create_bin_file(btf_kobj, &bin_attr_btf_vmlinux);
}

subsys_initcall(btf_vmlinux_init);
