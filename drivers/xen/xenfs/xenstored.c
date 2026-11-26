// SPDX-License-Identifier: GPL-2.0
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/fs.h>

#include <xen/page.h>
#include <xen/xenbus.h>

#include "xenfs.h"

static ssize_t xsd_read(struct file *file, char __user *buf,
			    size_t size, loff_t *off)
{
	const char *str = (const char *)file->private_data;
	return simple_read_from_buffer(buf, size, off, str, strlen(str));
}

static int xsd_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static int xsd_kva_open(struct inode *inode, struct file *file)
{
	file->private_data = (void *)kasprintf(GFP_KERNEL, "0x%p",
					       xen_store_interface);
	if (!file->private_data)
		return -ENOMEM;
	return 0;
}

static int xsd_kva_mmap_prepare(struct vm_area_desc *desc)
{
	size_t size = vma_desc_size(desc);

	if ((size > PAGE_SIZE) || (desc->pgoff != 0))
		return -EINVAL;

	mmap_action_remap_full(desc, virt_to_pfn(xen_store_interface));
	desc->action.error_override = -EAGAIN;

	return 0;
}

const struct file_operations xsd_kva_file_ops = {
	.open = xsd_kva_open,
	.mmap_prepare = xsd_kva_mmap_prepare,
	.read = xsd_read,
	.release = xsd_release,
};

static int xsd_port_open(struct inode *inode, struct file *file)
{
	file->private_data = (void *)kasprintf(GFP_KERNEL, "%d",
					       xen_store_evtchn);
	if (!file->private_data)
		return -ENOMEM;
	return 0;
}

const struct file_operations xsd_port_file_ops = {
	.open = xsd_port_open,
	.read = xsd_read,
	.release = xsd_release,
};
