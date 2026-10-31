// SPDX-License-Identifier: GPL-2.0
/*
 * Provide kernel BTF information for introspection and use by eBPF tools.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/btf.h>
#include <linux/zstd.h>

#ifdef CONFIG_DEBUG_INFO_BTF_LAZY
/* See scripts/gen-btf.sh, gen_btf_o() for details */
extern char __start_BTF_zst[];
extern char __stop_BTF_zst[];

static DEFINE_MUTEX(btf_vmlinux_data_lock);
static void *btf_vmlinux_raw;
static u32 btf_vmlinux_raw_size;
static bool btf_vmlinux_broken;
/* Compressed BTF: init data until btf_vmlinux_keep_zst(), freed once decompressed */
static void *btf_zst = __start_BTF_zst;

static u32 btf_vmlinux_size(void)
{
	zstd_frame_header hdr;

	guard(mutex)(&btf_vmlinux_data_lock);
	if (!btf_vmlinux_raw_size && btf_zst &&
	    !zstd_get_frame_header(&hdr, btf_zst, __stop_BTF_zst - __start_BTF_zst) &&
	    hdr.frameContentSize < U32_MAX)
		btf_vmlinux_raw_size = hdr.frameContentSize;
	return btf_vmlinux_raw_size;
}

static void btf_vmlinux_drop_zst(void)
{
	if (btf_zst != __start_BTF_zst)
		vfree(btf_zst);
	btf_zst = NULL;
}

/*
 * The raw vmlinux BTF, decompressed on first use and never freed, or
 * ERR_PTR(-ENOMEM) if that cannot be done (now: memory; for good: no copy of
 * the compressed BTF), or ERR_PTR(-EINVAL) if it is broken.
 */
void *btf_vmlinux_data(u32 *size)
{
	size_t ret, ws_size = zstd_dctx_workspace_bound();
	void *raw, *ws;

	/* Pairs with smp_store_release() below */
	raw = smp_load_acquire(&btf_vmlinux_raw);
	if (raw) {
		*size = btf_vmlinux_raw_size;
		return raw;
	}

	*size = btf_vmlinux_size();
	guard(mutex)(&btf_vmlinux_data_lock);
	if (btf_vmlinux_raw)
		return btf_vmlinux_raw;
	if (!btf_zst)
		return ERR_PTR(btf_vmlinux_broken ? -EINVAL : -ENOMEM);
	if (!*size) {
		pr_err("BTF: no size in the compressed vmlinux BTF\n");
		btf_vmlinux_broken = true;
		btf_vmlinux_drop_zst();
		return ERR_PTR(-EINVAL);
	}
	/* vmalloc_user(): btf_sysfs_vmlinux_mmap() maps it to user space */
	raw = vmalloc_user(*size);
	ws = kvmalloc(ws_size, GFP_KERNEL);
	if (raw && ws) {
		ret = zstd_decompress_dctx(zstd_init_dctx(ws, ws_size), raw, *size,
					   btf_zst, __stop_BTF_zst - __start_BTF_zst);
		if (!zstd_is_error(ret) && ret == *size) {
			/* Pairs with smp_load_acquire() above */
			smp_store_release(&btf_vmlinux_raw, raw);
		} else {
			pr_err("BTF: cannot decompress the vmlinux BTF: %s\n",
			       zstd_is_error(ret) ? zstd_get_error_name(ret) : "size mismatch");
			btf_vmlinux_broken = true;
		}
		btf_vmlinux_drop_zst();
	}
	kvfree(ws);
	if (btf_vmlinux_raw)
		return btf_vmlinux_raw;
	vfree(raw);
	return ERR_PTR(btf_vmlinux_broken ? -EINVAL : -ENOMEM);
}

/* Keep a copy of the compressed BTF before init memory is freed */
static int __init btf_vmlinux_keep_zst(void)
{
	size_t size = __stop_BTF_zst - __start_BTF_zst;

	guard(mutex)(&btf_vmlinux_data_lock);
	if (btf_zst) {
		/* vmalloc(): kmalloc() would round up to a power of 2 */
		btf_zst = vmalloc(size);
		if (btf_zst)
			memcpy(btf_zst, __start_BTF_zst, size);
		else
			pr_err("BTF: out of memory, vmlinux BTF unavailable\n");
	}
	return 0;
}
late_initcall_sync(btf_vmlinux_keep_zst);
#else
/* See scripts/link-vmlinux.sh, gen_btf() func for details */
extern char __start_BTF[];
extern char __stop_BTF[];

static u32 btf_vmlinux_size(void)
{
	return __stop_BTF - __start_BTF;
}

void *btf_vmlinux_data(u32 *size)
{
	*size = btf_vmlinux_size();
	return __start_BTF;
}
#endif

#ifdef CONFIG_SYSFS
static int btf_sysfs_mmap_check(void *data, size_t size, struct vm_area_struct *vma)
{
	unsigned long pages = PAGE_ALIGN(size) >> PAGE_SHIFT;
	size_t vm_size = vma->vm_end - vma->vm_start;

	if (!data || !PAGE_ALIGNED((unsigned long)data))
		return -EINVAL;

	if (vma->vm_pgoff)
		return -EINVAL;

	if (vma->vm_flags & (VM_WRITE | VM_EXEC | VM_MAYSHARE))
		return -EACCES;

	if ((vm_size >> PAGE_SHIFT) > pages)
		return -EINVAL;

	vm_flags_mod(vma, VM_DONTDUMP, VM_MAYEXEC | VM_MAYWRITE);
	return 0;
}

static int btf_sysfs_mmap_image(struct file *filp, struct kobject *kobj,
				const struct bin_attribute *attr,
				struct vm_area_struct *vma)
{
	void *data = READ_ONCE(attr->private);
	phys_addr_t addr;
	unsigned long pfn;
	size_t vm_size = vma->vm_end - vma->vm_start;
	int err;

	err = btf_sysfs_mmap_check(data, attr->size, vma);
	if (err)
		return err;

	/* Kernel image addresses can lie inside the vmalloc range on arm64. */
	addr = __pa_symbol(data);
	pfn = addr >> PAGE_SHIFT;
	if (pfn + (PAGE_ALIGN(attr->size) >> PAGE_SHIFT) < pfn)
		return -EINVAL;

	return remap_pfn_range(vma, vma->vm_start, pfn, vm_size, vma->vm_page_prot);
}

#ifdef CONFIG_DEBUG_INFO_BTF_LAZY
/* Reading or mapping the file decompresses the BTF but does not parse it */
static int btf_sysfs_vmlinux_mmap(struct file *filp, struct kobject *kobj,
				  const struct bin_attribute *attr,
				  struct vm_area_struct *vma)
{
	void *data;
	u32 size;
	int err;

	data = btf_vmlinux_data(&size);
	if (IS_ERR(data))
		return PTR_ERR(data);

	err = btf_sysfs_mmap_check(data, attr->size, vma);
	if (err)
		return err;

	return remap_vmalloc_range(vma, data, 0);
}

static ssize_t btf_sysfs_vmlinux_read(struct file *filp, struct kobject *kobj,
				      const struct bin_attribute *attr, char *buf,
				      loff_t off, size_t count)
{
	void *data;
	u32 size;

	data = btf_vmlinux_data(&size);
	if (IS_ERR(data))
		return PTR_ERR(data);

	return memory_read_from_buffer(buf, count, &off, data, size);
}
#else
#define btf_sysfs_vmlinux_read	sysfs_bin_attr_simple_read
#define btf_sysfs_vmlinux_mmap	btf_sysfs_mmap_image
#endif

static struct bin_attribute bin_attr_btf_vmlinux __ro_after_init = {
	.attr = { .name = "vmlinux", .mode = 0444, },
	.read = btf_sysfs_vmlinux_read,
	.mmap = btf_sysfs_vmlinux_mmap,
};

struct kobject *btf_kobj;

struct btf_sysfs_entry {
	struct bin_attribute attr;
	char *module_name;
};

static void *btf_sysfs_lazy_data(const struct bin_attribute *attr)
{
	struct btf_sysfs_entry *entry = container_of(attr, struct btf_sysfs_entry, attr);
	void *data;

	data = smp_load_acquire(&attr->private);
	if (!data) {
		request_module("%s", entry->module_name);
		data = smp_load_acquire(&attr->private);
	}
	return data;
}

static ssize_t btf_sysfs_read_lazy(struct file *filp, struct kobject *kobj,
				   const struct bin_attribute *attr, char *buf,
				   loff_t off, size_t count)
{
	void *data = btf_sysfs_lazy_data(attr);

	if (!data)
		return -ENODEV;

	return memory_read_from_buffer(buf, count, &off, data, attr->size);
}

static int btf_sysfs_mmap_lazy(struct file *filp, struct kobject *kobj,
			       const struct bin_attribute *attr,
			       struct vm_area_struct *vma)
{
	void *data = btf_sysfs_lazy_data(attr);
	int err;

	if (!data)
		return -ENODEV;

	err = btf_sysfs_mmap_check(data, attr->size, vma);
	if (err)
		return err;

	return remap_vmalloc_range(vma, data, 0);
}

struct bin_attribute *sysfs_btf_add(const char *name, void *data, size_t data_size,
				    bool mmap, const char *lazy_module_name)
{
	struct btf_sysfs_entry *entry;
	struct bin_attribute *attr;
	int err;

	entry = kzalloc_obj(*entry);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	attr = &entry->attr;
	sysfs_bin_attr_init(attr);
	attr->attr.mode = 0444;
	attr->size = data_size;
	attr->private = data;
	attr->read = lazy_module_name ? btf_sysfs_read_lazy : sysfs_bin_attr_simple_read;
	if (mmap)
		attr->mmap = lazy_module_name ? btf_sysfs_mmap_lazy : btf_sysfs_mmap_image;
	attr->attr.name = kstrdup(name, GFP_KERNEL);
	if (!attr->attr.name) {
		err = -ENOMEM;
		goto err_free;
	}
	if (lazy_module_name) {
		entry->module_name = kstrdup(lazy_module_name, GFP_KERNEL);
		if (!entry->module_name) {
			err = -ENOMEM;
			goto err_free;
		}
	}

	err = sysfs_create_bin_file(btf_kobj, attr);
	if (err) {
		pr_warn("failed to register [%s] BTF in sysfs: %d\n", name, err);
		goto err_free;
	}

	return attr;

err_free:
	kfree(entry->module_name);
	kfree(attr->attr.name);
	kfree(entry);
	return ERR_PTR(err);
}

bool sysfs_btf_update(struct bin_attribute *attr, void *data)
{
	return attr && !cmpxchg(&attr->private, NULL, data);
}

void sysfs_btf_remove(struct bin_attribute *attr)
{
	struct btf_sysfs_entry *entry = container_of(attr, struct btf_sysfs_entry, attr);

	sysfs_remove_bin_file(btf_kobj, attr);
	kfree(entry->module_name);
	kfree(attr->attr.name);
	kfree(entry);
}

static int __init btf_vmlinux_init(void)
{
	u32 size;

	/* with CONFIG_DEBUG_INFO_BTF_LAZY the read and mmap handlers get it */
	if (!IS_ENABLED(CONFIG_DEBUG_INFO_BTF_LAZY))
		bin_attr_btf_vmlinux.private = btf_vmlinux_data(&size);
	bin_attr_btf_vmlinux.size = btf_vmlinux_size();

	if (bin_attr_btf_vmlinux.size == 0)
		return 0;

	btf_kobj = kobject_create_and_add("btf", kernel_kobj);
	if (!btf_kobj)
		return -ENOMEM;

	return sysfs_create_bin_file(btf_kobj, &bin_attr_btf_vmlinux);
}

subsys_initcall(btf_vmlinux_init);
#endif /* CONFIG_SYSFS */
