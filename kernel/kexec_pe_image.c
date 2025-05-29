// SPDX-License-Identifier: GPL-2.0
/*
 * Kexec PE image loader

 * Copyright (C) 2025 Red Hat, Inc
 */

#define pr_fmt(fmt)	"kexec_file(Image): " fmt

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/kexec.h>
#include <linux/pe.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <asm/byteorder.h>
#include <asm/image.h>
#include <asm/memory.h>


static LIST_HEAD(phase_head);

struct parsed_phase {
	struct list_head head;
	struct list_head res_head;
};

static struct parsed_phase *cur_phase;

static char *kexec_res_names[3] = {"kernel", "initrd", "cmdline"};

struct kexec_res {
	struct list_head node;
	char *name;
	/* The free of buffer is deferred to kimage_file_post_load_cleanup */
	bool deferred_free;
	struct mem_range_result *r;
};

static struct parsed_phase *alloc_new_phase(void)
{
	struct parsed_phase *phase = kzalloc(sizeof(struct parsed_phase), GFP_KERNEL);

	INIT_LIST_HEAD(&phase->head);
	INIT_LIST_HEAD(&phase->res_head);
	list_add_tail(&phase->head, &phase_head);

	return phase;
}

/*
 * @name should be one of : kernel, initrd, cmdline
 */
static int bpf_kexec_carrier(const char *name, struct mem_range_result *r)
{
	struct kexec_res *res;

	if (!r || !name)
		return -EINVAL;

	res = kzalloc(sizeof(struct kexec_res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;
	res->name = kstrdup(name, GFP_KERNEL);
	kref_get(&r->ref);
	res->r = r;

	INIT_LIST_HEAD(&res->node);
	list_add_tail(&res->node, &cur_phase->res_head);
	return 0;
}

static struct carrier_listener kexec_res_listener[3] = {
	{ .name = "kernel",
	  .kmalloc = false,
	  .handler = bpf_kexec_carrier,
	},
	{ .name = "initrd",
	  .kmalloc = false,
	  .handler = bpf_kexec_carrier,
	},
	{ .name = "cmdline",
	  .kmalloc = true,
	  .handler = bpf_kexec_carrier,
	},
};

static bool is_valid_pe(const char *kernel_buf, unsigned long kernel_len)
{
	struct mz_hdr *mz;
	struct pe_hdr *pe;

	if (!kernel_buf)
		return false;
	mz = (struct mz_hdr *)kernel_buf;
	if (mz->magic != MZ_MAGIC)
		return false;
	pe = (struct pe_hdr *)(kernel_buf + mz->peaddr);
	if (pe->magic != PE_MAGIC)
		return false;
	if (pe->opt_hdr_size == 0) {
		pr_err("optional header is missing\n");
		return false;
	}

	return true;
}

static bool is_valid_format(const char *kernel_buf, unsigned long kernel_len)
{
	return is_valid_pe(kernel_buf, kernel_len);
}

/*
 * The UEFI Terse Executable (TE) image has MZ header.
 */
static int pe_image_probe(const char *kernel_buf, unsigned long kernel_len)
{
	return is_valid_pe(kernel_buf, kernel_len) ? 0 : -1;
}

static int get_pe_section(char *file_buf, const char *sect_name,
		char **sect_start, unsigned long *sect_sz)
{
	struct pe_hdr *pe_hdr;
	struct pe32plus_opt_hdr *opt_hdr;
	struct section_header *sect_hdr;
	int section_nr, i;
	struct mz_hdr *mz = (struct mz_hdr *)file_buf;

	*sect_start = NULL;
	*sect_sz = 0;
	pe_hdr = (struct pe_hdr *)(file_buf + mz->peaddr);
	section_nr = pe_hdr->sections;
	opt_hdr = (struct pe32plus_opt_hdr *)(file_buf + mz->peaddr + sizeof(struct pe_hdr));
	sect_hdr = (struct section_header *)((char *)opt_hdr + pe_hdr->opt_hdr_size);

	for (i = 0; i < section_nr; i++) {
		if (strcmp(sect_hdr->name, sect_name) == 0) {
			*sect_start = file_buf + sect_hdr->data_addr;
			*sect_sz = sect_hdr->raw_data_size;
			return 0;
		}
		sect_hdr++;
	}

	return -1;
}

static bool pe_has_bpf_section(char *file_buf, unsigned long pe_sz)
{
	char *sect_start = NULL;
	unsigned long sect_sz = 0;
	int ret;

	ret = get_pe_section(file_buf, ".bpf", &sect_start, &sect_sz);
	if (ret < 0)
		return false;
	return true;
}

/* Load a ELF */
static int arm_bpf_prog(char *bpf_elf, unsigned long sz)
{
	return 0;
}

static void disarm_bpf_prog(void)
{
}

struct kexec_context {
	bool kdump;
	char *image;
	int image_sz;
	char *initrd;
	int initrd_sz;
	char *cmdline;
	int cmdline_sz;
};

void bpf_handle_pefile(struct kexec_context *context);
void bpf_post_handle_pefile(struct kexec_context *context);


/*
 * optimize("O0") prevents inline, compiler constant propagation
 */
__attribute__((used, optimize("O0"))) void bpf_handle_pefile(struct kexec_context *context)
{
}

__attribute__((used, optimize("O0"))) void bpf_post_handle_pefile(struct kexec_context *context)
{
}

BTF_KFUNCS_START(kexec_modify_return_ids)
BTF_ID_FLAGS(func, bpf_handle_pefile, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_post_handle_pefile, KF_SLEEPABLE)
BTF_KFUNCS_END(kexec_modify_return_ids)

static const struct btf_kfunc_id_set kexec_modify_return_set = {
	.owner = THIS_MODULE,
	.set = &kexec_modify_return_ids,
};

static int __init kexec_bpf_prog_run_init(void)
{
	return register_btf_fmodret_id_set(&kexec_modify_return_set);
}
late_initcall(kexec_bpf_prog_run_init);

/*
 * PE file may be nested and should be unfold one by one.
 * Query 'kernel', 'initrd', 'cmdline' in cur_phase, as they are inputs for the
 * next phase.
 */
static int prepare_nested_pe(char **kernel, unsigned long *kernel_len, char **initrd,
		unsigned long *initrd_len, char **cmdline)
{
	struct kexec_res *res;
	int ret = -1;

	*kernel = NULL;
	*kernel_len = 0;

	list_for_each_entry(res, &cur_phase->res_head, node) {
		if (res->name == kexec_res_names[0]) {
			*kernel = res->r->buf;
			*kernel_len = res->r->data_sz;
			ret = 0;
		} else if (res->name == kexec_res_names[1]) {
			*initrd = res->r->buf;
			*initrd_len = res->r->data_sz;
		} else if (res->name == kexec_res_names[2]) {
			*cmdline = res->r->buf;
		}
	}

	return ret;
}

static void *pe_image_load(struct kimage *image,
				char *kernel, unsigned long kernel_len,
				char *initrd, unsigned long initrd_len,
				char *cmdline, unsigned long cmdline_len)
{
	char *parsed_kernel = NULL;
	unsigned long parsed_len;
	char *linux_start, *initrd_start, *cmdline_start, *bpf_start;
	unsigned long linux_sz, initrd_sz, cmdline_sz, bpf_sz;
	struct parsed_phase *phase, *phase_tmp;
	struct kexec_res *res, *res_tmp;
	void *ldata;
	int ret;

	linux_start = kernel;
	linux_sz = kernel_len;
	initrd_start = initrd;
	initrd_sz = initrd_len;
	cmdline_start = cmdline;
	cmdline_sz = cmdline_len;

	for (int i = 0; i < ARRAY_SIZE(kexec_res_listener); i++)
		register_carrier_listener(&kexec_res_listener[i]);

	while (is_valid_format(linux_start, linux_sz) &&
	       pe_has_bpf_section(linux_start, linux_sz)) {
		struct kexec_context context;

		get_pe_section(linux_start, ".bpf", &bpf_start, &bpf_sz);
		if (!!bpf_sz) {
			/* load and attach bpf-prog */
			ret = arm_bpf_prog(bpf_start, bpf_sz);
			if (ret) {
				pr_err("Fail to load .bpf section\n");
				ldata = ERR_PTR(ret);
				goto err;
			}
		}
		cur_phase = alloc_new_phase();
		if (image->type != KEXEC_TYPE_CRASH)
			context.kdump = false;
		else
			context.kdump = true;
		context.image = linux_start;
		context.image_sz = linux_sz;
		context.initrd = initrd_start;
		context.initrd_sz = initrd_sz;
		context.cmdline = cmdline_start;
		context.cmdline_sz = strlen(cmdline_start);
		/* bpf-prog fentry, which handle above buffers. */
		bpf_handle_pefile(&context);

		prepare_nested_pe(&linux_start, &linux_sz, &initrd_start,
					&initrd_sz, &cmdline_start);
		/* bpf-prog fentry */
		bpf_post_handle_pefile(&context);
		/*
		 * detach the current bpf-prog from their attachment points.
		 * It also a point to free any registered interim resource.
		 * Any resource except attached to phase is interim.
		 */
		disarm_bpf_prog();
	}

	for (int i = 0; i < ARRAY_SIZE(kexec_res_listener); i++)
		unregister_carrier_listener(kexec_res_listener[i].name);

	/* the rear of parsed phase contains the result */
	list_for_each_entry_reverse(phase, &phase_head, head) {
		if (initrd != NULL && cmdline != NULL && parsed_kernel != NULL)
			break;
		list_for_each_entry(res, &phase->res_head, node) {
			if (!strcmp(res->name, "kernel") && !parsed_kernel) {
				parsed_kernel = res->r->buf;
				parsed_len = res->r->data_sz;
				res->deferred_free = true;
			} else if (!strcmp(res->name, "initrd") && !initrd) {
				initrd = res->r->buf;
				initrd_len = res->r->data_sz;
				res->deferred_free = true;
			} else if (!strcmp(res->name, "cmdline") && !cmdline) {
				cmdline = res->r->buf;
				cmdline_len = res->r->data_sz;
				res->deferred_free = true;
			}
		}

	}

	if (initrd == NULL || cmdline == NULL || parsed_kernel == NULL) {
		char *c, buf[64];

		c = buf;
		if (parsed_kernel == NULL) {
			strcpy(c, "kernel ");
			c += strlen("kernel ");
		}
		if (initrd == NULL) {
			strcpy(c, "initrd ");
			c += strlen("initrd ");
		}
		if (cmdline == NULL) {
			strcpy(c, "cmdline ");
			c += strlen("cmdline ");
		}
		c = '\0';
		pr_err("Can not extract data for %s", buf);
		ldata = ERR_PTR(-EINVAL);
		goto err;
	}
	/*
	 * image's kernel_buf, initrd_buf, cmdline_buf are set. Now they should
	 * be updated to the new content.
	 */
	if (image->kernel_buf != parsed_kernel) {
		vfree(image->kernel_buf);
		image->kernel_buf = parsed_kernel;
		image->kernel_buf_len = parsed_len;
	}
	if (image->initrd_buf != initrd) {
		vfree(image->initrd_buf);
		image->initrd_buf = initrd;
		image->initrd_buf_len = initrd_len;
	}
	if (image->cmdline_buf != cmdline) {
		kfree(image->cmdline_buf);
		image->cmdline_buf = cmdline;
		image->cmdline_buf_len = cmdline_len;
	}
	ret = arch_kexec_kernel_image_probe(image, image->kernel_buf,
					    image->kernel_buf_len);
	if (ret) {
		pr_err("Fail to find suitable image loader\n");
		ldata = ERR_PTR(ret);
		goto err;
	}
	ldata = kexec_image_load_default(image);
	if (IS_ERR(ldata)) {
		pr_err("architecture code fails to load image\n");
		goto err;
	}
	image->image_loader_data = ldata;

err:
	list_for_each_entry_safe(phase, phase_tmp, &phase_head, head) {
		list_for_each_entry_safe(res, res_tmp, &phase->res_head, node) {
			list_del(&res->node);
			/* defer to kimage_file_post_load_cleanup() */
			if (res->deferred_free) {
				res->r->buf = NULL;
				res->r->buf_sz = 0;
			}
			mem_range_result_put(res->r);
			kfree(res);
		}
		list_del(&phase->head);
		kfree(phase);
	}

	return ldata;
}

const struct kexec_file_ops kexec_pe_image_ops = {
	.probe = pe_image_probe,
	.load = pe_image_load,
#ifdef CONFIG_KEXEC_IMAGE_VERIFY_SIG
	.verify_sig = kexec_kernel_verify_pe_sig,
#endif
};
