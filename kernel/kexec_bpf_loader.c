// SPDX-License-Identifier: GPL-2.0
/*
 * Kexec image bpf section helpers
 *
 * Copyright (C) 2025, 2026 Red Hat, Inc
 */

#define pr_fmt(fmt)	"kexec_file(Image): " fmt

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/kexec.h>
#include <linux/elf.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <asm/byteorder.h>
#include <asm/image.h>
#include <asm/memory.h>
#include <linux/decompress/generic.h>
#include "kexec_internal.h"

#include "kexec_bpf/kexec_pe_parser_bpf.lskel.h"

static struct kexec_pe_parser_bpf *pe_parser;

static void *get_symbol_from_elf(const char *elf_data, size_t elf_size,
		const char *symbol_name, unsigned int *symbol_size)
{
	Elf_Ehdr *ehdr = (Elf_Ehdr *)elf_data;
	Elf_Shdr *shdr, *dst_shdr;
	const Elf_Sym *sym;
	void *symbol_data;

	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		pr_err("Not a valid ELF file\n");
		return NULL;
	}

	sym = elf_find_symbol(ehdr, symbol_name);
	if (!sym)
		return NULL;
	shdr = (struct elf_shdr *)(elf_data + ehdr->e_shoff);
	dst_shdr = &shdr[sym->st_shndx];
	symbol_data = (void *)(elf_data + dst_shdr->sh_offset + sym->st_value);
	*symbol_size = sym->st_size;

	return symbol_data;
}

/* Load a ELF */
static int arm_bpf_prog(char *bpf_elf, unsigned long sz)
{
	opts_data = get_symbol_from_elf(bpf_elf, sz, "opts_data", &opts_data_sz);
	opts_insn = get_symbol_from_elf(bpf_elf, sz, "opts_insn", &opts_insn_sz);
	if (!opts_data || !opts_insn)
		return -1;
	/*
	 * When light skeleton generates opts_data[] and opts_insn[], it appends a
	 * NULL terminator at the end of string
	 */
	opts_data_sz = opts_data_sz - 1;
	opts_insn_sz = opts_insn_sz - 1;

	pe_parser = kexec_pe_parser_bpf__open_and_load();
	if (!pe_parser)
		return -1;
	kexec_pe_parser_bpf__attach(pe_parser);

	return 0;
}

static void disarm_bpf_prog(void)
{
	kexec_pe_parser_bpf__destroy(pe_parser);
	pe_parser = NULL;
	opts_data = NULL;
	opts_insn = NULL;
}

struct kexec_context {
	bool kdump;
	char *kernel;
	int kernel_sz;
	char *initrd;
	int initrd_sz;
	char *cmdline;
	int cmdline_sz;
};

void kexec_image_parser_anchor(struct kexec_context *context,
		unsigned long parser_id);

/*
 * optimize("O0") prevents inline, compiler constant propagation
 *
 * Let bpf be the program context pointer so that it will not be spilled into
 * stack.
 */
__attribute__((used, optimize("O0"))) void kexec_image_parser_anchor(
		struct kexec_context *context,
		unsigned long parser_id)
{
	/*
	 * To prevent linker from Identical Code Folding (ICF) with kexec_image_parser_anchor,
	 * making them have different code.
	 */
	volatile int dummy = 0;

	dummy += 1;
}


BTF_KFUNCS_START(kexec_modify_return_ids)
BTF_ID_FLAGS(func, kexec_image_parser_anchor, KF_SLEEPABLE)
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

#define KEXEC_BPF_CMD_DECOMPRESS	0x1
#define KEXEC_BPF_CMD_COPY		0x2

#define KEXEC_BPF_SUBCMD_KERNEL		0x1
#define KEXEC_BPF_SUBCMD_INITRD		0x2
#define KEXEC_BPF_SUBCMD_CMDLINE	0x3

struct cmd_hdr {
	uint16_t cmd;
	uint16_t subcmd;
	uint32_t payload_len;
} __packed;


/* Max decompressed size is capped at 512M */
#define MAX_UNCOMPRESSED_BUF_SIZE	(1 << 29)
#define CHUNK_SIZE	(1 << 23)

struct decompress_mem_allocator {
	void *chunk_start;
	unsigned int chunk_size;
	void *chunk_cur;
	unsigned int next_idx;
	char **chunk_base_addr;
};

/*
 * This global allocator for decompression is protected by kexec lock.
 */
static struct decompress_mem_allocator dcmpr_allocator;

/*
 * Set up an active chunk to hold partial decompressed data.
 */
static char *allocate_chunk_memory(void)
{
	struct decompress_mem_allocator *a = &dcmpr_allocator;
	char *p;

	if (unlikely((a->next_idx * a->chunk_size >= MAX_UNCOMPRESSED_BUF_SIZE)))
		return NULL;

	p = __vmalloc(a->chunk_size, GFP_KERNEL | __GFP_ACCOUNT);
	if (!p)
		return NULL;
	a->chunk_base_addr[a->next_idx++] = p;
	a->chunk_start = a->chunk_cur = p;

	return p;
}

static int merge_decompressed_data(struct decompress_mem_allocator *a,
			char **out, unsigned int *size)
{
	unsigned int last_chunk_sz = a->chunk_cur - a->chunk_start;
	unsigned long total_sz;
	char *dst, *cur_dst;
	int i;

	total_sz = (a->next_idx - 1) * a->chunk_size + last_chunk_sz;
	cur_dst = dst = __vmalloc(total_sz, GFP_KERNEL | __GFP_ACCOUNT);
	if (!dst)
		return -ENOMEM;

	for (i = 0; i < a->next_idx - 1; i++) {
		memcpy(cur_dst, a->chunk_base_addr[i], a->chunk_size);
		cur_dst += a->chunk_size;
		vfree(a->chunk_base_addr[i]);
	}

	memcpy(cur_dst, a->chunk_base_addr[i], last_chunk_sz);
	vfree(a->chunk_base_addr[i]);
	*out = dst;
	*size = total_sz;

	return 0;
}

static int decompress_mem_allocator_init(
	struct decompress_mem_allocator *a,
	unsigned int chunk_size)
{
	unsigned long sz = (MAX_UNCOMPRESSED_BUF_SIZE / chunk_size) * sizeof(void *);
	char *buf;

	a->chunk_base_addr = __vmalloc(sz, GFP_KERNEL | __GFP_ACCOUNT);
	if (!a->chunk_base_addr)
		return -ENOMEM;

	/* Pre-allocate the memory for the first chunk */
	buf = __vmalloc(chunk_size, GFP_KERNEL | __GFP_ACCOUNT);
	if (!buf) {
		vfree(a->chunk_base_addr);
		return -ENOMEM;
	}
	a->chunk_base_addr[0] = buf;
	a->chunk_start = a->chunk_cur = buf;
	a->chunk_size = chunk_size;
	a->next_idx = 1;
	return 0;
}

static void decompress_mem_allocator_fini(struct decompress_mem_allocator *a)
{
	vfree(a->chunk_base_addr);
}

/*
 * This is a callback for decompress_fn.
 *
 * It copies the partial decompressed content in [buf, buf + len) to dst. If the
 * active chunk is not large enough, retire it and activate a new chunk to hold
 * the remaining data.
 */
static long flush(void *buf, unsigned long len)
{
	struct decompress_mem_allocator *a = &dcmpr_allocator;
	long free, copied = 0;

	if (unlikely(len > a->chunk_size)) {
		pr_info("Chunk size is too small to hold decompressed data\n");
		return -1;
	}
	free = a->chunk_start + a->chunk_size - a->chunk_cur;
	BUG_ON(free < 0);
	if (free < len) {
		memcpy(a->chunk_cur, buf, free);
		copied += free;
		a->chunk_cur += free;
		buf += free;
		len -= free;
		a->chunk_start = a->chunk_cur = allocate_chunk_memory();
		if (unlikely(!a->chunk_start)) {
			pr_info("Decompression runs out of memory\n");
			return -1;
		}
	}
	memcpy(a->chunk_cur, buf, len);
	copied += len;
	a->chunk_cur += len;
	return copied;
}

static int parser_cmd_decompress(char *compressed_data, int image_gz_sz,
		char **out_buf, int *out_sz, struct kexec_context *ctx)
{
	struct decompress_mem_allocator *a = &dcmpr_allocator;
	decompress_fn decompressor;
	const char *name;
	int ret;

	decompress_mem_allocator_init(a, CHUNK_SIZE);
	decompressor = decompress_method(compressed_data, image_gz_sz, &name);
	if (!decompressor) {
		pr_err("Can not find decompress method\n");
		return -1;
	}
	pr_debug("Find decompressing method: %s, compressed sz:0x%x\n",
			name, image_gz_sz);
	ret = decompressor(compressed_data, image_gz_sz, NULL, flush,
				NULL, NULL, NULL);
	if (!!ret)
		goto err;
	ret = merge_decompressed_data(a, out_buf, out_sz);

err:
	decompress_mem_allocator_fini(a);

	return ret;
}

static int kexec_buff_parser(struct bpf_parser_context *parser)
{
	struct bpf_parser_buf *pbuf = parser->buf;
	struct kexec_context *ctx = (struct kexec_context *)parser->data;
	struct cmd_hdr *cmd = (struct cmd_hdr *)pbuf->buf;
	char *decompressed_buf, *buf, *p;
	int decompressed_sz, ret;

	buf = pbuf->buf + sizeof(struct cmd_hdr);
	if (cmd->payload_len + sizeof(struct cmd_hdr) > pbuf->size) {
		pr_info("Invalid payload size:0x%x, while buffer size:0x%x\n",
				cmd->payload_len, pbuf->size);
		return -EINVAL;
	}
	switch (cmd->cmd) {
	case KEXEC_BPF_CMD_DECOMPRESS:
		ret = parser_cmd_decompress(buf, cmd->payload_len, &decompressed_buf,
					&decompressed_sz, ctx);
		if (!ret) {
			switch (cmd->subcmd) {
			case KEXEC_BPF_SUBCMD_KERNEL:
				vfree(ctx->kernel);
				ctx->kernel = decompressed_buf;
				ctx->kernel_sz = decompressed_sz;
				break;
			default:
				break;
			}
		}
		break;
	case KEXEC_BPF_CMD_COPY:
		p = __vmalloc(cmd->payload_len, GFP_KERNEL | __GFP_ACCOUNT);
		if (!p)
			return -ENOMEM;
		memcpy(p, buf, cmd->payload_len);
		switch (cmd->subcmd) {
		case KEXEC_BPF_SUBCMD_KERNEL:
			vfree(ctx->kernel);
			ctx->kernel = p;
			ctx->kernel_sz = cmd->payload_len;
			break;
		case KEXEC_BPF_SUBCMD_INITRD:
			vfree(ctx->initrd);
			ctx->initrd = p;
			ctx->initrd_sz = cmd->payload_len;
			break;
		case KEXEC_BPF_SUBCMD_CMDLINE:
			vfree(ctx->cmdline);
			ctx->cmdline = p;
			ctx->cmdline_sz = cmd->payload_len;
			break;
		default:
			vfree(p);
			break;
		}
		break;
	default:
		break;
	}

	return 0;
}

/* At present, only PE format file with .bpf section is supported */
#define file_has_bpf_section	pe_has_bpf_section
#define file_get_section	pe_get_section

int decompose_kexec_image(struct kimage *image, int extended_fd)
{
	struct kexec_context context = { 0 };
	struct bpf_parser_context *bpf;
	unsigned long kernel_sz, bpf_sz;
	char *kernel_start, *bpf_start;
	int ret = 0;

	if (image->type != KEXEC_TYPE_CRASH)
	        context.kdump = false;
	else
	        context.kdump = true;

	kernel_start = image->kernel_buf;
	kernel_sz = image->kernel_buf_len;

	while (file_has_bpf_section(kernel_start, kernel_sz)) {

		bpf = alloc_bpf_parser_context(kexec_buff_parser, &context);
		if (!bpf)
			return -ENOMEM;
		file_get_section((const char *)kernel_start, ".bpf", &bpf_start, &bpf_sz);
		if (!!bpf_sz) {
			/* load and attach bpf-prog */
			ret = arm_bpf_prog(bpf_start, bpf_sz);
			if (ret) {
				put_bpf_parser_context(bpf);
				pr_err("Fail to load .bpf section\n");
				goto err;
			}
		}
		context.kernel = kernel_start;
		context.kernel_sz = kernel_sz;
		/* bpf-prog fentry, which handle above buffers. */
		kexec_image_parser_anchor(&context, (unsigned long)bpf);

		/*
		 * Container may be nested and should be unfold one by one.
		 * The former bpf-prog should prepare 'kernel', 'initrd',
		 * 'cmdline' for the next phase by calling kexec_buff_parser()
		 */
		kernel_start = context.kernel;
		kernel_sz = context.kernel_sz;

		/*
		 * detach the current bpf-prog from their attachment points.
		 */
		disarm_bpf_prog();
		put_bpf_parser_context(bpf);
	}

	/*
	 * image's kernel_buf, initrd_buf, cmdline_buf are set. Now they should
	 * be updated to the new content.
	 */
	image->kernel_buf = context.kernel;
	image->kernel_buf_len = context.kernel_sz;
	image->initrd_buf = context.initrd;
	image->initrd_buf_len = context.initrd_sz;
	image->cmdline_buf = context.cmdline;
	image->cmdline_buf_len = context.cmdline_sz;

	return 0;
err:
	vfree(context.kernel);
	vfree(context.initrd);
	vfree(context.cmdline);
	return ret;
}

