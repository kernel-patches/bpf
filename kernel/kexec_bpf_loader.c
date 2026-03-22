// SPDX-License-Identifier: GPL-2.0
/*
 * Kexec image bpf section helpers
 *
 * Copyright (C) 2025, 2026 Red Hat, Inc
 */

#define pr_fmt(fmt) "kexec_file(Image): " fmt

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/kexec.h>
#include <linux/ima.h>
#include <linux/elf.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <asm/byteorder.h>
#include <asm/image.h>
#include <asm/memory.h>
#include <linux/decompress/generic.h>
#include "kexec_internal.h"

/* Load a ELF */
static int arm_bpf_prog(char *bpf_elf, unsigned long sz)
{
	return -1;
}

static void disarm_bpf_prog(void)
{
}

#define MAX_PARSING_BUF_NUM    16

struct kexec_context {
	bool kdump;
	bool parsed;
	char *parsing_buf[MAX_PARSING_BUF_NUM];
	unsigned long parsing_buf_sz[MAX_PARSING_BUF_NUM];

	char *kernel;
	unsigned long kernel_sz;
	char *initrd;
	unsigned long initrd_sz;
	char *cmdline;
	unsigned long cmdline_sz;
};

void kexec_image_parser_anchor(struct kexec_context *context,
			       unsigned long parser_id);

void noinline __used kexec_image_parser_anchor(struct kexec_context *context,
					       unsigned long parser_id)
{
	barrier();
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

/* Mark the bpf parser success */
#define KEXEC_BPF_CMD_INVALID		0x0
#define KEXEC_BPF_CMD_DONE		0x1
#define KEXEC_BPF_CMD_DECOMPRESS	0x2
#define KEXEC_BPF_CMD_COPY		0x3

#define KEXEC_BPF_SUBCMD_INVALID	0x0
#define KEXEC_BPF_SUBCMD_KERNEL		0x1
#define KEXEC_BPF_SUBCMD_INITRD		0x2
#define KEXEC_BPF_SUBCMD_CMDLINE	0x3

#define KEXEC_BPF_PIPELINE_INVALID	0x0
#define KEXEC_BPF_PIPELINE_FILL		0x1

struct cmd_hdr {
	uint16_t cmd;
	uint8_t subcmd;
	uint8_t pipeline_flag;
	/* sizeof(chunks) + sizeof(all data) */
	uint32_t payload_len;
	/* 0 */
	uint16_t num_chunks;
} __packed;

/* Reserved for extension */
struct cmd_chunk {
	uint16_t type;
	uint32_t len;
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
			char **out, unsigned long *size)
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
		a->chunk_base_addr[i] = NULL;
	}

	memcpy(cur_dst, a->chunk_base_addr[i], last_chunk_sz);
	vfree(a->chunk_base_addr[i]);
	a->chunk_base_addr[i] = NULL;
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
	int i;

	for (i = 0; i < a->next_idx; i++) {
		if (a->chunk_base_addr[i] != NULL)
			vfree(a->chunk_base_addr[i]);
	}
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
		char **out_buf, unsigned long *out_sz, struct kexec_context *ctx)
{
	struct decompress_mem_allocator *a = &dcmpr_allocator;
	decompress_fn decompressor;
	const char *name;
	int ret;

	ret = decompress_mem_allocator_init(a, CHUNK_SIZE);
	if (ret < 0)
		return ret;
	decompressor = decompress_method(compressed_data, image_gz_sz, &name);
	if (!decompressor) {
		pr_err("Can not find decompress method\n");
		ret = -1;
		goto err;
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
	unsigned long decompressed_sz;
	int ret = 0;

	buf = pbuf->buf + sizeof(struct cmd_hdr);
	if (cmd->payload_len + sizeof(struct cmd_hdr) > pbuf->size) {
		pr_info("Invalid payload size:0x%x, while buffer size:0x%x\n",
				cmd->payload_len, pbuf->size);
		return -EINVAL;
	}
	switch (cmd->cmd) {
	case KEXEC_BPF_CMD_DONE:
		ctx->parsed = true;
		break;
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
				vfree(decompressed_buf);
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
		/* Todo: allow the concatenation of multiple initrd */
		case KEXEC_BPF_SUBCMD_INITRD:
			vfree(ctx->initrd);
			ctx->initrd = p;
			ctx->initrd_sz = cmd->payload_len;
			break;
		/* Todo: allow the concatenation of multiple cmdline */
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

#define KEXEC_ELF_BPF_PREFIX		".bpf."
#define KEXEC_ELF_BPF_NESTED		".bpf.nested"
#define KEXEC_ELF_BPF_MAX_IDX		8
#define KEXEC_ELF_BPF_MAX_DEPTH		4

static bool is_elf_image(const char *buf, size_t sz)
{
	if (sz < SELFMAG)
		return false;

	return memcmp(buf, ELFMAG, SELFMAG) == 0;
}

/*
 * elf_get_shstrtab - resolve the section-name string table of an ELF image
 * @buf:       ELF image buffer
 * @sz:        buffer length
 * @ehdr_out:  receives a pointer to the ELF header inside @buf
 * @shdrs_out: receives a pointer to the section-header table inside @buf
 * @shstrtab_out: receives a pointer to the section-name string table
 *
 * All output pointers are interior pointers into @buf; callers must not
 * free them independently.
 *
 * Returns 0 on success, -EINVAL if any structural check fails.
 */
static int elf_get_shstrtab(const char *buf, size_t sz,
			    const Elf64_Ehdr **ehdr_out,
			    const Elf64_Shdr **shdrs_out,
			    const char **shstrtab_out)
{
	const Elf64_Ehdr *ehdr;
	const Elf64_Shdr *shdrs;
	const Elf64_Shdr *shstr_shdr;

	if (sz < sizeof(*ehdr))
		return -EINVAL;

	ehdr = (const Elf64_Ehdr *)buf;

	if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0)
		return -EINVAL;

	if (ehdr->e_shstrndx >= ehdr->e_shnum)
		return -EINVAL;

	/* section-header table must fit inside the buffer */
	if (ehdr->e_shoff > sz ||
	    ehdr->e_shnum > (sz - ehdr->e_shoff) / sizeof(Elf64_Shdr))
		return -EINVAL;

	shdrs = (const Elf64_Shdr *)(buf + ehdr->e_shoff);
	shstr_shdr = &shdrs[ehdr->e_shstrndx];

	/* string table itself must fit inside the buffer */
	if (shstr_shdr->sh_offset > sz ||
	    shstr_shdr->sh_size > sz - shstr_shdr->sh_offset)
		return -EINVAL;

	*ehdr_out     = ehdr;
	*shdrs_out    = shdrs;
	*shstrtab_out = buf + shstr_shdr->sh_offset;

	return 0;
}

/*
 * validate_elf_bpf_sections - enforce the section-naming contract
 * @buf: ELF image buffer
 * @sz:  buffer length
 *
 * Every section other than the null entry (index 0) and ".shstrtab" must
 * be named either ".bpf.N" (N in 1..KEXEC_ELF_BPF_MAX_IDX, no gaps, no
 * duplicates) or ".bpf.nested" (at most once).  Any other name, any
 * duplicate, or a gap in the numeric sequence is an error.
 *
 * Returns 0 if the ELF passes all checks, -EINVAL otherwise.
 */
static int validate_elf_bpf_sections(const char *buf, size_t sz)
{
	const Elf64_Ehdr *ehdr;
	const Elf64_Shdr *shdrs;
	const Elf64_Shdr *shstr_shdr;
	const char *shstrtab;
	bool seen[KEXEC_ELF_BPF_MAX_IDX + 1] = {};
	bool seen_nested = false;
	int max_idx = 0;
	int ret;
	int i;

	if (!is_elf_image(buf, sz))
		return -EINVAL;

	ret = elf_get_shstrtab(buf, sz, &ehdr, &shdrs, &shstrtab);
	if (ret)
		return ret;

	shstr_shdr = &shdrs[ehdr->e_shstrndx];

	for (i = 0; i < ehdr->e_shnum; i++) {
		const char *name;
		const char *num_str;
		int idx;

		if (shdrs[i].sh_name >= shstr_shdr->sh_size)
			return -EINVAL;

		name = shstrtab + shdrs[i].sh_name;

		/* structural ELF sections: null entry and section-name table */
		if (name[0] == '\0' || strcmp(name, ".shstrtab") == 0)
			continue;

		/* .bpf.nested must appear at most once */
		if (strcmp(name, KEXEC_ELF_BPF_NESTED) == 0) {
			if (seen_nested) {
				pr_err("kexec: duplicate .bpf.nested section\n");
				return -EINVAL;
			}
			seen_nested = true;
			continue;
		}

		/* every remaining section must start with the ".bpf." prefix */
		if (strncmp(name, KEXEC_ELF_BPF_PREFIX,
			    sizeof(KEXEC_ELF_BPF_PREFIX) - 1) != 0) {
			pr_err("kexec: invalid ELF section name: %s\n", name);
			return -EINVAL;
		}

		/*
		 * Suffix must be exactly one digit in [1, KEXEC_ELF_BPF_MAX_IDX].
		 * Multi-digit numbers and leading zeros are rejected.
		 */
		num_str = name + sizeof(KEXEC_ELF_BPF_PREFIX) - 1;
		if (num_str[0] < '1' ||
		    num_str[0] > '0' + KEXEC_ELF_BPF_MAX_IDX ||
		    num_str[1] != '\0') {
			pr_err("kexec: invalid BPF section index in: %s\n", name);
			return -EINVAL;
		}

		idx = num_str[0] - '0';
		if (seen[idx]) {
			pr_err("kexec: duplicate BPF section: %s\n", name);
			return -EINVAL;
		}
		seen[idx] = true;
		if (idx > max_idx)
			max_idx = idx;
	}

	/* indices must be consecutive starting from 1 */
	for (i = 1; i <= max_idx; i++) {
		if (!seen[i]) {
			pr_err("kexec: missing .bpf.%d section\n", i);
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * elf_find_section - locate a named section in an ELF image
 * @buf:     ELF image buffer
 * @sz:      buffer length
 * @name:    section name to find
 * @out_buf: receives a pointer to the section data (NULL if not found)
 * @out_sz:  receives the section size in bytes (0 if not found)
 *
 * Returns 0 on success (including the "not found" case), -EINVAL on a
 * structural error.
 */
static int elf_find_section(const char *buf, size_t sz, const char *name,
			    char **out_buf, size_t *out_sz)
{
	const Elf64_Ehdr *ehdr;
	const Elf64_Shdr *shdrs;
	const Elf64_Shdr *shstr_shdr;
	const char *shstrtab;
	int ret;
	int i;

	ret = elf_get_shstrtab(buf, sz, &ehdr, &shdrs, &shstrtab);
	if (ret)
		return ret;

	shstr_shdr = &shdrs[ehdr->e_shstrndx];

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdrs[i].sh_name >= shstr_shdr->sh_size)
			return -EINVAL;

		if (strcmp(shstrtab + shdrs[i].sh_name, name) != 0)
			continue;

		/* section data must be within the buffer */
		if (shdrs[i].sh_offset > sz ||
		    shdrs[i].sh_size > sz - shdrs[i].sh_offset)
			return -EINVAL;

		*out_buf = (char *)(buf + shdrs[i].sh_offset);
		*out_sz  = shdrs[i].sh_size;
		return 0;
	}

	*out_buf = NULL;
	*out_sz  = 0;
	return 0;
}

/*
 * process_bpf_parsers_container - recursively process an ELF container, which holds a
 * batch of bpf parsers
 *
 * @elf_buf: ELF image buffer at this level
 * @elf_sz:  buffer length
 * @context: shared kexec parsing context
 * @depth:   current recursion depth (call with 1 for the top level)
 *
 *   1. a valid section names should be .bpf.1, .bpf.2, ... in order.
 *      They are different parser for the current layer.
 *   2. Only a .bpf.nested section is allowed for the internal level.
 *   3. At each level, stop trying at the first attempt where context->parsed becomes
 *      true, then try to load .bpf.nested to parse the internal layer
 *
 * Returns 0 on success, -EINVAL on any error.
 */
static int process_bpf_parsers_container(const char *elf_buf, size_t elf_sz,
				   struct kexec_context *context, int depth)
{
	struct bpf_parser_context *bpf;
	char *section_buf, *nested_buf;
	size_t section_sz;
	size_t nested_sz;
	/* .bpf.1 etc */
	char section_name[sizeof(KEXEC_ELF_BPF_PREFIX) + 1];
	bool found = false;
	int ret;
	int i;

	if (depth > KEXEC_ELF_BPF_MAX_DEPTH) {
		pr_err("kexec: ELF BPF nesting depth exceeds %d\n",
		       KEXEC_ELF_BPF_MAX_DEPTH);
		return -EINVAL;
	}

	ret = validate_elf_bpf_sections(elf_buf, elf_sz);
	if (ret)
		return ret;

	for (i = 1; i <= KEXEC_ELF_BPF_MAX_IDX && !found; i++) {
		snprintf(section_name, sizeof(section_name), ".bpf.%d", i);

		ret = elf_find_section(elf_buf, elf_sz, section_name,
				       &section_buf, &section_sz);
		if (ret)
			return ret;

		/* no section at this index means the sequence is exhausted */
		if (!section_buf)
			break;

		bpf = alloc_bpf_parser_context(kexec_buff_parser, context);
		if (!bpf)
			return -ENOMEM;

		ret = arm_bpf_prog(section_buf, section_sz);
		if (ret) {
			/* arm failed: no disarm needed, try next index */
			put_bpf_parser_context(bpf);
			pr_info("kexec: arm_bpf_prog failed for %s (depth %d), trying next\n",
				 section_name, depth);
			continue;
		}

		/*
		 * Give the BPF prog a clean slate so context->parsed reliably
		 * reflects whether *this* invocation succeeded.
		 */
		context->parsed = false;
		/* This is the hook point for bpf-prog */
		kexec_image_parser_anchor(context, (unsigned long)bpf);
		disarm_bpf_prog();

		/* Free the old parsing context, and reload the new */
		for (int i = 0; i < MAX_PARSING_BUF_NUM; i++) {
			if (!!context->parsing_buf[i])
				break;
			vfree(context->parsing_buf[i]);
			context->parsing_buf[i] = NULL;
			context->parsing_buf_sz[i] = 0;
		}

		put_bpf_parser_context(bpf);
		/* If the bpf-prog success, it flags by KEXEC_BPF_CMD_DONE */
		if (context->parsed)
			found = true;
	}

	if (!found) {
		pr_err("kexec: no BPF section succeeded at depth %d\n", depth);
		return -EINVAL;
	}

	/*
	 * A numbered section succeeded.  If .bpf.nested is present, the
	 * current context->kernel may still be in a container format that
	 * the next level of BPF progs knows how to unpack.
	 */
	ret = elf_find_section(elf_buf, elf_sz, KEXEC_ELF_BPF_NESTED,
			       &nested_buf, &nested_sz);
	if (ret)
		return ret;

	if (!nested_buf)
		return 0;

	context->parsed = false;
	return process_bpf_parsers_container(nested_buf, nested_sz, context,
				       depth + 1);
}

int decompose_kexec_image(struct kimage *image, int extended_fd)
{
	struct kexec_context ctx = { 0 };
	unsigned long parser_sz;
	char *parser_start;
	int ret = -EINVAL;

	if (extended_fd < 0)
		return ret;

	if (image->type != KEXEC_TYPE_CRASH)
		ctx.kdump = false;
	else
		ctx.kdump = true;

	parser_start = image->kernel_buf;
	parser_sz = image->kernel_buf_len;

	if (!validate_elf_bpf_sections(parser_start, parser_sz)) {

		ret = kernel_read_file_from_fd(extended_fd,
						0,
						(void **)&ctx.parsing_buf[0],
						KEXEC_FILE_SIZE_MAX,
						NULL,
						0);
		if (ret < 0) {
			pr_err("Fail to read image container\n");
			return -EINVAL;
		}
		ctx.parsing_buf_sz[0] = ret;
		ret = process_bpf_parsers_container(parser_start, parser_sz, &ctx, 0);
		if (!ret) {
			char *p;

			/* Envelop should hold valid kernel, initrd, cmdline sections */
			if (!ctx.kernel || !ctx.initrd || !ctx.cmdline) {
				vfree(ctx.kernel);
				vfree(ctx.initrd);
				vfree(ctx.cmdline);
				return -EINVAL;
			}
			/*
			 * kimage_file_post_load_cleanup() calls kfree() to free
			 * cmdline
			 */
			p = kmalloc(ctx.cmdline_sz, GFP_KERNEL);
			if (!p) {
				vfree(ctx.kernel);
				vfree(ctx.initrd);
				vfree(ctx.cmdline);
				return -ENOMEM;
			}
			vfree(image->kernel_buf);
			image->kernel_buf = ctx.kernel;
			image->kernel_buf_len = ctx.kernel_sz;
			image->initrd_buf = ctx.initrd;
			image->initrd_buf_len = ctx.initrd_sz;
			memcpy(p, ctx.cmdline, ctx.cmdline_sz);
			image->cmdline_buf = p;
			image->cmdline_buf_len = ctx.cmdline_sz;
			vfree(ctx.cmdline);
		}
		return ret;
	}

	return -EINVAL;
}
