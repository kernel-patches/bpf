// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Based on:
 *
 * Minimal BPF JIT image disassembler
 *
 * Disassembles BPF JIT compiler emitted opcodes back to asm insn's for
 * debugging or verification purposes.
 *
 * Copyright 2013 Daniel Borkmann <daniel@iogearbox.net>
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <bpf/libbpf.h>

#ifdef HAVE_LLVM_SUPPORT
#ifdef LLVM_PLUGIN_DIR
#include <dlfcn.h>
#endif
#include "llvm_disasm.h"
#endif

#ifdef HAVE_LIBBFD_SUPPORT
#include <bfd.h>
#include <dis-asm.h>
#include <tools/dis-asm-compat.h>
#endif

#include "json_writer.h"
#include "main.h"

static int oper_count;

#ifdef HAVE_LLVM_SUPPORT
#define DISASM_SPACER

typedef void *disasm_ctx_t;

static const struct bpftool_llvm_ops *llvm_ops;

#ifdef LLVM_PLUGIN_DIR
#define LLVM_PLUGIN_NAME "bpftool-llvm.so"

static const char *dl_error(void)
{
	const char *err = dlerror();

	/* The error may already be consumed, e.g. by an LD_PRELOAD-ed library */
	return err ? err : "unknown error";
}

/*
 * Look for the plugin in its install directory, then next to the bpftool
 * binary so that bpftool also works from its build directory. Do not look
 * in the current directory: bpftool usually runs as root, and would then
 * load any library planted in the directory it is run from.
 */
static int llvm_plugin_find(char *path, size_t size)
{
	char exe[PATH_MAX];
	ssize_t len;
	char *dir;
	int n;

	snprintf(path, size, "%s/%s", LLVM_PLUGIN_DIR, LLVM_PLUGIN_NAME);
	if (!access(path, F_OK))
		return 0;

	len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (len < 0)
		return -1;
	exe[len] = '\0';
	dir = strrchr(exe, '/');
	if (!dir)
		return -1;
	*dir = '\0';

	n = snprintf(path, size, "%s/%s", exe, LLVM_PLUGIN_NAME);
	if (n < 0 || (size_t)n >= size)
		return -1;
	return access(path, F_OK);
}

static int llvm_load(bool verbose)
{
	const struct bpftool_llvm_ops *ops;
	char path[PATH_MAX];
	void *handle;

	if (llvm_ops)
		return 0;

	if (llvm_plugin_find(path, sizeof(path))) {
		if (verbose)
			p_err("%s not found in %s or next to bpftool, it is required to disassemble JITed programs",
			      LLVM_PLUGIN_NAME, LLVM_PLUGIN_DIR);
		return -1;
	}

	handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!handle) {
		if (verbose)
			p_err("failed to load LLVM disassembler plugin: %s",
			      dl_error());
		return -1;
	}

	ops = dlsym(handle, BPFTOOL_LLVM_OPS_SYM);
	if (!ops) {
		if (verbose)
			p_err("invalid LLVM disassembler plugin: %s", dl_error());
		goto err_close;
	}
	if (ops->abi_version != BPFTOOL_LLVM_ABI_VERSION) {
		if (verbose)
			p_err("%s has ABI version %u, expected %u",
			      path, ops->abi_version, BPFTOOL_LLVM_ABI_VERSION);
		goto err_close;
	}

	/* Keep the plugin loaded until bpftool exits */
	llvm_ops = ops;
	return 0;

err_close:
	dlclose(handle);
	return -1;
}
#else
static int llvm_load(__maybe_unused bool verbose)
{
	llvm_ops = &bpftool_llvm_ops;
	return 0;
}
#endif /* LLVM_PLUGIN_DIR */

static int printf_json(char *s)
{
	s = strtok(s, " \t");
	jsonw_string_field(json_wtr, "operation", s);

	jsonw_name(json_wtr, "operands");
	jsonw_start_array(json_wtr);
	oper_count = 1;

	while ((s = strtok(NULL, " \t,()")) != 0) {
		jsonw_string(json_wtr, s);
		oper_count++;
	}
	return 0;
}

static int
init_context(disasm_ctx_t *ctx, const char *arch,
	     __maybe_unused const char *disassembler_options,
	     __maybe_unused unsigned char *image, __maybe_unused ssize_t len,
	     __maybe_unused __u64 func_ksym)
{
	*ctx = llvm_ops->create_context(arch);
	if (!*ctx) {
		p_err("Failed to create disassembler");
		return -1;
	}

	return 0;
}

static void destroy_context(disasm_ctx_t *ctx)
{
	llvm_ops->destroy_context(*ctx);
}

static int
disassemble_insn(disasm_ctx_t *ctx, unsigned char *image, ssize_t len, int pc,
		 __u64 func_ksym)
{
	char buf[256];
	int count;

	count = llvm_ops->disassemble(*ctx, image + pc, len - pc, func_ksym + pc,
				      buf, sizeof(buf));
	if (json_output)
		printf_json(buf);
	else
		printf("%s", buf);

	return count;
}

bool disasm_llvm_available(void)
{
	return !llvm_load(false);
}

int disasm_init(void)
{
	if (llvm_load(true))
		return -1;
	return llvm_ops->init();
}
#endif /* HAVE_LLVM_SUPPORT */

#ifdef HAVE_LIBBFD_SUPPORT
#define DISASM_SPACER "\t"

struct disasm_info {
	struct disassemble_info info;
	__u64 func_ksym;
};

static void disasm_print_addr(bfd_vma addr, struct disassemble_info *info)
{
	struct disasm_info *dinfo = container_of(info, struct disasm_info, info);

	addr += dinfo->func_ksym;
	generic_print_address(addr, info);
}

typedef struct {
	struct disasm_info *info;
	disassembler_ftype disassemble;
	bfd *bfdf;
} disasm_ctx_t;

static int get_exec_path(char *tpath, size_t size)
{
	const char *path = "/proc/self/exe";
	ssize_t len;

	len = readlink(path, tpath, size - 1);
	if (len <= 0)
		return -1;

	tpath[len] = 0;

	return 0;
}

static int printf_json(void *out, const char *fmt, va_list ap)
{
	char *s;
	int err;

	err = vasprintf(&s, fmt, ap);
	if (err < 0)
		return -1;

	if (!oper_count) {
		int i;

		/* Strip trailing spaces */
		i = strlen(s) - 1;
		while (s[i] == ' ')
			s[i--] = '\0';

		jsonw_string_field(json_wtr, "operation", s);
		jsonw_name(json_wtr, "operands");
		jsonw_start_array(json_wtr);
		oper_count++;
	} else if (!strcmp(fmt, ",")) {
		   /* Skip */
	} else {
		jsonw_string(json_wtr, s);
		oper_count++;
	}
	free(s);
	return 0;
}

static int fprintf_json(void *out, const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = printf_json(out, fmt, ap);
	va_end(ap);

	return r;
}

static int fprintf_json_styled(void *out,
			       enum disassembler_style style __maybe_unused,
			       const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = printf_json(out, fmt, ap);
	va_end(ap);

	return r;
}

static int init_context(disasm_ctx_t *ctx, const char *arch,
			const char *disassembler_options,
			unsigned char *image, ssize_t len, __u64 func_ksym)
{
	struct disassemble_info *info;
	char tpath[PATH_MAX];
	bfd *bfdf;

	memset(tpath, 0, sizeof(tpath));
	if (get_exec_path(tpath, sizeof(tpath))) {
		p_err("failed to create disassembler (get_exec_path)");
		return -1;
	}

	ctx->bfdf = bfd_openr(tpath, NULL);
	if (!ctx->bfdf) {
		p_err("failed to create disassembler (bfd_openr)");
		return -1;
	}
	if (!bfd_check_format(ctx->bfdf, bfd_object)) {
		p_err("failed to create disassembler (bfd_check_format)");
		goto err_close;
	}
	bfdf = ctx->bfdf;

	ctx->info = malloc(sizeof(struct disasm_info));
	if (!ctx->info) {
		p_err("mem alloc failed");
		goto err_close;
	}
	ctx->info->func_ksym = func_ksym;
	info = &ctx->info->info;

	if (json_output)
		init_disassemble_info_compat(info, stdout,
					     (fprintf_ftype) fprintf_json,
					     fprintf_json_styled);
	else
		init_disassemble_info_compat(info, stdout,
					     (fprintf_ftype) fprintf,
					     fprintf_styled);

	/* Update architecture info for offload. */
	if (arch) {
		const bfd_arch_info_type *inf = bfd_scan_arch(arch);

		if (inf) {
			bfdf->arch_info = inf;
		} else {
			p_err("No libbfd support for %s", arch);
			goto err_free;
		}
	}

	info->arch = bfd_get_arch(bfdf);
	info->mach = bfd_get_mach(bfdf);
	if (disassembler_options)
		info->disassembler_options = disassembler_options;
	info->buffer = image;
	info->buffer_length = len;
	info->print_address_func = disasm_print_addr;

	disassemble_init_for_target(info);

#ifdef DISASM_FOUR_ARGS_SIGNATURE
	ctx->disassemble = disassembler(info->arch,
					bfd_big_endian(bfdf),
					info->mach,
					bfdf);
#else
	ctx->disassemble = disassembler(bfdf);
#endif
	if (!ctx->disassemble) {
		p_err("failed to create disassembler");
		goto err_free;
	}
	return 0;

err_free:
	free(info);
err_close:
	bfd_close(ctx->bfdf);
	return -1;
}

static void destroy_context(disasm_ctx_t *ctx)
{
	free(ctx->info);
	bfd_close(ctx->bfdf);
}

static int
disassemble_insn(disasm_ctx_t *ctx, __maybe_unused unsigned char *image,
		 __maybe_unused ssize_t len, int pc,
		 __maybe_unused __u64 func_ksym)
{
	return ctx->disassemble(pc, &ctx->info->info);
}

int disasm_init(void)
{
	bfd_init();
	return 0;
}
#endif /* HAVE_LIBBPFD_SUPPORT */

int disasm_print_insn(unsigned char *image, ssize_t len, int opcodes,
		      const char *arch, const char *disassembler_options,
		      const struct btf *btf,
		      const struct bpf_prog_linfo *prog_linfo,
		      __u64 func_ksym, unsigned int func_idx,
		      bool linum)
{
	const struct bpf_line_info *linfo = NULL;
	unsigned int nr_skip = 0;
	int count, i;
	unsigned int pc = 0;
	disasm_ctx_t ctx;

	if (!len)
		return -1;

	if (init_context(&ctx, arch, disassembler_options, image, len, func_ksym))
		return -1;

	if (json_output)
		jsonw_start_array(json_wtr);
	do {
		if (prog_linfo) {
			linfo = bpf_prog_linfo__lfind_addr_func(prog_linfo,
								func_ksym + pc,
								func_idx,
								nr_skip);
			if (linfo)
				nr_skip++;
		}

		if (json_output) {
			jsonw_start_object(json_wtr);
			oper_count = 0;
			if (linfo)
				btf_dump_linfo_json(btf, linfo, linum);
			jsonw_name(json_wtr, "pc");
			jsonw_printf(json_wtr, "\"0x%x\"", pc);
		} else {
			if (linfo)
				btf_dump_linfo_plain(btf, linfo, "; ",
						     linum);
			printf("%4x:" DISASM_SPACER, pc);
		}

		count = disassemble_insn(&ctx, image, len, pc, func_ksym);

		if (json_output) {
			/* Operand array, was started in fprintf_json. Before
			 * that, make sure we have a _null_ value if no operand
			 * other than operation code was present.
			 */
			if (oper_count == 1)
				jsonw_null(json_wtr);
			jsonw_end_array(json_wtr);
		}

		if (opcodes) {
			if (json_output) {
				jsonw_name(json_wtr, "opcodes");
				jsonw_start_array(json_wtr);
				for (i = 0; i < count; ++i)
					jsonw_printf(json_wtr, "\"0x%02hhx\"",
						     (uint8_t)image[pc + i]);
				jsonw_end_array(json_wtr);
			} else {
				printf("\n\t");
				for (i = 0; i < count; ++i)
					printf("%02x ",
					       (uint8_t)image[pc + i]);
			}
		}
		if (json_output)
			jsonw_end_object(json_wtr);
		else
			printf("\n");

		pc += count;
	} while (count > 0 && pc < len);
	if (json_output)
		jsonw_end_array(json_wtr);

	destroy_context(&ctx);

	return 0;
}
