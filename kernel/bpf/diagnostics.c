// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/stdarg.h>
#include <linux/string.h>

#include "disasm.h"
#include "diagnostics.h"

#define CATEGORY_MEMORY_SAFETY "Memory Safety"
#define CATEGORY_REGISTER_TYPE_SAFETY "Register Type Safety"
#define CATEGORY_CALL_TYPE_SAFETY "Call Type Safety"
#define CATEGORY_RESOURCE_LIFETIME_SAFETY "Resource Lifetime Safety"
#define CATEGORY_EXECUTION_CONTEXT_SAFETY "Execution Context Safety"
#define CATEGORY_PROGRAM_STRUCTURE "Program Structure"
#define CATEGORY_POLICY "Policy"
#define CATEGORY_VERIFIER_LIMIT "Verifier Limit"
#define CATEGORY_VERIFIER_INTERNAL_ERROR "Verifier Internal Error"

#define BPF_DIAG_TEXT_WIDTH 100
#define BPF_DIAG_TEXT_INDENT "  "
#define BPF_DIAG_MSG_LEN 512
#define BPF_DIAG_CONTEXT 2
#define BPF_DIAG_CONTEXT_CNT (1 + BPF_DIAG_CONTEXT * 2)
#define BPF_DIAG_SOURCE_LANE_WIDTH 88
#define BPF_DIAG_TAB_WIDTH 8
#define BPF_DIAG_REG_DESC_LEN 512
#define BPF_DIAG_REG_TMP_LEN 192
#define BPF_DIAG_SCRATCH_STR_CNT 3
#define BPF_DIAG_SCRATCH_STR_LEN 256
#define BPF_DIAG_TEXT_LEN 160

struct bpf_diag_source_line {
	const char *line;
	int line_num;
};

struct bpf_diag_insn {
	char text[BPF_DIAG_TEXT_LEN];
	int idx;
	bool valid;
};

struct bpf_diag_insn_buf {
	char *buf;
	size_t size;
	size_t len;
};

struct bpf_diag_insn_ctx {
	struct bpf_verifier_env *env;
	struct bpf_diag_insn_buf buf;
};

struct bpf_diag_scratch {
	char str[BPF_DIAG_SCRATCH_STR_CNT][BPF_DIAG_SCRATCH_STR_LEN];
	struct bpf_linfo_source source;
	struct bpf_diag_source_line source_lines[BPF_DIAG_CONTEXT_CNT];
	struct bpf_diag_insn insns[BPF_DIAG_CONTEXT_CNT];
};

struct bpf_diag {
	struct bpf_diag_scratch scratch;
};

bool bpf_diag_enabled(const struct bpf_verifier_env *env)
{
	return env->log.level & BPF_LOG_LEVEL;
}

static struct bpf_diag *diag_env(struct bpf_verifier_env *env)
{
	return env->diag;
}

int bpf_diag_init(struct bpf_verifier_env *env)
{
	if (!bpf_diag_enabled(env))
		return 0;

	env->diag = kzalloc_obj(struct bpf_diag, GFP_KERNEL_ACCOUNT);
	return env->diag ? 0 : -ENOMEM;
}

static struct bpf_diag_scratch *diag_scratch(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = diag_env(env);

	return diag ? &diag->scratch : NULL;
}

char *bpf_diag_scratch_buf(struct bpf_verifier_env *env, unsigned int slot, size_t *size)
{
	struct bpf_diag_scratch *scratch = diag_scratch(env);
	char *buf = NULL;
	size_t buf_size = 0;

	if (!scratch)
		goto out;

	if ((unsigned int)slot >= BPF_DIAG_SCRATCH_STR_CNT)
		goto out;

	buf = scratch->str[slot];
	buf_size = sizeof(scratch->str[slot]);

out:
	if (size)
		*size = buf_size;
	return buf;
}

const char *bpf_diag_scratch_strcpy(struct bpf_verifier_env *env, unsigned int slot,
				    const char *str)
{
	size_t size;
	char *buf = bpf_diag_scratch_buf(env, slot, &size);

	if (!buf)
		return "";
	strscpy(buf, str ?: "", size);
	return buf;
}

const char *bpf_diag_scratch_printf(struct bpf_verifier_env *env, unsigned int slot,
				    const char *fmt, ...)
{
	size_t size;
	va_list args;
	char *buf = bpf_diag_scratch_buf(env, slot, &size);

	if (!buf)
		return "";

	va_start(args, fmt);
	vscnprintf(buf, size, fmt, args);
	va_end(args);
	return buf;
}

void bpf_diag_free(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = env->diag;

	if (!diag)
		return;

	kfree(diag);
	env->diag = NULL;
}

static void diag_log(struct bpf_verifier_env *env, const char *fmt, ...)
{
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(&env->log, fmt, args);
	va_end(args);
}

static void diag_print_wrapped_prefixed(struct bpf_verifier_env *env, const char *first_prefix,
					const char *next_prefix, const char *text)
{
	const char *prefix = first_prefix;

	while (*text) {
		const char *line = text;
		int prefix_len = strlen(prefix);
		int text_width = BPF_DIAG_TEXT_WIDTH - prefix_len;
		int len = 0, last_space = -1;

		if (text_width < 1)
			text_width = 1;

		while (line[len] && line[len] != '\n' && len < text_width) {
			if (line[len] == ' ')
				last_space = len;
			len++;
		}

		if (line[len] && line[len] != '\n' && line[len] != ' ' && last_space > 0)
			len = last_space;

		diag_log(env, "%s%.*s\n", prefix, len, line);

		text = line + len;
		while (*text == ' ')
			text++;
		if (*text == '\n')
			text++;

		prefix = next_prefix;
	}
}

static void diag_print_wrapped_text(struct bpf_verifier_env *env, const char *text)
{
	diag_print_wrapped_prefixed(env, BPF_DIAG_TEXT_INDENT, BPF_DIAG_TEXT_INDENT, text);
}

static void diag_vprint_indented(struct bpf_verifier_env *env, const char *fmt, va_list args)
{
	char *buf;

	if (!bpf_diag_enabled(env))
		return;

	buf = kvasprintf(GFP_KERNEL_ACCOUNT, fmt, args);
	if (!buf) {
		diag_log(env, "%s<failed to allocate diagnostic text>\n", BPF_DIAG_TEXT_INDENT);
		return;
	}

	diag_print_wrapped_text(env, buf);
	kfree(buf);
}

static int diag_line_width(unsigned int line)
{
	int width = 1;

	while (line >= 10) {
		line /= 10;
		width++;
	}

	return width;
}

static const char *diag_func_name(struct bpf_verifier_env *env, u32 insn_idx)
{
	const struct bpf_subprog_info *subprog;
	int subprogno;

	subprog = bpf_find_containing_subprog(env, insn_idx);
	if (!subprog)
		return NULL;

	subprogno = subprog - env->subprog_info;
	return bpf_verifier_subprog_name(env, subprogno);
}

static bool diag_fill_source(struct bpf_verifier_env *env, const struct bpf_line_info *linfo,
			     struct bpf_linfo_source *src)
{
	if (!env->prog->aux->btf)
		return false;

	bpf_get_linfo_source(env->prog->aux->btf, linfo, src, 0);
	return src->file && *src->file && src->line && *src->line;
}

static bool diag_get_source(struct bpf_verifier_env *env, u32 insn_idx,
			    struct bpf_linfo_source *src)
{
	const struct bpf_line_info *linfo;

	linfo = bpf_find_linfo(env->prog, insn_idx);
	if (!linfo)
		return false;

	return diag_fill_source(env, linfo, src);
}

static void diag_fill_source_lines(struct bpf_verifier_env *env, const struct bpf_linfo_source *src,
				   int start_line, int end_line, struct bpf_diag_source_line *lines)
{
	const struct bpf_line_info *linfo = env->prog->aux->linfo;
	struct btf *btf = env->prog->aux->btf;
	u32 i;

	for (i = 0; i < BPF_DIAG_CONTEXT_CNT; i++)
		lines[i].line_num = start_line + i;

	if (!btf || !env->prog->aux->nr_linfo)
		return;

	for (i = 0; i < env->prog->aux->nr_linfo; i++) {
		struct bpf_linfo_source line_src;
		int idx;

		bpf_get_linfo_source(btf, &linfo[i], &line_src, 0);
		if (line_src.file_name_off != src->file_name_off ||
		    line_src.line_num < start_line || line_src.line_num > end_line ||
		    !line_src.line || !*line_src.line)
			continue;

		idx = line_src.line_num - start_line;
		if (!lines[idx].line)
			lines[idx].line = line_src.line;
	}
}

static int diag_line_indent(const char *line)
{
	int indent = 0;

	while (*line == ' ' || *line == '\t') {
		if (*line == '\t')
			indent = round_up(indent + 1, BPF_DIAG_TAB_WIDTH);
		else
			indent++;
		line++;
	}

	return indent;
}

static void diag_insn_print(void *private_data, const char *fmt, ...)
{
	struct bpf_diag_insn_ctx *ctx = private_data;
	struct bpf_diag_insn_buf *buf = &ctx->buf;
	va_list args;

	if (buf->len >= buf->size)
		return;

	va_start(args, fmt);
	buf->len += vscnprintf(buf->buf + buf->len, buf->size - buf->len, fmt, args);
	va_end(args);
}

static const char *diag_disasm_kfunc_name(void *private_data, const struct bpf_insn *insn)
{
	struct bpf_diag_insn_ctx *ctx = private_data;

	return bpf_disasm_kfunc_name(ctx->env, insn);
}

static void diag_format_insn(struct bpf_verifier_env *env, int insn_idx,
			     struct bpf_diag_insn *diag_insn)
{
	struct bpf_insn *insn;
	struct bpf_diag_insn_ctx ctx = {
		.env = env,
		.buf = {
			.buf = diag_insn->text,
			.size = sizeof(diag_insn->text),
		},
	};
	const struct bpf_insn_cbs cbs = {
		.cb_call = diag_disasm_kfunc_name,
		.cb_print = diag_insn_print,
		.private_data = &ctx,
	};

	diag_insn->idx = insn_idx;
	diag_insn->valid = false;
	diag_insn->text[0] = '\0';

	if (insn_idx < 0 || insn_idx >= env->prog->len)
		return;

	if (insn_idx > 0 && bpf_is_ldimm64(&env->prog->insnsi[insn_idx - 1]))
		return;

	insn = &env->prog->insnsi[insn_idx];
	if (bpf_is_ldimm64(insn) && insn_idx + 1 >= env->prog->len)
		return;

	print_bpf_insn(&cbs, insn, env->allow_ptr_leaks);
	while (ctx.buf.len && diag_insn->text[ctx.buf.len - 1] == '\n')
		diag_insn->text[--ctx.buf.len] = '\0';

	diag_insn->valid = true;
}

static void diag_format_source_text(char *buf, size_t size, const char *line, int width)
{
	int col = 0, len = 0;

	if (!size)
		return;
	if (width <= 0) {
		buf[0] = '\0';
		return;
	}

	line = line ?: "...";
	while (*line && col < width && len + 1 < size) {
		if (*line == '\t') {
			int next = round_up(col + 1, BPF_DIAG_TAB_WIDTH);

			while (col < next && col < width && len + 1 < size) {
				buf[len++] = ' ';
				col++;
			}
			line++;
			continue;
		}

		buf[len++] = *line++;
		col++;
	}

	if (*line) {
		int ellipsis_len = min(3, width);

		while (len > 0 && col > width - ellipsis_len) {
			len--;
			col--;
		}
		while (ellipsis_len-- && len + 1 < size)
			buf[len++] = '.';
	}

	buf[len] = '\0';
}

static void diag_format_source_lane(char *buf, size_t size, const char *source_prefix,
				    int source_line_width, int line_num, const char *line)
{
	int len, text_width;

	if (line_num <= 0) {
		buf[0] = '\0';
		return;
	}

	len = scnprintf(buf, size, "%s%*d | ", source_prefix, source_line_width, line_num);
	if (len >= (int)size)
		return;

	text_width = BPF_DIAG_SOURCE_LANE_WIDTH - len;
	diag_format_source_text(buf + len, size - len, line, text_width);
}

static void diag_print_source_line(struct bpf_verifier_env *env, const char *source_prefix,
				   int source_line_width, const struct bpf_diag_source_line *line)
{
	size_t source_lane_size;
	char *source_lane;

	source_lane = bpf_diag_scratch_buf(env, 0, &source_lane_size);
	diag_format_source_lane(source_lane, source_lane_size, source_prefix, source_line_width,
				line->line_num, line->line);
	diag_write(env, "  %s\n", source_lane);
}

static void diag_print_insn_line(struct bpf_verifier_env *env,
				 const struct bpf_diag_insn *diag_insn, int focus_insn_idx,
				 int insn_width)
{
	if (!diag_insn->valid)
		return;
	diag_write(env, "  %s%*d | %s\n", diag_insn->idx == focus_insn_idx ? ">>> " : "    ",
		   insn_width, diag_insn->idx, diag_insn->text);
}

void bpf_diag_report_header(struct bpf_verifier_env *env, const char *category, const char *problem)
{
	char first;

	if (!bpf_diag_enabled(env))
		return;

	category = category ?: CATEGORY_VERIFIER_INTERNAL_ERROR;
	problem = problem ?: "";

	if (!problem[0]) {
		diag_log(env, "\nVerification failed: %s\n", category);
		return;
	}

	first = toupper(problem[0]);
	diag_log(env, "\nVerification failed: %s: %c%s\n", category, first, problem + 1);
}

static void diag_report_reason(struct bpf_verifier_env *env, const char *fmt, ...) __printf(2, 3);
static void diag_report_suggestion(struct bpf_verifier_env *env, const char *fmt, ...)
	__printf(2, 3);

static void diag_report_section(struct bpf_verifier_env *env, const char *title)
{
	if (!bpf_diag_enabled(env))
		return;

	diag_log(env, "\n%s:\n", title);
}

static void diag_report_reason(struct bpf_verifier_env *env, const char *fmt, ...)
{
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	diag_report_section(env, "Reason");

	va_start(args, fmt);
	diag_vprint_indented(env, fmt, args);
	va_end(args);
}

static void diag_report_suggestion(struct bpf_verifier_env *env, const char *fmt, ...)
{
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	diag_report_section(env, "Suggestion");

	va_start(args, fmt);
	diag_vprint_indented(env, fmt, args);
	va_end(args);
	diag_log(env, "\n");
}

static void diag_print_source_annotation(struct bpf_verifier_env *env, int line_width, int indent,
					 const char *label, const char *msg)
{
	size_t first_prefix_size, next_prefix_size;
	char *first_prefix, *next_prefix;
	char *text;

	first_prefix = bpf_diag_scratch_buf(env, 0, &first_prefix_size);
	next_prefix = bpf_diag_scratch_buf(env, 1, &next_prefix_size);
	indent = min_t(int, indent, max_t(int, 0, BPF_DIAG_SOURCE_LANE_WIDTH - line_width - 8));
	text = kasprintf(GFP_KERNEL_ACCOUNT, "%s: %s", label, msg);
	if (!text) {
		diag_write(env, "  %*s | %*s^-- %s: %s\n", line_width + 4, "", indent, "", label,
			   msg);
		return;
	}

	scnprintf(first_prefix, first_prefix_size, "  %*s | %*s^-- ", line_width + 4, "", indent,
		  "");
	scnprintf(next_prefix, next_prefix_size, "  %*s | %*s    ", line_width + 4, "", indent, "");

	diag_print_wrapped_prefixed(env, first_prefix, next_prefix, text);
	kfree(text);
}

void bpf_diag_report_source(struct bpf_verifier_env *env, u32 insn_idx, const char *label,
			    const char *fmt, ...)
{
	struct bpf_diag_scratch *scratch;
	struct bpf_diag_source_line *source_lines;
	struct bpf_diag_insn *diag_insn;
	struct bpf_linfo_source *src;
	char *msg;
	const char *func;
	int start_line, end_line, width, indent, insn_width, i;
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	va_start(args, fmt);
	msg = kvasprintf(GFP_KERNEL_ACCOUNT, fmt, args);
	va_end(args);
	if (!msg)
		msg = kstrdup("<failed to allocate diagnostic text>", GFP_KERNEL_ACCOUNT);
	if (!msg)
		return;

	label = label ?: "note";
	scratch = diag_scratch(env);

	src = &scratch->source;
	source_lines = scratch->source_lines;
	diag_insn = scratch->insns;
	memset(source_lines, 0, sizeof(scratch->source_lines));
	memset(diag_insn, 0, sizeof(scratch->insns));

	if (!diag_get_source(env, insn_idx, src)) {
		diag_log(env, "  insn %u\n", insn_idx);
		diag_print_source_annotation(env, 0, 0, label, msg);
		goto out_free_msg;
	}

	func = diag_func_name(env, insn_idx);
	if (func && *func)
		diag_log(env, "  %s @ %s:%d:%d\n", func, src->file, src->line_num, src->line_col);
	else
		diag_log(env, "  %s:%d:%d\n", src->file, src->line_num, src->line_col);

	start_line = src->line_num - BPF_DIAG_CONTEXT;
	end_line = src->line_num + BPF_DIAG_CONTEXT;
	width = diag_line_width(end_line);
	indent = diag_line_indent(src->line);
	insn_width = diag_line_width(env->prog->len ? env->prog->len - 1 : 0);
	diag_fill_source_lines(env, src, start_line, end_line, source_lines);

	for (i = 0; i < BPF_DIAG_CONTEXT_CNT; i++) {
		int row = i - BPF_DIAG_CONTEXT;

		diag_format_insn(env, insn_idx + row, &diag_insn[i]);
	}

	/*
	 * Source lines and BPF instructions are independent context windows.
	 * Only their focused entries describe the same location, so render
	 * separate blocks instead of pairing neighboring rows.
	 */
	diag_write(env, "  Source context:\n");
	for (i = 0; i < BPF_DIAG_CONTEXT_CNT; i++) {
		const char *source_prefix;

		source_prefix = source_lines[i].line_num == src->line_num ? ">>> " : "    ";
		diag_print_source_line(env, source_prefix, width, &source_lines[i]);
		if (source_lines[i].line_num == src->line_num)
			diag_print_source_annotation(env, width, indent, label, msg);
	}
	diag_write(env, "  Instruction context:\n");
	for (i = 0; i < BPF_DIAG_CONTEXT_CNT; i++)
		diag_print_insn_line(env, &diag_insn[i], insn_idx, insn_width);

out_free_msg:
	kfree(msg);
}
