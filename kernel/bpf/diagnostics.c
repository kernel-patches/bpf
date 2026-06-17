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

#define BPF_DIAG_CATEGORY_MEMORY_SAFETY "Memory Safety"
#define BPF_DIAG_CATEGORY_REGISTER_TYPE_SAFETY "Register Type Safety"
#define BPF_DIAG_CATEGORY_CALL_TYPE_SAFETY "Call Type Safety"
#define BPF_DIAG_CATEGORY_RESOURCE_LIFETIME_SAFETY "Resource Lifetime Safety"
#define BPF_DIAG_CATEGORY_EXECUTION_CONTEXT_SAFETY "Execution Context Safety"
#define BPF_DIAG_CATEGORY_PROGRAM_STRUCTURE "Program Structure"
#define BPF_DIAG_CATEGORY_POLICY "Policy"
#define BPF_DIAG_CATEGORY_VERIFIER_LIMIT "Verifier Limit"
#define BPF_DIAG_CATEGORY_VERIFIER_INTERNAL_ERROR "Verifier Internal Error"

#define BPF_DIAG_TEXT_WIDTH 100
#define BPF_DIAG_TEXT_INDENT "  "
#define BPF_DIAG_MSG_LEN 512
#define BPF_DIAG_SOURCE_CONTEXT 2
#define BPF_DIAG_SOURCE_LINE_CNT (1 + BPF_DIAG_SOURCE_CONTEXT * 2)
#define BPF_DIAG_INSN_CONTEXT 2
#define BPF_DIAG_INSN_CNT (1 + BPF_DIAG_INSN_CONTEXT * 2)
#define BPF_DIAG_COLUMN_GAP 3
#define BPF_DIAG_SOURCE_LANE_WIDTH 88
#define BPF_DIAG_TAB_WIDTH 8
#define BPF_DIAG_REG_DESC_LEN 512
#define BPF_DIAG_REG_TMP_LEN 192
#define BPF_DIAG_SCRATCH_STR_CNT 3
#define BPF_DIAG_SCRATCH_STR_LEN 256
#define BPF_DIAG_TEXT_LEN 160

struct bpf_diag_source {
	const char *file;
	const char *line;
	u32 file_name_off;
	int line_num;
	int line_col;
};

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
	struct bpf_diag_source source;
	struct bpf_diag_source_line source_lines[BPF_DIAG_SOURCE_LINE_CNT];
	struct bpf_diag_insn insns[BPF_DIAG_INSN_CNT];
};

struct bpf_diag {
	struct bpf_diag_scratch scratch;
};

bool bpf_diag_enabled(const struct bpf_verifier_env *env)
{
	return env->log.level & BPF_LOG_LEVEL;
}

static struct bpf_diag *bpf_diag_env(struct bpf_verifier_env *env)
{
	if (!bpf_diag_enabled(env))
		return NULL;
	if (env->diag)
		return env->diag;

	env->diag = kzalloc_obj(struct bpf_diag, GFP_KERNEL_ACCOUNT);
	return env->diag;
}

static struct bpf_diag_scratch *bpf_diag_scratch(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = bpf_diag_env(env);

	return diag ? &diag->scratch : NULL;
}

char *bpf_diag_scratch_buf(struct bpf_verifier_env *env,
			   unsigned int slot, size_t *size)
{
	struct bpf_diag_scratch *scratch = bpf_diag_scratch(env);
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

const char *bpf_diag_scratch_strcpy(struct bpf_verifier_env *env,
				    unsigned int slot,
				    const char *str)
{
	size_t size;
	char *buf = bpf_diag_scratch_buf(env, slot, &size);

	if (!buf)
		return "";
	strscpy(buf, str ?: "", size);
	return buf;
}

const char *bpf_diag_scratch_printf(struct bpf_verifier_env *env,
				    unsigned int slot,
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

static void bpf_diag_log(struct bpf_verifier_env *env, const char *fmt, ...)
{
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(&env->log, fmt, args);
	va_end(args);
}
static void bpf_diag_print_wrapped_prefixed(struct bpf_verifier_env *env,
					    const char *first_prefix,
					    const char *next_prefix,
					    const char *text)
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

		if (line[len] && line[len] != '\n' && line[len] != ' ' &&
		    last_space > 0)
			len = last_space;

		bpf_diag_log(env, "%s%.*s\n", prefix, len, line);

		text = line + len;
		while (*text == ' ')
			text++;
		if (*text == '\n')
			text++;

		prefix = next_prefix;
	}
}

static void bpf_diag_print_wrapped_text(struct bpf_verifier_env *env,
					const char *text)
{
	bpf_diag_print_wrapped_prefixed(env, BPF_DIAG_TEXT_INDENT,
					BPF_DIAG_TEXT_INDENT, text);
}

static void bpf_diag_vprint_indented(struct bpf_verifier_env *env,
				     const char *fmt, va_list args)
{
	char *buf;

	if (!bpf_diag_enabled(env))
		return;

	buf = kvasprintf(GFP_KERNEL_ACCOUNT, fmt, args);
	if (!buf) {
		bpf_diag_log(env, "%s<failed to allocate diagnostic text>\n",
			     BPF_DIAG_TEXT_INDENT);
		return;
	}

	bpf_diag_print_wrapped_text(env, buf);
	kfree(buf);
}

static int bpf_diag_line_width(unsigned int line)
{
	int width = 1;

	while (line >= 10) {
		line /= 10;
		width++;
	}

	return width;
}

static const char *bpf_diag_func_name(struct bpf_verifier_env *env, u32 insn_idx)
{
	const struct bpf_subprog_info *subprog;
	const struct bpf_func_info *info;
	const struct btf_type *type;
	int subprogno;

	subprog = bpf_find_containing_subprog(env, insn_idx);
	if (!subprog)
		return NULL;
	if (subprog->name && *subprog->name)
		return subprog->name;

	if (!env->prog->aux->func_info || !env->prog->aux->btf)
		return NULL;

	subprogno = subprog - env->subprog_info;
	if (subprogno < 0 || subprogno >= env->prog->aux->func_info_cnt)
		return NULL;

	info = &env->prog->aux->func_info[subprogno];
	type = btf_type_by_id(env->prog->aux->btf, info->type_id);
	if (!type)
		return NULL;

	return btf_name_by_offset(env->prog->aux->btf, type->name_off);
}

static bool bpf_diag_fill_source(struct bpf_verifier_env *env,
				 const struct bpf_line_info *linfo,
				 struct bpf_diag_source *src)
{
	const char *file, *line;
	int line_num;

	if (!env->prog->aux->btf)
		return false;

	bpf_get_linfo_file_line(env->prog->aux->btf, linfo, &file, &line,
				&line_num, 0);
	if (!file || !*file || !line || !*line)
		return false;

	src->file = file;
	src->line = line;
	src->file_name_off = linfo->file_name_off;
	src->line_num = line_num;
	src->line_col = BPF_LINE_INFO_LINE_COL(linfo->line_col);
	return true;
}

static bool bpf_diag_get_source(struct bpf_verifier_env *env, u32 insn_idx,
				struct bpf_diag_source *src)
{
	const struct bpf_line_info *linfo;

	linfo = bpf_find_linfo(env->prog, insn_idx);
	if (!linfo)
		return false;

	return bpf_diag_fill_source(env, linfo, src);
}

static void bpf_diag_fill_source_lines(struct bpf_verifier_env *env,
				       const struct bpf_diag_source *src,
				       int start_line, int end_line,
				       struct bpf_diag_source_line *lines)
{
	const struct bpf_line_info *linfo = env->prog->aux->linfo;
	struct btf *btf = env->prog->aux->btf;
	u32 i;

	for (i = 0; i < BPF_DIAG_SOURCE_LINE_CNT; i++)
		lines[i].line_num = start_line + i;

	if (!btf || !env->prog->aux->nr_linfo)
		return;

	for (i = 0; i < env->prog->aux->nr_linfo; i++) {
		const char *file, *line;
		int line_num, idx;

		if (linfo[i].file_name_off != src->file_name_off)
			continue;

		bpf_get_linfo_file_line(btf, &linfo[i], &file, &line,
					&line_num, 0);
		if (line_num < start_line || line_num > end_line)
			continue;

		idx = line_num - start_line;
		if (lines[idx].line)
			continue;
		if (line && *line)
			lines[idx].line = line;
	}
}

static int bpf_diag_line_indent(const char *line)
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

static void bpf_diag_insn_print(void *private_data, const char *fmt, ...)
{
	struct bpf_diag_insn_ctx *ctx = private_data;
	struct bpf_diag_insn_buf *buf = &ctx->buf;
	va_list args;

	if (buf->len >= buf->size)
		return;

	va_start(args, fmt);
	buf->len += vscnprintf(buf->buf + buf->len, buf->size - buf->len,
			       fmt, args);
	va_end(args);
}

static const char *bpf_diag_disasm_kfunc_name(void *private_data,
					      const struct bpf_insn *insn)
{
	struct bpf_diag_insn_ctx *ctx = private_data;

	return bpf_disasm_kfunc_name(ctx->env, insn);
}

static void bpf_diag_format_insn(struct bpf_verifier_env *env, int insn_idx,
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
		.cb_call = bpf_diag_disasm_kfunc_name,
		.cb_print = bpf_diag_insn_print,
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

static void bpf_diag_format_source_text(char *buf, size_t size,
					const char *line, int width)
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
		while (ellipsis_len-- && len + 1 < size) {
			buf[len++] = '.';
			col++;
		}
	}

	buf[len] = '\0';
}

static void bpf_diag_format_source_lane(char *buf, size_t size,
					const char *source_prefix,
					int source_line_width,
					int line_num, const char *line)
{
	int len, text_width;

	if (line_num <= 0) {
		buf[0] = '\0';
		return;
	}

	len = scnprintf(buf, size, "%s%*d | ",
			source_prefix, source_line_width, line_num);
	if (len >= (int)size)
		return;

	text_width = BPF_DIAG_SOURCE_LANE_WIDTH - len;
	bpf_diag_format_source_text(buf + len, size - len, line, text_width);
}

static void bpf_diag_print_source_insn_line(struct bpf_verifier_env *env,
					    const char *source_prefix,
					    int source_line_width,
					    const struct bpf_diag_source_line *line,
					    const struct bpf_diag_insn *diag_insn,
					    int focus_insn_idx,
					    int insn_width)
{
	size_t source_lane_size;
	char *source_lane;

	source_lane = bpf_diag_scratch_buf(env, 0,
					   &source_lane_size);
	if (!source_lane)
		return;

	bpf_diag_format_source_lane(source_lane, source_lane_size,
				    source_prefix, source_line_width,
				    line->line_num, line->line);

	bpf_diag_log(env, "  %-*s%*s", BPF_DIAG_SOURCE_LANE_WIDTH,
		     source_lane, BPF_DIAG_COLUMN_GAP, "");
	if (diag_insn->valid)
		bpf_diag_log(env, "%s%*d | %s",
			     diag_insn->idx == focus_insn_idx ? ">>> " : "    ",
			     insn_width, diag_insn->idx, diag_insn->text);
	bpf_diag_log(env, "\n");
}

void bpf_diag_report_header(struct bpf_verifier_env *env,
			    const char *category, const char *problem)
{
	char first;

	if (!bpf_diag_enabled(env))
		return;

	category = category ?: BPF_DIAG_CATEGORY_VERIFIER_INTERNAL_ERROR;
	problem = problem ?: "";

	if (!problem[0]) {
		bpf_diag_log(env, "\nVerification failed: %s\n", category);
		return;
	}

	first = toupper(problem[0]);
	bpf_diag_log(env, "\nVerification failed: %s: %c%s\n", category,
		     first, problem + 1);
}

static void bpf_diag_report_reason(struct bpf_verifier_env *env,
				   const char *fmt, ...) __printf(2, 3);
static void bpf_diag_report_suggestion(struct bpf_verifier_env *env,
				       const char *fmt, ...) __printf(2, 3);

static void bpf_diag_report_section(struct bpf_verifier_env *env,
				    const char *title)
{
	if (!bpf_diag_enabled(env))
		return;

	bpf_diag_log(env, "\n%s:\n", title);
}

static void bpf_diag_report_reason(struct bpf_verifier_env *env,
				   const char *fmt, ...)
{
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	bpf_diag_report_section(env, "Reason");

	va_start(args, fmt);
	bpf_diag_vprint_indented(env, fmt, args);
	va_end(args);
}

static void bpf_diag_report_suggestion(struct bpf_verifier_env *env,
				       const char *fmt, ...)
{
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	bpf_diag_report_section(env, "Suggestion");

	va_start(args, fmt);
	bpf_diag_vprint_indented(env, fmt, args);
	va_end(args);
	bpf_diag_log(env, "\n");
}

static void bpf_diag_print_source_annotation(struct bpf_verifier_env *env,
					     int line_width, int indent,
					     const char *label,
					     const char *msg)
{
	size_t first_prefix_size, next_prefix_size;
	char *first_prefix, *next_prefix;
	char *text;

	first_prefix = bpf_diag_scratch_buf(env, 0,
					    &first_prefix_size);
	next_prefix = bpf_diag_scratch_buf(env,
					   1,
					   &next_prefix_size);
	if (!first_prefix || !next_prefix)
		return;

	indent = min_t(int, indent,
		       max_t(int, 0, BPF_DIAG_SOURCE_LANE_WIDTH -
			     line_width - 8));
	text = kasprintf(GFP_KERNEL_ACCOUNT, "%s: %s", label, msg);
	if (!text) {
		bpf_diag_log(env, "  %*s | %*s^-- %s\n",
			     line_width + 4, "", indent, "", label);
		return;
	}

	scnprintf(first_prefix, first_prefix_size, "  %*s | %*s^-- ",
		  line_width + 4, "", indent, "");
	scnprintf(next_prefix, next_prefix_size, "  %*s | %*s    ",
		  line_width + 4, "", indent, "");

	bpf_diag_print_wrapped_prefixed(env, first_prefix, next_prefix, text);
	kfree(text);
}

void bpf_diag_report_source(struct bpf_verifier_env *env, u32 insn_idx,
			    const char *label, const char *fmt, ...)
{
	struct bpf_diag_scratch *scratch;
	struct bpf_diag_source_line *source_lines;
	struct bpf_diag_insn *diag_insn;
	struct bpf_diag_source *src;
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
		msg = kstrdup("<failed to allocate diagnostic text>",
			      GFP_KERNEL_ACCOUNT);
	if (!msg)
		return;

	label = label ?: "note";
	scratch = bpf_diag_scratch(env);
	if (!scratch)
		goto out_free_msg;

	src = &scratch->source;
	source_lines = scratch->source_lines;
	diag_insn = scratch->insns;
	memset(source_lines, 0, sizeof(scratch->source_lines));
	memset(diag_insn, 0, sizeof(scratch->insns));

	if (!bpf_diag_get_source(env, insn_idx, src)) {
		bpf_diag_log(env, "  insn %u\n", insn_idx);
		bpf_diag_print_source_annotation(env, 0, 0, label, msg);
		goto out_free_msg;
	}

	func = bpf_diag_func_name(env, insn_idx);
	if (func && *func)
		bpf_diag_log(env, "  %s @ %s:%d:%d\n", func, src->file,
			     src->line_num, src->line_col);
	else
		bpf_diag_log(env, "  %s:%d:%d\n", src->file, src->line_num,
			     src->line_col);

	start_line = src->line_num - BPF_DIAG_SOURCE_CONTEXT;
	end_line = src->line_num + BPF_DIAG_SOURCE_CONTEXT;
	width = bpf_diag_line_width(end_line);
	indent = bpf_diag_line_indent(src->line);
	insn_width = bpf_diag_line_width(env->prog->len ? env->prog->len - 1 : 0);
	bpf_diag_fill_source_lines(env, src, start_line, end_line,
				   source_lines);

	for (i = 0; i < BPF_DIAG_INSN_CNT; i++) {
		int row = i - BPF_DIAG_INSN_CONTEXT;

		bpf_diag_format_insn(env, insn_idx + row, &diag_insn[i]);
	}

	for (i = 0; i < BPF_DIAG_SOURCE_LINE_CNT; i++) {
		const char *source_prefix;

		source_prefix = source_lines[i].line_num == src->line_num ?
				">>> " : "    ";
		bpf_diag_print_source_insn_line(env, source_prefix, width,
						&source_lines[i],
						&diag_insn[i],
						insn_idx, insn_width);
		if (source_lines[i].line_num == src->line_num)
			bpf_diag_print_source_annotation(env, width, indent,
							 label, msg);
	}

out_free_msg:
	kfree(msg);
}
