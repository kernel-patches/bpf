// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/overflow.h>
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

struct bpf_diag_log {
	struct bpf_diag_history_event *events;
	u32 cnt;
	u32 cap;
};

struct bpf_diag_reg_fmt {
	char old_buf[BPF_DIAG_REG_DESC_LEN];
	char new_buf[BPF_DIAG_REG_DESC_LEN];
	char offset_desc[BPF_DIAG_REG_DESC_LEN];
	char btf_type[BPF_DIAG_REG_TMP_LEN];
	char range[BPF_DIAG_REG_TMP_LEN];
	char smin_buf[32];
	char smax_buf[32];
	char umin_buf[32];
	char umax_buf[32];
};

struct bpf_diag_scratch {
	char str[BPF_DIAG_SCRATCH_STR_CNT][BPF_DIAG_SCRATCH_STR_LEN];
	struct bpf_diag_source source;
	struct bpf_diag_source_line source_lines[BPF_DIAG_SOURCE_LINE_CNT];
	struct bpf_diag_insn insns[BPF_DIAG_INSN_CNT];
	struct bpf_diag_reg_fmt reg_fmt;
};

struct bpf_diag {
	struct bpf_diag_log log;
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

static void bpf_diag_write(struct bpf_verifier_env *env, const char *fmt, ...)
{
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(&env->log, fmt, args);
	va_end(args);
}

static struct bpf_diag_log *bpf_diag_event_log(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = bpf_diag_env(env);

	return diag ? &diag->log : NULL;
}

u64 bpf_diag_event_log_pos(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = bpf_diag_env(env);

	if (!diag)
		return 0;
	return diag->log.cnt;
}

void bpf_diag_event_log_reset(struct bpf_verifier_env *env, u64 pos)
{
	struct bpf_diag *diag = env->diag;
	struct bpf_diag_log *log;
	u64 end;

	if (!diag)
		return;

	log = &diag->log;
	end = log->cnt;
	if (WARN_ON_ONCE(pos > end))
		pos = end;

	log->cnt = pos;
}

void bpf_diag_free(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = env->diag;

	if (!diag)
		return;

	kfree(diag->log.events);
	kfree(diag);
	env->diag = NULL;
}

static const struct bpf_diag_history_event *
bpf_diag_history_event(const struct bpf_diag_log *log, u32 idx)
{
	return &log->events[idx];
}

static void bpf_diag_append_history(struct bpf_verifier_env *env,
				    const struct bpf_diag_history_event *event)
{
	struct bpf_diag_history_event *events;
	struct bpf_diag_log *log;
	u32 cap;

	log = bpf_diag_event_log(env);
	if (!log)
		return;

	if (log->cnt < log->cap) {
		log->events[log->cnt++] = *event;
		return;
	}

	cap = log->cap ? log->cap * 2 : 64;
	if (cap < log->cap)
		return;

	events = krealloc_array(log->events, cap, sizeof(*events),
				GFP_KERNEL_ACCOUNT);
	if (!events)
		return;
	log->events = events;
	log->cap = cap;
	log->events[log->cnt++] = *event;
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

		bpf_diag_write(env, "%s%.*s\n", prefix, len, line);

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

static void bpf_diag_trim_btf_show_name(char *buf)
{
	size_t len = strlen(buf);

	if (len && buf[len - 1] == '{')
		buf[len - 1] = '\0';
}

void bpf_diag_format_btf_type(char *buf, size_t size, const struct btf *btf,
			      u32 type_id)
{
	int ret;

	if (!size)
		return;

	buf[0] = '\0';
	ret = btf_type_snprintf_show_name(btf, type_id, buf, size);
	if (ret < 0 || !buf[0]) {
		scnprintf(buf, size, "BTF type ID %u", type_id);
		return;
	}

	bpf_diag_trim_btf_show_name(buf);
}

const char *bpf_diag_format_btf_type_scratch(struct bpf_verifier_env *env,
					     unsigned int slot,
					     const struct btf *btf,
					     u32 type_id)
{
	size_t size;
	char *buf = bpf_diag_scratch_buf(env, slot, &size);

	if (!buf)
		return "";

	bpf_diag_format_btf_type(buf, size, btf, type_id);
	return buf;
}

static void bpf_diag_vprint_indented(struct bpf_verifier_env *env,
				     const char *fmt, va_list args)
{
	char *buf;

	if (!bpf_diag_enabled(env))
		return;

	buf = kvasprintf(GFP_KERNEL_ACCOUNT, fmt, args);
	if (!buf) {
		bpf_diag_write(env, "%s<failed to allocate diagnostic text>\n",
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

	bpf_diag_write(env, "  %-*s%*s", BPF_DIAG_SOURCE_LANE_WIDTH,
		       source_lane, BPF_DIAG_COLUMN_GAP, "");
	if (diag_insn->valid)
		bpf_diag_write(env, "%s%*d | %s",
			       diag_insn->idx == focus_insn_idx ?
			       ">>> " : "    ", insn_width, diag_insn->idx,
			       diag_insn->text);
	bpf_diag_write(env, "\n");
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
		bpf_diag_write(env, "\nVerification failed: %s\n", category);
		return;
	}

	first = toupper(problem[0]);
	bpf_diag_write(env, "\nVerification failed: %s: %c%s\n", category,
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

	bpf_diag_write(env, "\n%s:\n", title);
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
	bpf_diag_write(env, "\n");
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
		bpf_diag_write(env, "  %*s | %*s^-- %s\n",
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
		bpf_diag_write(env, "  insn %u\n", insn_idx);
		bpf_diag_print_source_annotation(env, 0, 0, label, msg);
		goto out_free_msg;
	}

	func = bpf_diag_func_name(env, insn_idx);
	if (func && *func)
		bpf_diag_write(env, "  %s @ %s:%d:%d\n", func, src->file,
			       src->line_num, src->line_col);
	else
		bpf_diag_write(env, "  %s:%d:%d\n", src->file, src->line_num,
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

static u32 bpf_diag_current_frameno(const struct bpf_verifier_env *env)
{
	return env->cur_state->frame[env->cur_state->curframe]->frameno;
}

static int bpf_diag_stack_argno(u8 slot);

void bpf_diag_report_register_type(struct bpf_verifier_env *env,
				   u32 insn_idx, int regno,
				   const char *problem, const char *reason,
				   const char *suggestion)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REG,
		.frameno = bpf_diag_current_frameno(env),
		.regno = regno,
	};

	bpf_diag_report_header(env, BPF_DIAG_CATEGORY_REGISTER_TYPE_SAFETY,
			       problem);
	bpf_diag_report_reason(env, "%s", reason);

	bpf_diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s", problem);

	if (regno >= 0)
		bpf_diag_print_history(env, &opts);

	bpf_diag_report_suggestion(env, "%s", suggestion);
}

static const char *bpf_diag_arg_ordinal(int argno)
{
	switch (argno) {
	case 1:
		return "first";
	case 2:
		return "second";
	case 3:
		return "third";
	case 4:
		return "fourth";
	case 5:
		return "fifth";
	case 6:
		return "sixth";
	case 7:
		return "seventh";
	case 8:
		return "eighth";
	case 9:
		return "ninth";
	case 10:
		return "tenth";
	case 11:
		return "eleventh";
	case 12:
		return "twelfth";
	default:
		return NULL;
	}
}

void bpf_diag_report_invalid_deref(struct bpf_verifier_env *env, u32 insn_idx,
				   int regno, const char *reg_name,
				   const char *type_name,
				   enum bpf_diag_invalid_deref_kind kind,
				   s64 offset)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REG,
		.frameno = bpf_diag_current_frameno(env),
		.regno = regno,
	};

	bpf_diag_report_header(env, BPF_DIAG_CATEGORY_REGISTER_TYPE_SAFETY,
			       "invalid dereference");

	switch (kind) {
	case BPF_DIAG_DEREF_SCALAR:
		bpf_diag_report_reason(env,
				       "%s is an integer scalar here, not a pointer to memory.",
				       reg_name);
		break;
	case BPF_DIAG_DEREF_NULLABLE_PTR:
		bpf_diag_report_reason(env,
				       "%s may be NULL here (%s). The program could dereference NULL on this path, so the verifier cannot prove this access is safe.",
				       reg_name, type_name);
		break;
	case BPF_DIAG_DEREF_MODIFIED_PTR:
		bpf_diag_report_reason(env,
				       "%s has offset %lld here, but this pointer type must be dereferenced in its original form.",
				       reg_name, offset);
		break;
	case BPF_DIAG_DEREF_INVALID_PTR:
	default:
		bpf_diag_report_reason(env,
				       "%s has type %s here, which is not valid for this memory access.",
				       reg_name, type_name);
		break;
	}

	bpf_diag_report_section(env, "At");
	if (kind == BPF_DIAG_DEREF_MODIFIED_PTR)
		bpf_diag_report_source(env, insn_idx, "error",
				       "dereference requires the original %s pointer",
				       type_name);
	else
		bpf_diag_report_source(env, insn_idx, "error",
				       "invalid dereference of %s (%s)",
				       reg_name, type_name);

	if (regno >= 0)
		bpf_diag_print_history(env, &opts);

	switch (kind) {
	case BPF_DIAG_DEREF_NULLABLE_PTR:
		bpf_diag_report_suggestion(env,
					   "Add a NULL check before the access and dereference the pointer only on the non-NULL path.");
		break;
	case BPF_DIAG_DEREF_MODIFIED_PTR:
		bpf_diag_report_suggestion(env,
					   "Preserve the original pointer in another register, or use only offsets this pointer type permits before dereferencing it.");
		break;
	case BPF_DIAG_DEREF_SCALAR:
	case BPF_DIAG_DEREF_INVALID_PTR:
	default:
		bpf_diag_report_suggestion(env,
					   "Preserve a pointer-valued register where needed, or reload and revalidate the pointer after scalar arithmetic, helper calls, or other operations that can invalidate it.");
		break;
	}
}

void bpf_diag_report_unreadable_reg(struct bpf_verifier_env *env,
				    u32 insn_idx, int regno)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REG,
		.frameno = bpf_diag_current_frameno(env),
		.regno = regno,
	};

	bpf_diag_report_header(env, BPF_DIAG_CATEGORY_REGISTER_TYPE_SAFETY,
			       "unreadable register");
	bpf_diag_report_reason(env,
			       "R%d is not readable here. A previous operation may have invalidated this register, so the verifier cannot use it as an input.",
			       regno);

	bpf_diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error",
			       "R%d is not readable", regno);

	if (regno >= 0)
		bpf_diag_print_history(env, &opts);

	bpf_diag_report_suggestion(env,
				   "Avoid using the register after it is invalidated, or reload and revalidate a fresh pointer before this instruction.");
}

static void bpf_diag_format_stack_arg(char *buf, size_t size, u8 slot)
{
	int argno = bpf_diag_stack_argno(slot);
	const char *ordinal = bpf_diag_arg_ordinal(argno);

	if (ordinal)
		scnprintf(buf, size, "outgoing stack argument %u (%s argument)",
			  slot + 1, ordinal);
	else
		scnprintf(buf, size, "outgoing stack argument %u", slot + 1);
}

void bpf_diag_report_stack_arg_uninit(struct bpf_verifier_env *env,
				      u32 insn_idx, int nargs,
				      int stack_arg_slot,
				      const char *callee_name)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_STACK_ARG,
		.frameno = bpf_diag_current_frameno(env),
		.stack_arg_slot = stack_arg_slot,
	};
	const char *arg_buf;

	arg_buf = bpf_diag_scratch_buf(env, 1, NULL);
	if (arg_buf)
		bpf_diag_format_stack_arg((char *)arg_buf, BPF_DIAG_SCRATCH_STR_LEN,
					  stack_arg_slot);
	else
		arg_buf = "";
	bpf_diag_report_header(env, BPF_DIAG_CATEGORY_REGISTER_TYPE_SAFETY,
			       "missing stack argument");
	if (callee_name && *callee_name)
		bpf_diag_report_reason(env,
				       "Function %s expects %d arguments, but %s is not initialized at this call.",
				       callee_name, nargs, arg_buf);
	else
		bpf_diag_report_reason(env,
				       "The callee expects %d arguments, but %s is not initialized at this call.",
				       nargs, arg_buf);

	bpf_diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error",
			       "%s is not initialized", arg_buf);

	if (stack_arg_slot >= 0)
		bpf_diag_print_history(env, &opts);

	bpf_diag_report_suggestion(env,
				   "Write the outgoing stack argument after any operation that may invalidate stored pointer values, and before making this call.");
}

void bpf_diag_report_memory(struct bpf_verifier_env *env, u32 insn_idx,
			    const char *problem, const char *reason,
			    const char *suggestion)
{
	bpf_diag_report_header(env, BPF_DIAG_CATEGORY_MEMORY_SAFETY, problem);
	bpf_diag_report_reason(env, "%s", reason);

	bpf_diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s", problem);

	bpf_diag_report_suggestion(env, "%s", suggestion);
}

void bpf_diag_record_branch(struct bpf_verifier_env *env, u32 insn_idx,
			    bool cond_true)
{
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = BPF_DIAG_HISTORY_BRANCH,
		.branch.cond_true = cond_true,
	};

	bpf_diag_append_history(env, &event);
}

static void bpf_diag_snapshot_one_reg(struct bpf_diag_reg_snapshot *snapshot,
				      const struct bpf_reg_state *reg)
{
	snapshot->type = reg->type;
	if (base_type(reg->type) == PTR_TO_MAP_VALUE ||
	    base_type(reg->type) == CONST_PTR_TO_MAP ||
	    base_type(reg->type) == PTR_TO_MAP_KEY)
		snapshot->map_ptr = reg->map_ptr;
	if (base_type(reg->type) == PTR_TO_BTF_ID && reg->btf && reg->btf_id) {
		snapshot->btf = reg->btf;
		snapshot->btf_id = reg->btf_id;
	}
	snapshot->var_off = reg->var_off;
	snapshot->r64 = reg->r64;
}

static void bpf_diag_snapshot_reg(struct bpf_diag_history_event *event,
				  enum bpf_diag_reg_mod_reason reason,
				  const struct bpf_reg_state *old_reg,
				  const struct bpf_reg_state *new_reg)
{
	event->reg.reason = reason;
	bpf_diag_snapshot_one_reg(&event->reg.old, old_reg);
	bpf_diag_snapshot_one_reg(&event->reg.new, new_reg);
}

static bool bpf_diag_snapshot_eq(const struct bpf_diag_reg_snapshot *old,
				 const struct bpf_diag_reg_snapshot *new)
{
	return old->type == new->type &&
	       old->map_ptr == new->map_ptr &&
	       old->btf == new->btf &&
	       old->btf_id == new->btf_id &&
	       old->var_off.value == new->var_off.value &&
	       old->var_off.mask == new->var_off.mask &&
	       old->r64.base == new->r64.base &&
	       old->r64.size == new->r64.size;
}

static bool bpf_diag_reg_snapshot_eq(const struct bpf_diag_history_event *event)
{
	return bpf_diag_snapshot_eq(&event->reg.old, &event->reg.new);
}

static void bpf_diag_record_reg_mod_reason(struct bpf_verifier_env *env,
					   u32 insn_idx, u32 frameno,
					   u8 dst_reg, bool src_valid,
					   u8 src_reg, u8 opcode,
					   bool stack_slot_valid,
					   u32 stack_frameno,
					   u16 stack_spi,
					   enum bpf_diag_reg_mod_reason reason,
					   const struct bpf_reg_state *old_reg,
					   const struct bpf_reg_state *new_reg)
{
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = BPF_DIAG_HISTORY_REG_MOD,
		.reg.frameno = frameno,
		.reg.dst_reg = dst_reg,
		.reg.src_reg = src_reg,
		.reg.opcode = opcode,
		.reg.src_valid = src_valid,
		.reg.stack_slot_valid = stack_slot_valid,
		.reg.stack_frameno = stack_frameno,
		.reg.stack_spi = stack_spi,
	};

	bpf_diag_snapshot_reg(&event, reason, old_reg, new_reg);
	if (reason == BPF_DIAG_REG_MOD_WRITE &&
	    bpf_diag_reg_snapshot_eq(&event))
		return;

	bpf_diag_append_history(env, &event);
}

void bpf_diag_record_reg_mod(struct bpf_verifier_env *env, u32 insn_idx,
			     u32 frameno, u8 dst_reg, bool src_valid,
			     u8 src_reg, u8 opcode,
			     const struct bpf_reg_state *old_reg,
			     const struct bpf_reg_state *new_reg)
{
	bpf_diag_record_reg_mod_reason(env, insn_idx, frameno, dst_reg,
				       src_valid, src_reg, opcode, false, 0, 0,
				       BPF_DIAG_REG_MOD_WRITE, old_reg,
				       new_reg);
}

void bpf_diag_record_reg_stack_fill(struct bpf_verifier_env *env, u32 insn_idx,
				    u32 frameno, u8 dst_reg, u32 stack_frameno,
				    u16 stack_spi, bool src_valid, u8 src_reg,
				    u8 opcode,
				    const struct bpf_reg_state *old_reg,
				    const struct bpf_reg_state *new_reg)
{
	bpf_diag_record_reg_mod_reason(env, insn_idx, frameno, dst_reg,
				       src_valid, src_reg, opcode, true,
				       stack_frameno, stack_spi,
				       BPF_DIAG_REG_MOD_WRITE, old_reg,
				       new_reg);
}

void bpf_diag_record_reg_invalidate(struct bpf_verifier_env *env, u32 insn_idx,
				    u32 frameno, u8 dst_reg,
				    enum bpf_diag_reg_mod_reason reason,
				    const struct bpf_reg_state *old_reg,
				    const struct bpf_reg_state *new_reg)
{
	bpf_diag_record_reg_mod_reason(env, insn_idx, frameno, dst_reg,
				       false, 0, 0, false, 0, 0, reason, old_reg,
				       new_reg);
}

void bpf_diag_record_stack_arg(struct bpf_verifier_env *env, u32 insn_idx,
			       u32 frameno, u8 slot,
			       enum bpf_diag_stack_arg_reason reason,
			       const struct bpf_reg_state *old_reg,
			       const struct bpf_reg_state *new_reg)
{
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = BPF_DIAG_HISTORY_STACK_ARG,
		.stack_arg.frameno = frameno,
		.stack_arg.slot = slot,
		.stack_arg.reason = reason,
	};

	bpf_diag_snapshot_one_reg(&event.stack_arg.old, old_reg);
	bpf_diag_snapshot_one_reg(&event.stack_arg.new, new_reg);

	if (reason == BPF_DIAG_STACK_ARG_WRITE &&
	    bpf_diag_snapshot_eq(&event.stack_arg.old, &event.stack_arg.new))
		return;

	bpf_diag_append_history(env, &event);
}

void bpf_diag_record_stack_slot(struct bpf_verifier_env *env, u32 insn_idx,
				u32 frameno, u16 spi,
				enum bpf_diag_stack_slot_reason reason,
				const struct bpf_reg_state *old_reg,
				const struct bpf_reg_state *new_reg)
{
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = BPF_DIAG_HISTORY_STACK_SLOT,
		.stack_slot.frameno = frameno,
		.stack_slot.spi = spi,
		.stack_slot.reason = reason,
	};

	bpf_diag_snapshot_one_reg(&event.stack_slot.old, old_reg);
	bpf_diag_snapshot_one_reg(&event.stack_slot.new, new_reg);

	if (reason == BPF_DIAG_STACK_SLOT_SPILL &&
	    bpf_diag_snapshot_eq(&event.stack_slot.old,
				 &event.stack_slot.new))
		return;
	if (reason == BPF_DIAG_STACK_SLOT_WRITE &&
	    bpf_diag_snapshot_eq(&event.stack_slot.old,
				 &event.stack_slot.new))
		return;

	bpf_diag_append_history(env, &event);
}

static void bpf_diag_record_ref(struct bpf_verifier_env *env, u32 insn_idx,
				u8 kind, u32 ref_id)
{
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = kind,
		.ref.ref_id = ref_id,
	};

	bpf_diag_append_history(env, &event);
}

void bpf_diag_record_ref_acquire(struct bpf_verifier_env *env, u32 insn_idx,
				 u32 ref_id)
{
	bpf_diag_record_ref(env, insn_idx, BPF_DIAG_HISTORY_REF_ACQUIRE,
			    ref_id);
}

void bpf_diag_record_ref_release(struct bpf_verifier_env *env, u32 insn_idx,
				 u32 ref_id)
{
	bpf_diag_record_ref(env, insn_idx, BPF_DIAG_HISTORY_REF_RELEASE,
			    ref_id);
}

void bpf_diag_record_context(struct bpf_verifier_env *env, u32 insn_idx,
			     enum bpf_diag_context_kind ctx_kind, bool enter,
			     u32 depth)
{
	/* Keep leave events so context rendering can stop at a depth-zero exit
	 * and show nested-region depth accurately for the active path.
	 */
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = BPF_DIAG_HISTORY_CONTEXT,
		.ctx.kind = ctx_kind,
		.ctx.enter = enter,
		.ctx.depth = depth,
	};

	if (ctx_kind == BPF_DIAG_CONTEXT_NONE)
		return;

	bpf_diag_append_history(env, &event);
}

static int bpf_diag_history_context_start_idx(const struct bpf_diag_log *log,
					      const struct bpf_diag_history_opts *opts)
{
	int i;

	if (!opts->ctx_depth)
		return 0;

	for (i = log->cnt; i > 0; i--) {
		const struct bpf_diag_history_event *event;

		event = bpf_diag_history_event(log, i - 1);

		if (event->kind != BPF_DIAG_HISTORY_CONTEXT ||
		    event->ctx.kind != opts->ctx_kind)
			continue;

		if (event->ctx.enter && event->ctx.depth == 1)
			return i - 1;
		if (!event->ctx.enter && event->ctx.depth == 0)
			return 0;
	}

	return 0;
}

struct bpf_diag_history_filter {
	const struct bpf_diag_history_opts *opts;
	bool stack_slot_valid;
	u32 stack_frameno;
	u16 stack_spi;
	u32 stack_until_idx;
};

static bool bpf_diag_reg_event_matches(const struct bpf_diag_history_event *event,
				       const struct bpf_diag_history_opts *opts)
{
	return opts->scope == BPF_DIAG_HISTORY_SCOPE_REG &&
	       event->kind == BPF_DIAG_HISTORY_REG_MOD &&
	       event->reg.dst_reg == opts->regno &&
	       event->reg.frameno == opts->frameno;
}

static bool bpf_diag_stack_slot_matches(const struct bpf_diag_history_event *event,
					const struct bpf_diag_history_filter *filter)
{
	return event->kind == BPF_DIAG_HISTORY_STACK_SLOT &&
	       event->stack_slot.spi == filter->stack_spi &&
	       event->stack_slot.frameno == filter->stack_frameno;
}

static bool bpf_diag_reg_event_keeps_lineage(const struct bpf_diag_history_event *event)
{
	if (event->reg.reason != BPF_DIAG_REG_MOD_WRITE)
		return false;

	switch (event->reg.opcode) {
	case BPF_ADD:
	case BPF_SUB:
	case BPF_MUL:
	case BPF_OR:
	case BPF_AND:
	case BPF_LSH:
	case BPF_RSH:
	case BPF_ARSH:
	case BPF_XOR:
	case BPF_NEG:
	case BPF_END:
		return true;
	default:
		return false;
	}
}

static void bpf_diag_history_follow_reg_stack(const struct bpf_diag_log *log,
					      struct bpf_diag_history_filter *filter)
{
	const struct bpf_diag_history_opts *opts = filter->opts;
	int i;

	if (!opts || opts->scope != BPF_DIAG_HISTORY_SCOPE_REG)
		return;

	for (i = log->cnt; i > 0; i--) {
		const struct bpf_diag_history_event *event;

		event = bpf_diag_history_event(log, i - 1);
		if (!bpf_diag_reg_event_matches(event, opts))
			continue;

		if (event->reg.stack_slot_valid) {
			filter->stack_slot_valid = true;
			filter->stack_frameno = event->reg.stack_frameno;
			filter->stack_spi = event->reg.stack_spi;
			filter->stack_until_idx = i - 1;
			return;
		}

		if (!bpf_diag_reg_event_keeps_lineage(event))
			return;
	}
}

static int bpf_diag_history_stack_start_idx(const struct bpf_diag_log *log,
					    const struct bpf_diag_history_filter *filter)
{
	int fallback = filter->stack_until_idx;
	int i;

	for (i = filter->stack_until_idx + 1; i > 0; i--) {
		const struct bpf_diag_history_event *event;

		event = bpf_diag_history_event(log, i - 1);
		if (!bpf_diag_stack_slot_matches(event, filter))
			continue;

		fallback = i - 1;
		if (event->stack_slot.reason == BPF_DIAG_STACK_SLOT_SPILL)
			return fallback;
	}

	return fallback;
}

static int bpf_diag_history_start_idx(const struct bpf_diag_log *log,
				      const struct bpf_diag_history_filter *filter)
{
	const struct bpf_diag_history_opts *opts = filter->opts;
	int i;

	if (!opts || opts->scope == BPF_DIAG_HISTORY_SCOPE_ALL)
		return 0;
	if (opts->scope == BPF_DIAG_HISTORY_SCOPE_CONTEXT)
		return bpf_diag_history_context_start_idx(log, opts);
	if (filter->stack_slot_valid)
		return bpf_diag_history_stack_start_idx(log, filter);

	for (i = log->cnt; i > 0; i--) {
		const struct bpf_diag_history_event *event;

		event = bpf_diag_history_event(log, i - 1);

		if (bpf_diag_reg_event_matches(event, opts))
			return i - 1;
		if (opts->scope == BPF_DIAG_HISTORY_SCOPE_STACK_ARG &&
		    event->kind == BPF_DIAG_HISTORY_STACK_ARG &&
		    event->stack_arg.slot == opts->stack_arg_slot &&
		    event->stack_arg.frameno == opts->frameno)
			return i - 1;
		if (opts->scope == BPF_DIAG_HISTORY_SCOPE_REF &&
		    event->kind == BPF_DIAG_HISTORY_REF_ACQUIRE &&
		    event->ref.ref_id == opts->ref_id)
			return i - 1;
	}

	return 0;
}

static bool
bpf_diag_history_event_visible(const struct bpf_diag_history_event *event,
			       u32 idx,
			       const struct bpf_diag_history_filter *filter)
{
	const struct bpf_diag_history_opts *opts = filter->opts;

	if (!opts || opts->scope == BPF_DIAG_HISTORY_SCOPE_ALL)
		return event->kind != BPF_DIAG_HISTORY_CONTEXT;

	switch (event->kind) {
	case BPF_DIAG_HISTORY_BRANCH:
		return true;
	case BPF_DIAG_HISTORY_REG_MOD:
		return opts->scope == BPF_DIAG_HISTORY_SCOPE_REG &&
		       event->reg.dst_reg == opts->regno &&
		       event->reg.frameno == opts->frameno;
	case BPF_DIAG_HISTORY_STACK_ARG:
		return opts->scope == BPF_DIAG_HISTORY_SCOPE_STACK_ARG &&
		       event->stack_arg.slot == opts->stack_arg_slot &&
		       event->stack_arg.frameno == opts->frameno;
	case BPF_DIAG_HISTORY_STACK_SLOT:
		return filter->stack_slot_valid &&
		       idx <= filter->stack_until_idx &&
		       bpf_diag_stack_slot_matches(event, filter);
	case BPF_DIAG_HISTORY_REF_ACQUIRE:
	case BPF_DIAG_HISTORY_REF_RELEASE:
		return opts->scope == BPF_DIAG_HISTORY_SCOPE_REF &&
		       event->ref.ref_id == opts->ref_id;
	case BPF_DIAG_HISTORY_CONTEXT:
		return opts->scope == BPF_DIAG_HISTORY_SCOPE_CONTEXT &&
		       event->ctx.kind == opts->ctx_kind;
	default:
		return false;
	}
}

static const char *bpf_diag_s64_bound_name(s64 value)
{
	if (value == S64_MIN)
		return "S64_MIN";
	if (value == S64_MAX)
		return "S64_MAX";
	return NULL;
}

static const char *bpf_diag_u64_bound_name(u64 value)
{
	if (value == U64_MAX)
		return "U64_MAX";
	return NULL;
}

static void bpf_diag_format_s64_value(char *buf, size_t size, s64 value)
{
	const char *name = bpf_diag_s64_bound_name(value);

	if (name)
		strscpy(buf, name, size);
	else
		scnprintf(buf, size, "%lld", value);
}

static void bpf_diag_format_u64_value(char *buf, size_t size, u64 value)
{
	const char *name = bpf_diag_u64_bound_name(value);

	if (name)
		strscpy(buf, name, size);
	else
		scnprintf(buf, size, "%llu", value);
}

static bool bpf_diag_range_unknown(s64 smin, s64 smax, u64 umin, u64 umax)
{
	return smin == S64_MIN && smax == S64_MAX &&
	       umin == 0 && umax == U64_MAX;
}

static bool bpf_diag_cnum64_unknown(struct cnum64 range)
{
	return bpf_diag_range_unknown(cnum64_smin(range), cnum64_smax(range),
				      cnum64_umin(range), cnum64_umax(range));
}

static bool bpf_diag_snapshot_unknown(const struct bpf_diag_reg_snapshot *snapshot)
{
	return tnum_is_unknown(snapshot->var_off) &&
	       bpf_diag_cnum64_unknown(snapshot->r64);
}

static void bpf_diag_format_scalar_range(struct bpf_diag_reg_fmt *fmt,
					 char *buf, size_t size,
					 struct cnum64 range)
{
	s64 smin = cnum64_smin(range);
	s64 smax = cnum64_smax(range);
	u64 umin = cnum64_umin(range);
	u64 umax = cnum64_umax(range);

	bpf_diag_format_s64_value(fmt->smin_buf, sizeof(fmt->smin_buf), smin);
	bpf_diag_format_s64_value(fmt->smax_buf, sizeof(fmt->smax_buf), smax);
	bpf_diag_format_u64_value(fmt->umin_buf, sizeof(fmt->umin_buf), umin);
	bpf_diag_format_u64_value(fmt->umax_buf, sizeof(fmt->umax_buf), umax);

	scnprintf(buf, size,
		  "signed range [%s, %s], unsigned range [%s, %s]",
		  fmt->smin_buf, fmt->smax_buf, fmt->umin_buf, fmt->umax_buf);
}

static void bpf_diag_format_s64_sum(char *buf, size_t size, s64 value,
				    int addend)
{
	s64 sum;

	if (check_add_overflow(value, (s64)addend, &sum)) {
		if (addend < 0)
			scnprintf(buf, size, "%lld plus %d (below S64_MIN)",
				  value, addend);
		else
			scnprintf(buf, size, "%lld plus %d (above S64_MAX)",
				  value, addend);
		return;
	}

	scnprintf(buf, size, "%lld", sum);
}

static void bpf_diag_format_access_offset(struct bpf_verifier_env *env,
					  char *buf, size_t size, int off,
					  const struct bpf_reg_state *reg)
{
	struct bpf_diag_scratch *scratch = bpf_diag_scratch(env);
	struct bpf_diag_reg_fmt *fmt;
	char *start;

	if (tnum_is_const(reg->var_off)) {
		start = bpf_diag_scratch_buf(env, 2,
					     NULL);
		if (!start) {
			scnprintf(buf, size, "constant");
			return;
		}
		bpf_diag_format_s64_sum(start, BPF_DIAG_SCRATCH_STR_LEN,
					(s64)reg->var_off.value, off);
		scnprintf(buf, size, "constant %s", start);
		return;
	}

	if (tnum_is_unknown(reg->var_off) &&
	    bpf_diag_cnum64_unknown(reg->r64)) {
		scnprintf(buf, size, "unknown");
		return;
	}

	fmt = &scratch->reg_fmt;
	memset(fmt, 0, sizeof(*fmt));

	bpf_diag_format_scalar_range(fmt, fmt->range, sizeof(fmt->range),
				     reg->r64);
	if (off)
		scnprintf(buf, size,
			  "variable: known bits %#llx, unknown mask %#llx, plus fixed offset %d; %s",
			  (u64)reg->var_off.value, reg->var_off.mask, off,
			  fmt->range);
	else
		scnprintf(buf, size,
			  "variable: known bits %#llx, unknown mask %#llx; %s",
			  (u64)reg->var_off.value, reg->var_off.mask,
			  fmt->range);
}

static u64 bpf_diag_mem_max_start(const struct bpf_reg_state *reg, int off)
{
	/* A negative fixed offset can clamp the maximum start to zero when
	 * the unsigned variable maximum is smaller than -off.
	 */
	if (off < 0 && reg_umax(reg) < (u64)-off)
		return 0;
	return reg_umax(reg) + off;
}

void bpf_diag_report_mem_bounds(struct bpf_verifier_env *env, u32 insn_idx,
				int regno, const char *reg_name,
				const char *type_name,
				enum bpf_diag_mem_bounds_kind kind,
				int off, int size, u32 mem_size,
				const struct bpf_reg_state *reg)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REG,
		.frameno = bpf_diag_current_frameno(env),
		.regno = regno,
	};
	char *offset_desc, *proof, *start;
	u64 max_start, max_end;

	if (!bpf_diag_enabled(env))
		return;

	offset_desc = bpf_diag_scratch_buf(env, 0, NULL);
	proof = bpf_diag_scratch_buf(env, 1, NULL);
	start = bpf_diag_scratch_buf(env, 2, NULL);
	if (!offset_desc || !proof || !start)
		return;

	switch (kind) {
	case BPF_DIAG_MEM_NEGATIVE_MIN:
		bpf_diag_format_s64_sum(start, BPF_DIAG_SCRATCH_STR_LEN, reg_smin(reg),
					off);
		scnprintf(proof, BPF_DIAG_SCRATCH_STR_LEN,
			  "the smallest possible access starts at %s, below 0",
			  start);
		break;
	case BPF_DIAG_MEM_MIN_OUT_OF_RANGE:
		bpf_diag_format_s64_sum(start, BPF_DIAG_SCRATCH_STR_LEN, reg_smin(reg),
					off);
		scnprintf(proof, BPF_DIAG_SCRATCH_STR_LEN,
			  "the smallest possible access starts at %s, outside object_size %u",
			  start, mem_size);
		break;
	case BPF_DIAG_MEM_UNBOUNDED:
		scnprintf(proof, BPF_DIAG_SCRATCH_STR_LEN,
			  "%s has unsigned maximum %llu, which exceeds BPF_MAX_VAR_OFF %u",
			  reg_name, reg_umax(reg), BPF_MAX_VAR_OFF);
		break;
	case BPF_DIAG_MEM_MAX_OUT_OF_RANGE:
	default:
		max_start = bpf_diag_mem_max_start(reg, off);
		max_end = max_start + size;
		scnprintf(proof, BPF_DIAG_SCRATCH_STR_LEN,
			  "the largest possible access ends at %llu: start %llu + access_size %d, beyond object_size %u",
			  max_end, max_start, size, mem_size);
		break;
	}

	bpf_diag_format_access_offset(env, offset_desc, BPF_DIAG_SCRATCH_STR_LEN,
				      off, reg);

	bpf_diag_report_header(env, BPF_DIAG_CATEGORY_MEMORY_SAFETY,
			       "access outside bounds");
	bpf_diag_report_reason(env,
			       "The verifier cannot prove offset + access_size <= object_size. Here, %s. %s is %s; offset is %s; access_size is %d; object_size is %u.",
			       proof, reg_name, type_name, offset_desc, size,
			       mem_size);

	bpf_diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error",
			       "access may be outside object bounds");

	if (regno >= 0)
		bpf_diag_print_history(env, &opts);

	bpf_diag_report_suggestion(env,
				   "Add or adjust a bounds check that proves offset + access_size stays within the object.");
}

void bpf_diag_report_resource_state(struct bpf_verifier_env *env,
				    u32 insn_idx, const char *problem,
				    const char *reason,
				    const char *suggestion)
{
	bpf_diag_report_header(env, BPF_DIAG_CATEGORY_RESOURCE_LIFETIME_SAFETY,
			       problem);
	bpf_diag_report_reason(env, "%s", reason);

	bpf_diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s", problem);

	bpf_diag_report_suggestion(env, "%s", suggestion);
}

void bpf_diag_report_irq_resource_state(struct bpf_verifier_env *env,
					u32 insn_idx, const char *problem,
					const char *reason,
					const char *suggestion,
					u32 depth)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_CONTEXT,
		.ctx_kind = BPF_DIAG_CONTEXT_IRQ,
		.ctx_depth = depth,
	};

	bpf_diag_report_header(env, BPF_DIAG_CATEGORY_RESOURCE_LIFETIME_SAFETY,
			       problem);
	bpf_diag_report_reason(env, "%s", reason);

	bpf_diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s", problem);

	if (depth)
		bpf_diag_print_history(env, &opts);

	bpf_diag_report_suggestion(env, "%s", suggestion);
}

void bpf_diag_report_ref_leak(struct bpf_verifier_env *env, u32 ref_id,
			      u32 alloc_insn, u32 fail_insn)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REF,
		.ref_id = ref_id,
	};

	bpf_diag_report_header(env, BPF_DIAG_CATEGORY_RESOURCE_LIFETIME_SAFETY,
			       "unreleased resource");
	bpf_diag_report_reason(env,
			       "Owned resource (id=%u) was acquired at instruction %u and still needs to be released before this exit path.",
			       ref_id, alloc_insn);

	bpf_diag_report_section(env, "At");
	bpf_diag_report_source(env, fail_insn, "error",
			       "owned resource (id=%u) still needs release",
			       ref_id);

	bpf_diag_print_history(env, &opts);

	bpf_diag_report_suggestion(env,
				   "Release or transfer ownership of the acquired resource on every path before the program exits.");
}

static void bpf_diag_format_var_offset(struct bpf_diag_reg_fmt *fmt,
				       char *buf, size_t size,
				       const struct bpf_diag_reg_snapshot *snapshot)
{
	if (tnum_is_const(snapshot->var_off)) {
		scnprintf(buf, size, "at offset %lld",
			  (s64)snapshot->var_off.value);
		return;
	}

	if (bpf_diag_snapshot_unknown(snapshot)) {
		scnprintf(buf, size, "with unknown offset");
		return;
	}

	bpf_diag_format_scalar_range(fmt, fmt->range, sizeof(fmt->range),
				     snapshot->r64);
	scnprintf(buf, size,
		  "with variable offset: known bits %#llx, unknown mask %#llx, %s",
		  snapshot->var_off.value, snapshot->var_off.mask, fmt->range);
}

static bool bpf_diag_format_snapshot_btf_type(char *buf, size_t size,
					      const struct bpf_diag_reg_snapshot *snapshot)
{
	if (!snapshot->btf || !snapshot->btf_id)
		return false;

	bpf_diag_format_btf_type(buf, size, snapshot->btf, snapshot->btf_id);
	return true;
}

static const char *bpf_diag_reg_map_name(const struct bpf_map *map)
{
	if (!map || !map->name[0])
		return NULL;

	return map->name;
}

static void bpf_diag_format_reg_snapshot(struct bpf_verifier_env *env,
					 struct bpf_diag_reg_fmt *fmt,
					 char *buf, size_t size,
					 const struct bpf_diag_reg_snapshot *snapshot)
{
	const char *type_name = reg_type_str(env, snapshot->type);
	const char *map_name;
	bool has_btf_type;

	bpf_diag_format_var_offset(fmt, fmt->offset_desc,
				   sizeof(fmt->offset_desc), snapshot);
	has_btf_type = bpf_diag_format_snapshot_btf_type(fmt->btf_type,
							 sizeof(fmt->btf_type),
							 snapshot);

	if (snapshot->type == SCALAR_VALUE) {
		if (tnum_is_const(snapshot->var_off)) {
			scnprintf(buf, size, "integer scalar value %lld",
				  (s64)snapshot->var_off.value);
			return;
		}

		if (bpf_diag_snapshot_unknown(snapshot)) {
			scnprintf(buf, size, "integer scalar with unknown value");
			return;
		}

		if (cnum64_is_const(snapshot->r64)) {
			scnprintf(buf, size, "integer scalar value %lld",
				  cnum64_smin(snapshot->r64));
			return;
		}

		bpf_diag_format_scalar_range(fmt, fmt->range,
					     sizeof(fmt->range),
					     snapshot->r64);
		scnprintf(buf, size, "integer scalar with %s", fmt->range);
		return;
	}

	if (snapshot->type == NOT_INIT) {
		scnprintf(buf, size, "uninitialized value");
		return;
	}

	if (base_type(snapshot->type) == PTR_TO_CTX) {
		scnprintf(buf, size, "context pointer %s", fmt->offset_desc);
		return;
	}

	if (base_type(snapshot->type) == PTR_TO_STACK) {
		scnprintf(buf, size, "stack pointer %s", fmt->offset_desc);
		return;
	}

	if (base_type(snapshot->type) == PTR_TO_MAP_VALUE) {
		map_name = bpf_diag_reg_map_name(snapshot->map_ptr);
		if (map_name) {
			scnprintf(buf, size, "%s from %s %s",
				  type_may_be_null(snapshot->type) ?
				  "nullable map value" : "map value",
				  map_name, fmt->offset_desc);
			return;
		}
		scnprintf(buf, size, "%s %s",
			  type_may_be_null(snapshot->type) ?
			  "nullable map value" : "map value",
			  fmt->offset_desc);
		return;
	}

	if (base_type(snapshot->type) == CONST_PTR_TO_MAP) {
		map_name = bpf_diag_reg_map_name(snapshot->map_ptr);
		if (map_name)
			scnprintf(buf, size, "map pointer for map %s", map_name);
		else
			scnprintf(buf, size, "map pointer");
		return;
	}

	if (type_is_non_owning_ref(snapshot->type)) {
		if (has_btf_type)
			scnprintf(buf, size,
				  "borrowed allocated object pointer type=%s",
				  fmt->btf_type);
		else
			scnprintf(buf, size, "borrowed allocated object pointer");
		return;
	}

	if (type_is_ptr_alloc_obj(snapshot->type)) {
		if (has_btf_type)
			scnprintf(buf, size,
				  "owned allocated object pointer type=%s",
				  fmt->btf_type);
		else
			scnprintf(buf, size, "owned allocated object pointer");
		return;
	}

	if (base_type(snapshot->type) == PTR_TO_BTF_ID && has_btf_type) {
		scnprintf(buf, size, "%s type=%s %s", type_name,
			  fmt->btf_type, fmt->offset_desc);
		return;
	}

	scnprintf(buf, size, "%s %s", type_name, fmt->offset_desc);
}

static void bpf_diag_print_reg_mod(struct bpf_verifier_env *env,
				   const struct bpf_diag_history_event *event)
{
	struct bpf_diag_scratch *scratch = bpf_diag_scratch(env);
	struct bpf_diag_reg_fmt *fmt = &scratch->reg_fmt;
	const char *reason = NULL;

	memset(fmt, 0, sizeof(*fmt));

	bpf_diag_format_reg_snapshot(env, fmt, fmt->old_buf,
				     sizeof(fmt->old_buf), &event->reg.old);
	bpf_diag_format_reg_snapshot(env, fmt, fmt->new_buf,
				     sizeof(fmt->new_buf), &event->reg.new);

	switch (event->reg.reason) {
	case BPF_DIAG_REG_MOD_REF_RELEASE:
		reason = "resource release invalidated this pointer";
		break;
	case BPF_DIAG_REG_MOD_PKT_DATA_CHANGE:
		reason = "packet data may have moved";
		break;
	case BPF_DIAG_REG_MOD_NON_OWN_REF:
		reason = "leaving the protected region invalidated this borrowed pointer";
		break;
	case BPF_DIAG_REG_MOD_WRITE:
	default:
		break;
	}

	if (reason) {
		bpf_diag_report_source(env, event->insn_idx, "invalidated",
				       "R%d: %s; previous value was %s",
				       event->reg.dst_reg, reason,
				       fmt->old_buf);
		return;
	}

	bpf_diag_report_source(env, event->insn_idx, "update",
			       "R%d changed from %s to %s",
			       event->reg.dst_reg, fmt->old_buf, fmt->new_buf);
}

static int bpf_diag_stack_argno(u8 slot)
{
	return MAX_BPF_FUNC_REG_ARGS + slot + 1;
}

static void bpf_diag_print_stack_arg(struct bpf_verifier_env *env,
				     const struct bpf_diag_history_event *event)
{
	struct bpf_diag_scratch *scratch = bpf_diag_scratch(env);
	struct bpf_diag_reg_fmt *fmt = &scratch->reg_fmt;
	const char *reason = NULL;
	int argno = bpf_diag_stack_argno(event->stack_arg.slot);

	memset(fmt, 0, sizeof(*fmt));

	bpf_diag_format_reg_snapshot(env, fmt, fmt->old_buf,
				     sizeof(fmt->old_buf),
				     &event->stack_arg.old);
	bpf_diag_format_reg_snapshot(env, fmt, fmt->new_buf,
				     sizeof(fmt->new_buf),
				     &event->stack_arg.new);

	switch (event->stack_arg.reason) {
	case BPF_DIAG_STACK_ARG_REF_RELEASE:
		reason = "resource release invalidated this value";
		break;
	case BPF_DIAG_STACK_ARG_PKT_DATA_CHANGE:
		reason = "packet data may have moved";
		break;
	case BPF_DIAG_STACK_ARG_NON_OWN_REF:
		reason = "leaving the protected region invalidated this borrowed pointer";
		break;
	case BPF_DIAG_STACK_ARG_WRITE:
	default:
		break;
	}

	if (reason) {
		bpf_diag_report_source(env, event->insn_idx, "invalidated",
				       "stack arg%d: %s; previous value was %s",
				       argno, reason, fmt->old_buf);
		return;
	}

	bpf_diag_report_source(env, event->insn_idx, "update",
			       "stack arg%d changed from %s to %s",
			       argno, fmt->old_buf, fmt->new_buf);
}

static int bpf_diag_stack_slot_off(u16 spi)
{
	return -(spi + 1) * BPF_REG_SIZE;
}

static void bpf_diag_print_stack_slot(struct bpf_verifier_env *env,
				      const struct bpf_diag_history_event *event)
{
	struct bpf_diag_scratch *scratch = bpf_diag_scratch(env);
	struct bpf_diag_reg_fmt *fmt = &scratch->reg_fmt;
	const char *reason = NULL;
	int off = bpf_diag_stack_slot_off(event->stack_slot.spi);

	memset(fmt, 0, sizeof(*fmt));

	bpf_diag_format_reg_snapshot(env, fmt, fmt->old_buf,
				     sizeof(fmt->old_buf),
				     &event->stack_slot.old);
	bpf_diag_format_reg_snapshot(env, fmt, fmt->new_buf,
				     sizeof(fmt->new_buf),
				     &event->stack_slot.new);

	switch (event->stack_slot.reason) {
	case BPF_DIAG_STACK_SLOT_REF_RELEASE:
		reason = "resource release invalidated this spilled value";
		break;
	case BPF_DIAG_STACK_SLOT_PKT_DATA_CHANGE:
		reason = "packet data may have moved";
		break;
	case BPF_DIAG_STACK_SLOT_NON_OWN_REF:
		reason = "leaving the protected region invalidated this borrowed pointer";
		break;
	case BPF_DIAG_STACK_SLOT_WRITE:
		reason = "a later stack write overwrote this spilled value";
		break;
	case BPF_DIAG_STACK_SLOT_SPILL:
	default:
		break;
	}

	if (reason) {
		bpf_diag_report_source(env, event->insn_idx, "invalidated",
				       "stack slot fp%d: %s; previous value was %s",
				       off, reason, fmt->old_buf);
		return;
	}

	bpf_diag_report_source(env, event->insn_idx, "spilled",
			       "stack slot fp%d changed from %s to %s",
			       off, fmt->old_buf, fmt->new_buf);
}

static void bpf_diag_print_ref_event(struct bpf_verifier_env *env,
				     const struct bpf_diag_history_event *event)
{
	if (event->kind == BPF_DIAG_HISTORY_REF_ACQUIRE) {
		bpf_diag_report_source(env, event->insn_idx, "acquired",
				       "owned resource (id=%u)",
				       event->ref.ref_id);
		return;
	}

	bpf_diag_report_source(env, event->insn_idx, "released",
			       "owned resource (id=%u)", event->ref.ref_id);
}

static const char *bpf_diag_context_name(enum bpf_diag_context_kind kind)
{
	switch (kind) {
	case BPF_DIAG_CONTEXT_RCU:
		return "RCU read lock region";
	case BPF_DIAG_CONTEXT_PREEMPT:
		return "non-preemptible region";
	case BPF_DIAG_CONTEXT_IRQ:
		return "IRQ-disabled region";
	case BPF_DIAG_CONTEXT_LOCK:
		return "lock region";
	case BPF_DIAG_CONTEXT_NONE:
	default:
		return "context";
	}
}

static void bpf_diag_print_context_event(struct bpf_verifier_env *env,
					 const struct bpf_diag_history_event *event)
{
	bpf_diag_report_source(env, event->insn_idx, "context",
			       "%s %s; depth is now %u",
			       event->ctx.enter ? "entered" : "left",
			       bpf_diag_context_name(event->ctx.kind),
			       event->ctx.depth);
}

void bpf_diag_print_history(struct bpf_verifier_env *env,
			    const struct bpf_diag_history_opts *opts)
{
	const struct bpf_diag_history_event *event;
	struct bpf_diag_history_filter filter = {
		.opts = opts,
	};
	const struct bpf_diag_log *log;
	bool printed = false;
	int start_idx;
	u32 i;

	bpf_diag_report_section(env, "Causal path");

	if (!env->diag) {
		bpf_diag_write(env, "  no recorded diagnostic events on this path\n");
		return;
	}
	log = &env->diag->log;

	bpf_diag_history_follow_reg_stack(log, &filter);
	start_idx = bpf_diag_history_start_idx(log, &filter);
	for (i = start_idx; i < log->cnt; i++) {
		event = bpf_diag_history_event(log, i);
		if (!bpf_diag_history_event_visible(event, i, &filter))
			continue;

		switch (event->kind) {
		case BPF_DIAG_HISTORY_BRANCH:
			bpf_diag_report_source(env, event->insn_idx, "branch",
					       "explored as %s, goto %s",
					       event->branch.cond_true ? "true" :
					       "false",
					       event->branch.cond_true ? "followed" :
					       "not followed");
			printed = true;
			break;
		case BPF_DIAG_HISTORY_REG_MOD:
			bpf_diag_print_reg_mod(env, event);
			printed = true;
			break;
		case BPF_DIAG_HISTORY_STACK_ARG:
			bpf_diag_print_stack_arg(env, event);
			printed = true;
			break;
		case BPF_DIAG_HISTORY_STACK_SLOT:
			bpf_diag_print_stack_slot(env, event);
			printed = true;
			break;
		case BPF_DIAG_HISTORY_REF_ACQUIRE:
		case BPF_DIAG_HISTORY_REF_RELEASE:
			bpf_diag_print_ref_event(env, event);
			printed = true;
			break;
		case BPF_DIAG_HISTORY_CONTEXT:
			bpf_diag_print_context_event(env, event);
			printed = true;
			break;
		default:
			break;
		}
	}

	if (!printed) {
		if (opts && opts->scope == BPF_DIAG_HISTORY_SCOPE_STACK_ARG &&
		    opts->stack_arg_slot >= 0) {
			const char *arg_buf;

			arg_buf = bpf_diag_scratch_buf(env, 0, NULL);
			if (arg_buf)
				bpf_diag_format_stack_arg((char *)arg_buf,
							  BPF_DIAG_SCRATCH_STR_LEN,
							  opts->stack_arg_slot);
			else
				arg_buf = "this outgoing stack argument";
			bpf_diag_write(env,
				       "  no retained writes for %s on this path\n",
				       arg_buf);
		} else {
			bpf_diag_write(env,
				       "  no retained diagnostic events on this path\n");
		}
	}
}
