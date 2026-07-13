// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

#include <linux/bitmap.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/overflow.h>
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
#define BPF_DIAG_SCRATCH_REG_CNT CALLER_SAVED_REGS
#define BPF_DIAG_TEXT_LEN 160

struct bpf_diag_reg_snapshot {
	u32 type;
	u32 btf_id;
	const struct bpf_map *map_ptr;
	const struct btf *btf;
	struct tnum var_off;
	struct cnum64 r64;
};

enum bpf_diag_history_kind {
	BPF_DIAG_HISTORY_BRANCH,
	BPF_DIAG_HISTORY_MOD,
	BPF_DIAG_HISTORY_REF_ACQUIRE,
	BPF_DIAG_HISTORY_REF_RELEASE,
	BPF_DIAG_HISTORY_CONTEXT,
};

struct bpf_diag_event_hdr {
	u32 insn_idx : 24;
	u32 kind : 8;
};

struct bpf_diag_history_event {
	union {
		struct {
			u32 insn_idx : 24;
			u32 kind : 8;
		};
		struct {
			struct bpf_diag_event_hdr hdr;
			bool cond_true;
		} branch;
		struct {
			struct bpf_diag_event_hdr hdr;
			struct bpf_diag_mod_target target;
			struct bpf_diag_mod_target origin;
			struct bpf_diag_reg_snapshot old, new;
			u8 reason;
			bool origin_valid;
		} mod;
		struct {
			struct bpf_diag_event_hdr hdr;
			u32 ref_id;
		} ref;
		struct {
			struct bpf_diag_event_hdr hdr;
			u32 depth;
			u8 kind;
			bool enter;
		} ctx;
	};
};

enum bpf_diag_history_scope {
	BPF_DIAG_HISTORY_SCOPE_ALL,
	BPF_DIAG_HISTORY_SCOPE_REG,
	BPF_DIAG_HISTORY_SCOPE_STACK_ARG,
	BPF_DIAG_HISTORY_SCOPE_REF,
	BPF_DIAG_HISTORY_SCOPE_CONTEXT,
};

struct bpf_diag_history_opts {
	enum bpf_diag_history_scope scope;
	u32 frameno;
	int regno;
	int stack_arg_slot;
	u32 ref_id;
	enum bpf_diag_context_kind ctx_kind;
	u32 ctx_depth;
};

static void diag_print_history(struct bpf_verifier_env *env,
			       const struct bpf_diag_history_opts *opts);

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
	int error;
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

struct bpf_diag_fmt_buf {
	struct list_head node;
	char data[];
};

struct bpf_diag_scratch {
	char str[BPF_DIAG_SCRATCH_STR_CNT][BPF_DIAG_SCRATCH_STR_LEN];
	struct bpf_reg_state regs[BPF_DIAG_SCRATCH_REG_CNT];
	struct bpf_linfo_source source;
	struct bpf_diag_source_line source_lines[BPF_DIAG_CONTEXT_CNT];
	struct bpf_diag_insn insns[BPF_DIAG_CONTEXT_CNT];
	unsigned long *history_bitmap;
	u32 history_bitmap_nbits;
	struct bpf_diag_reg_fmt reg_fmt;
};

struct bpf_diag {
	struct bpf_diag_log log;
	struct bpf_diag_scratch scratch;
	struct list_head fmt_bufs;
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
	if (!env->diag)
		return -ENOMEM;

	INIT_LIST_HEAD(&env->diag->fmt_bufs);
	return 0;
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

static void diag_fmt_set_error(struct bpf_diag *diag, int error)
{
	if (!diag->log.error)
		diag->log.error = error;
}

static char *diag_fmt_alloc(struct bpf_verifier_env *env, size_t size)
{
	struct bpf_diag *diag = diag_env(env);
	struct bpf_diag_fmt_buf *buf;

	if (!diag)
		return NULL;

	buf = kmalloc(struct_size(buf, data, size), GFP_KERNEL_ACCOUNT);
	if (!buf) {
		diag_fmt_set_error(diag, -ENOMEM);
		return NULL;
	}
	list_add_tail(&buf->node, &diag->fmt_bufs);
	return buf->data;
}

char *bpf_diag_fmt_buf(struct bpf_verifier_env *env, size_t size)
{
	char *buf;

	if (!size)
		return NULL;

	buf = diag_fmt_alloc(env, size);
	if (buf)
		buf[0] = '\0';
	return buf;
}

const char *bpf_diag_vfmt(struct bpf_verifier_env *env, const char *fmt, va_list args)
{
	struct bpf_diag *diag = diag_env(env);
	va_list copy;
	char *buf;
	int len;

	va_copy(copy, args);
	len = vsnprintf(NULL, 0, fmt, copy);
	va_end(copy);
	if (len < 0 || len == INT_MAX) {
		if (diag)
			diag_fmt_set_error(diag, -EOVERFLOW);
		return "";
	}

	buf = diag_fmt_alloc(env, len + 1);
	if (buf)
		vsnprintf(buf, len + 1, fmt, args);
	return buf ?: "";
}

const char *bpf_diag_fmt(struct bpf_verifier_env *env, const char *fmt, ...)
{
	const char *buf;
	va_list args;

	va_start(args, fmt);
	buf = bpf_diag_vfmt(env, fmt, args);
	va_end(args);
	return buf;
}

const char *bpf_diag_fmt_btf_type(struct bpf_verifier_env *env, const struct btf *btf, u32 type_id)
{
	char *buf = bpf_diag_fmt_buf(env, BPF_DIAG_SCRATCH_STR_LEN);

	if (!buf)
		return "";

	bpf_diag_format_btf_type(buf, BPF_DIAG_SCRATCH_STR_LEN, btf, type_id);
	return buf;
}

static void diag_fmt_free(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = diag_env(env);
	struct bpf_diag_fmt_buf *buf, *tmp;

	if (!diag)
		return;

	list_for_each_entry_safe(buf, tmp, &diag->fmt_bufs, node) {
		list_del(&buf->node);
		kfree(buf);
	}
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

struct bpf_reg_state *bpf_diag_reg_scratch(struct bpf_verifier_env *env, unsigned int slot)
{
	struct bpf_diag_scratch *scratch = diag_scratch(env);

	if (!scratch || slot >= BPF_DIAG_SCRATCH_REG_CNT)
		return NULL;
	return &scratch->regs[slot];
}

static void diag_write(struct bpf_verifier_env *env, const char *fmt, ...)
{
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(&env->log, fmt, args);
	va_end(args);
}

static struct bpf_diag_log *diag_event_log(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = diag_env(env);

	return diag ? &diag->log : NULL;
}

u32 bpf_diag_event_log_pos(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = diag_env(env);

	if (!diag)
		return 0;
	return diag->log.cnt;
}

void bpf_diag_event_log_reset(struct bpf_verifier_env *env, u32 pos)
{
	struct bpf_diag *diag = env->diag;
	struct bpf_diag_log *log;
	u32 end;

	if (!diag)
		return;

	log = &diag->log;
	end = log->cnt;
	if (WARN_ON_ONCE(pos > end))
		pos = end;

	log->cnt = pos;
}

u32 bpf_diag_irq_depth(const struct bpf_verifier_state *state)
{
	u32 depth = 0;
	int i;

	for (i = 0; i < state->acquired_refs; i++) {
		if (state->refs[i].type == REF_TYPE_IRQ)
			depth++;
	}

	return depth;
}

void bpf_diag_free(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = env->diag;

	if (!diag)
		return;

	diag_fmt_free(env);
	kfree(diag->log.events);
	kfree(diag->scratch.history_bitmap);
	kfree(diag);
	env->diag = NULL;
}

static const struct bpf_diag_history_event *diag_history_event(const struct bpf_diag_log *log,
							       u32 idx)
{
	return &log->events[idx];
}

static int diag_append_history(struct bpf_verifier_env *env,
			       const struct bpf_diag_history_event *event)
{
	struct bpf_diag_history_event *events;
	struct bpf_diag_log *log;
	u32 cap;

	log = diag_event_log(env);
	if (!log)
		return 0;
	if (log->error)
		return log->error;

	if (log->cnt < log->cap) {
		log->events[log->cnt++] = *event;
		return 0;
	}

	cap = log->cap ? log->cap * 2 : 64;
	if (cap < log->cap) {
		log->error = -EOVERFLOW;
		return log->error;
	}

	events = krealloc_array(log->events, cap, sizeof(*events), GFP_KERNEL_ACCOUNT);
	if (!events) {
		log->error = -ENOMEM;
		return log->error;
	}
	log->events = events;
	log->cap = cap;
	log->events[log->cnt++] = *event;
	return 0;
}

int bpf_diag_error(const struct bpf_verifier_env *env)
{
	return env->diag ? env->diag->log.error : 0;
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

		diag_write(env, "%s%.*s\n", prefix, len, line);

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

void bpf_diag_format_btf_type(char *buf, size_t size, const struct btf *btf, u32 type_id)
{
	size_t len;
	int ret;

	buf[0] = '\0';
	ret = btf_type_snprintf_show_name(btf, type_id, buf, size);
	if (ret < 0 || !buf[0]) {
		scnprintf(buf, size, "BTF type ID %u", type_id);
		return;
	}

	len = strlen(buf);
	if (len && buf[len - 1] == '{')
		buf[len - 1] = '\0';
}

const char *bpf_diag_format_btf_type_scratch(struct bpf_verifier_env *env, unsigned int slot,
					     const struct btf *btf, u32 type_id)
{
	size_t size;
	char *buf = bpf_diag_scratch_buf(env, slot, &size);

	if (!buf)
		return "";

	bpf_diag_format_btf_type(buf, size, btf, type_id);
	return buf;
}

static void diag_vprint_indented(struct bpf_verifier_env *env, const char *fmt, va_list args)
{
	char *buf;

	if (!bpf_diag_enabled(env))
		return;

	buf = kvasprintf(GFP_KERNEL_ACCOUNT, fmt, args);
	if (!buf) {
		diag_write(env, "%s<failed to allocate diagnostic text>\n", BPF_DIAG_TEXT_INDENT);
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
		diag_write(env, "\nVerification failed: %s\n", category);
		return;
	}

	first = toupper(problem[0]);
	diag_write(env, "\nVerification failed: %s: %c%s\n", category, first, problem + 1);
}

static void diag_report_reason(struct bpf_verifier_env *env, const char *fmt, ...) __printf(2, 3);
static void diag_report_suggestion(struct bpf_verifier_env *env, const char *fmt, ...)
	__printf(2, 3);

static void diag_report_section(struct bpf_verifier_env *env, const char *title)
{
	if (!bpf_diag_enabled(env))
		return;

	diag_write(env, "\n%s:\n", title);
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
	diag_write(env, "\n");
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
		diag_write(env, "  insn %u\n", insn_idx);
		diag_print_source_annotation(env, 0, 0, label, msg);
		goto out_free_msg;
	}

	func = diag_func_name(env, insn_idx);
	if (func && *func)
		diag_write(env, "  %s @ %s:%d:%d\n", func, src->file, src->line_num, src->line_col);
	else
		diag_write(env, "  %s:%d:%d\n", src->file, src->line_num, src->line_col);

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

static u32 diag_current_frameno(const struct bpf_verifier_env *env)
{
	return env->cur_state->frame[env->cur_state->curframe]->frameno;
}

static const char *diag_context_name(enum bpf_diag_context_kind kind)
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

void bpf_diag_report_register_type(struct bpf_verifier_env *env, u32 insn_idx, int regno,
				   const char *problem, const char *reason, const char *suggestion)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REG,
		.frameno = diag_current_frameno(env),
		.regno = regno,
	};

	bpf_diag_report_header(env, CATEGORY_REGISTER_TYPE_SAFETY, problem);
	diag_report_reason(env, "%s", reason);

	diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s", problem);

	if (regno >= 0)
		diag_print_history(env, &opts);

	diag_report_suggestion(env, "%s", suggestion);
}

const char *bpf_diag_reg_type_plain(struct bpf_verifier_env *env, enum bpf_reg_type type)
{
	switch (base_type(type)) {
	case NOT_INIT:
		return "an uninitialized value";
	case SCALAR_VALUE:
		return "an integer scalar";
	case PTR_TO_CTX:
		return "a context pointer";
	case PTR_TO_STACK:
		return "a stack pointer";
	case PTR_TO_MAP_VALUE:
		if (type_may_be_null(type))
			return "a nullable map value pointer";
		return "a map value pointer";
	case PTR_TO_MEM:
		if (type_may_be_null(type))
			return "a nullable memory pointer";
		return "a memory pointer";
	case PTR_TO_BTF_ID:
		if (type_may_be_null(type))
			return "a nullable kernel object pointer";
		if (type_is_non_owning_ref(type))
			return "a borrowed allocated object pointer";
		if (type_is_ptr_alloc_obj(type))
			return "an owned allocated object pointer";
		if (type_flag(type) & PTR_UNTRUSTED)
			return "an untrusted kernel object pointer";
		return "a kernel object pointer";
	default:
		return reg_type_str(env, type);
	}
}

static const char *diag_arg_ordinal(int argno)
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

void bpf_diag_report_call_type(struct bpf_verifier_env *env, u32 insn_idx, int argno, int regno,
			       int stack_arg_slot, const char *call_name, const char *arg_name,
			       const char *reason, const char *suggestion)
{
	struct bpf_diag_history_opts opts = {
		.frameno = diag_current_frameno(env),
	};
	const char *ordinal = diag_arg_ordinal(argno);
	const char *arg_desc;
	bool print_history = true;

	if (regno >= 0) {
		opts.scope = BPF_DIAG_HISTORY_SCOPE_REG;
		opts.regno = regno;
	} else if (stack_arg_slot >= 0) {
		opts.scope = BPF_DIAG_HISTORY_SCOPE_STACK_ARG;
		opts.stack_arg_slot = stack_arg_slot;
	} else {
		print_history = false;
	}

	if (ordinal && arg_name)
		arg_desc = bpf_diag_fmt(env, "%s argument (%s)", ordinal, arg_name);
	else if (ordinal)
		arg_desc = bpf_diag_fmt(env, "%s argument", ordinal);
	else if (arg_name)
		arg_desc = bpf_diag_fmt(env, "argument %s", arg_name);
	else
		arg_desc = "argument";

	bpf_diag_report_header(env, CATEGORY_CALL_TYPE_SAFETY, "invalid call argument");
	diag_report_reason(env, "The %s to %s does not satisfy the verifier contract: %s.",
			   arg_desc, call_name, reason);

	diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "invalid %s for %s", arg_desc, call_name);

	if (print_history)
		diag_print_history(env, &opts);

	diag_report_suggestion(env, "%s", suggestion);
	diag_fmt_free(env);
}

static const char *diag_context_constraint(enum bpf_diag_context_kind kind)
{
	switch (kind) {
	case BPF_DIAG_CONTEXT_RCU:
		return "RCU read-side critical sections cannot call operations that may sleep";
	case BPF_DIAG_CONTEXT_PREEMPT:
		return "preemption-disabled code cannot call operations that may sleep";
	case BPF_DIAG_CONTEXT_IRQ:
		return "IRQ-disabled code cannot call operations that may sleep";
	case BPF_DIAG_CONTEXT_LOCK:
		return "code holding a BPF spin lock cannot call operations that may sleep";
	case BPF_DIAG_CONTEXT_NONE:
	default:
		return NULL;
	}
}

static void diag_format_active_context(char *buf, size_t size, u32 depth, const char *context)
{
	if (depth == 1)
		scnprintf(buf, size, "an active %s (depth 1)", context);
	else
		scnprintf(buf, size, "%u active %ss (depth %u)", depth, context, depth);
}

static u32 diag_context_depth(struct bpf_verifier_env *env, enum bpf_diag_context_kind kind)
{
	switch (kind) {
	case BPF_DIAG_CONTEXT_RCU:
		return env->cur_state->active_rcu_locks;
	case BPF_DIAG_CONTEXT_PREEMPT:
		return env->cur_state->active_preempt_locks;
	case BPF_DIAG_CONTEXT_IRQ:
		return bpf_diag_irq_depth(env->cur_state);
	case BPF_DIAG_CONTEXT_LOCK:
		return env->cur_state->active_locks;
	case BPF_DIAG_CONTEXT_NONE:
	default:
		return 0;
	}
}

static void diag_ctx_forbidden(struct bpf_verifier_env *env, u32 insn_idx, const char *operation,
			       enum bpf_diag_context_kind ctx_kind, const char *context,
			       const char *suggestion)
{
	u32 depth = diag_context_depth(env, ctx_kind);
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_CONTEXT,
		.ctx_kind = ctx_kind,
		.ctx_depth = depth,
	};
	const char *depth_buf;

	bpf_diag_report_header(env, CATEGORY_EXECUTION_CONTEXT_SAFETY,
			       "operation is not allowed in this context");
	if (diag_context_constraint(ctx_kind)) {
		if (depth) {
			depth_buf = bpf_diag_scratch_buf(env, 2, NULL);
			if (depth_buf)
				diag_format_active_context((char *)depth_buf,
							   BPF_DIAG_SCRATCH_STR_LEN, depth,
							   context);
			else
				depth_buf = "";
			diag_report_reason(env,
					   "The operation %s cannot be used in %s because %s. This "
					   "path is still inside %s.",
					   operation, context, diag_context_constraint(ctx_kind),
					   depth_buf);
		} else {
			diag_report_reason(env, "The operation %s cannot be used in %s because %s.",
					   operation, context, diag_context_constraint(ctx_kind));
		}
	} else {
		diag_report_reason(env, "The operation %s cannot be used in %s.", operation,
				   context);
	}

	diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s is not allowed in %s", operation,
			       context);

	if (ctx_kind != BPF_DIAG_CONTEXT_NONE)
		diag_print_history(env, &opts);

	diag_report_suggestion(env, "%s", suggestion);
}

static void diag_ctx_active(struct bpf_verifier_env *env, u32 insn_idx, const char *operation,
			    enum bpf_diag_context_kind ctx_kind, const char *context,
			    const char *suggestion)
{
	u32 depth = diag_context_depth(env, ctx_kind);
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_CONTEXT,
		.ctx_kind = ctx_kind,
		.ctx_depth = depth,
	};
	const char *depth_buf;

	depth_buf = bpf_diag_scratch_buf(env, 2, NULL);
	if (depth_buf)
		diag_format_active_context((char *)depth_buf, BPF_DIAG_SCRATCH_STR_LEN, depth,
					   context);
	else
		depth_buf = "";

	bpf_diag_report_header(env, CATEGORY_EXECUTION_CONTEXT_SAFETY,
			       "operation is not allowed in this context");
	diag_report_reason(env,
			   "The operation %s cannot be used while this path is still inside %s. "
			   "Leave the region before this operation.",
			   operation, depth_buf);

	diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s is not allowed before leaving %s",
			       operation, context);

	diag_print_history(env, &opts);

	diag_report_suggestion(env, "%s", suggestion);
}

static void diag_ctx_underflow(struct bpf_verifier_env *env, u32 insn_idx, const char *operation,
			       enum bpf_diag_context_kind ctx_kind, const char *suggestion)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_CONTEXT,
		.ctx_kind = ctx_kind,
	};
	const char *context = diag_context_name(ctx_kind);

	bpf_diag_report_header(env, CATEGORY_EXECUTION_CONTEXT_SAFETY, "unmatched context exit");
	diag_report_reason(env,
			   "The operation %s tries to leave %s, but this path has no active %s to "
			   "leave. The current depth is 0.",
			   operation, context, context);

	diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s has no matching enter on this path",
			       operation);

	diag_print_history(env, &opts);

	diag_report_suggestion(env, "%s", suggestion);
}

void bpf_diag_ctx(struct bpf_verifier_env *env, enum bpf_diag_ctx_report report, u32 insn_idx,
		  const char *operation, enum bpf_diag_context_kind ctx_kind, const char *context,
		  const char *suggestion)
{
	switch (report) {
	case BPF_DIAG_CTX_FORBIDDEN:
		diag_ctx_forbidden(env, insn_idx, operation, ctx_kind, context, suggestion);
		return;
	case BPF_DIAG_CTX_ACTIVE:
		diag_ctx_active(env, insn_idx, operation, ctx_kind, context, suggestion);
		return;
	case BPF_DIAG_CTX_UNDERFLOW:
		diag_ctx_underflow(env, insn_idx, operation, ctx_kind, suggestion);
		return;
	}
}

void bpf_diag_report_program_structure(struct bpf_verifier_env *env, u32 insn_idx,
				       const char *problem, const char *suggestion,
				       const char *reason_fmt, ...)
{
	va_list args;

	bpf_diag_report_header(env, CATEGORY_PROGRAM_STRUCTURE, problem);
	diag_report_section(env, "Reason");

	va_start(args, reason_fmt);
	diag_vprint_indented(env, reason_fmt, args);
	va_end(args);

	diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s", problem);

	diag_report_suggestion(env, "%s", suggestion);
}
void bpf_diag_report_invalid_deref(struct bpf_verifier_env *env, u32 insn_idx, int regno,
				   const char *reg_name, const struct bpf_reg_state *reg,
				   enum bpf_diag_invalid_deref_kind kind, s64 offset)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REG,
		.frameno = diag_current_frameno(env),
		.regno = regno,
	};
	const char *type_name = bpf_diag_reg_type_plain(env, reg->type);

	bpf_diag_report_header(env, CATEGORY_REGISTER_TYPE_SAFETY, "invalid dereference");

	switch (kind) {
	case BPF_DIAG_DEREF_SCALAR:
		diag_report_reason(env, "%s is an integer scalar here, not a pointer to memory.",
				   reg_name);
		break;
	case BPF_DIAG_DEREF_NULLABLE_PTR:
		diag_report_reason(env,
				   "%s may be NULL here (%s). The program could dereference NULL "
				   "on this path, so the verifier cannot prove this access is "
				   "safe.",
				   reg_name, type_name);
		break;
	case BPF_DIAG_DEREF_MODIFIED_PTR:
		diag_report_reason(env,
				   "%s has offset %lld here, but this pointer type must be "
				   "dereferenced in its original form.",
				   reg_name, offset);
		break;
	case BPF_DIAG_DEREF_INVALID_PTR:
	default:
		diag_report_reason(env,
				   "%s has type %s here, which is not valid for this memory "
				   "access.",
				   reg_name, type_name);
		break;
	}

	diag_report_section(env, "At");
	if (kind == BPF_DIAG_DEREF_MODIFIED_PTR)
		bpf_diag_report_source(env, insn_idx, "error",
				       "dereference requires the original %s pointer", type_name);
	else
		bpf_diag_report_source(env, insn_idx, "error", "invalid dereference of %s (%s)",
				       reg_name, type_name);

	if (regno >= 0)
		diag_print_history(env, &opts);

	switch (kind) {
	case BPF_DIAG_DEREF_NULLABLE_PTR:
		diag_report_suggestion(env, "Add a NULL check before the access and dereference "
					    "the pointer only on the non-NULL path.");
		break;
	case BPF_DIAG_DEREF_MODIFIED_PTR:
		diag_report_suggestion(env, "Preserve the original pointer in another register, or "
					    "use only offsets this pointer type permits before "
					    "dereferencing it.");
		break;
	case BPF_DIAG_DEREF_SCALAR:
	case BPF_DIAG_DEREF_INVALID_PTR:
	default:
		diag_report_suggestion(env, "Preserve a pointer-valued register where needed, or "
					    "reload and revalidate the pointer after scalar "
					    "arithmetic, helper calls, or other operations that "
					    "can invalidate it.");
		break;
	}
}

void bpf_diag_report_unreadable_reg(struct bpf_verifier_env *env, u32 insn_idx, int regno)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REG,
		.frameno = diag_current_frameno(env),
		.regno = regno,
	};

	bpf_diag_report_header(env, CATEGORY_REGISTER_TYPE_SAFETY, "unreadable register");
	diag_report_reason(env,
			   "R%d is not readable here. A previous operation may have invalidated "
			   "this register, so the verifier cannot use it as an input.",
			   regno);

	diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "R%d is not readable", regno);

	if (regno >= 0)
		diag_print_history(env, &opts);

	diag_report_suggestion(env, "Avoid using the register after it is invalidated, or reload "
				    "and revalidate a fresh pointer before this instruction.");
}

static int diag_stack_argno(u8 slot)
{
	return MAX_BPF_FUNC_REG_ARGS + slot + 1;
}

static void diag_format_stack_arg(char *buf, size_t size, u8 slot, const char *arg_name)
{
	int argno = diag_stack_argno(slot);
	const char *ordinal = diag_arg_ordinal(argno);

	if (ordinal && arg_name)
		scnprintf(buf, size, "outgoing stack argument %u (%s argument, %s)", slot + 1,
			  ordinal, arg_name);
	else if (ordinal)
		scnprintf(buf, size, "outgoing stack argument %u (%s argument)", slot + 1, ordinal);
	else if (arg_name)
		scnprintf(buf, size, "outgoing stack argument %u (%s)", slot + 1, arg_name);
	else
		scnprintf(buf, size, "outgoing stack argument %u", slot + 1);
}

void bpf_diag_report_stack_arg_uninit(struct bpf_verifier_env *env, u32 insn_idx, int nargs,
				      int stack_arg_slot, const char *callee_name,
				      const char *arg_name)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_STACK_ARG,
		.frameno = diag_current_frameno(env),
		.stack_arg_slot = stack_arg_slot,
	};
	const char *arg_buf;

	arg_buf = bpf_diag_scratch_buf(env, 1, NULL);
	if (arg_buf)
		diag_format_stack_arg((char *)arg_buf, BPF_DIAG_SCRATCH_STR_LEN, stack_arg_slot,
				      arg_name);
	else
		arg_buf = "";
	bpf_diag_report_header(env, CATEGORY_REGISTER_TYPE_SAFETY, "missing stack argument");
	if (callee_name && *callee_name)
		diag_report_reason(env,
				   "Function %s expects %d arguments, but %s is not initialized at "
				   "this call.",
				   callee_name, nargs, arg_buf);
	else
		diag_report_reason(env,
				   "The callee expects %d arguments, but %s is not initialized at "
				   "this call.",
				   nargs, arg_buf);

	diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s is not initialized", arg_buf);

	if (stack_arg_slot >= 0)
		diag_print_history(env, &opts);

	diag_report_suggestion(env, "Write the outgoing stack argument after any operation that "
				    "may invalidate stored pointer values, and before making this "
				    "call.");
}

void bpf_diag_report_memory(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
			    const char *reason, const char *suggestion)
{
	bpf_diag_report_header(env, CATEGORY_MEMORY_SAFETY, problem);
	diag_report_reason(env, "%s", reason);

	diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s", problem);

	diag_report_suggestion(env, "%s", suggestion);
}

int bpf_diag_record_branch(struct bpf_verifier_env *env, u32 insn_idx, bool cond_true)
{
	struct bpf_diag_history_event event = {
		.branch = {
			.hdr = {
				.insn_idx = insn_idx,
				.kind = BPF_DIAG_HISTORY_BRANCH,
			},
			.cond_true = cond_true,
		},
	};

	return diag_append_history(env, &event);
}

static void diag_snapshot_reg(struct bpf_diag_reg_snapshot *snapshot,
			      const struct bpf_reg_state *reg)
{
	snapshot->type = reg->type;
	if (type_is_map_ptr(reg->type))
		snapshot->map_ptr = reg->map_ptr;
	if (base_type(reg->type) == PTR_TO_BTF_ID && reg->btf && reg->btf_id) {
		snapshot->btf_id = reg->btf_id;
		snapshot->btf = reg->btf;
	}
	snapshot->var_off = reg->var_off;
	snapshot->r64 = reg->r64;
}

static bool diag_snapshot_eq(const struct bpf_diag_reg_snapshot *old,
			     const struct bpf_diag_reg_snapshot *new)
{
	return old->type == new->type && old->map_ptr == new->map_ptr && old->btf == new->btf &&
	       old->btf_id == new->btf_id && old->var_off.value == new->var_off.value &&
	       old->var_off.mask == new->var_off.mask && old->r64.base == new->r64.base &&
	       old->r64.size == new->r64.size;
}

static bool diag_mod_snapshot_eq(const struct bpf_diag_history_event *event)
{
	return diag_snapshot_eq(&event->mod.old, &event->mod.new);
}

static bool diag_mod_insn_origin(struct bpf_verifier_env *env, u32 insn_idx,
				 const struct bpf_diag_mod_target *target,
				 struct bpf_diag_mod_target *origin)
{
	const struct bpf_insn *insn = &env->prog->insnsi[insn_idx];
	u8 class = BPF_CLASS(insn->code);
	u32 frameno;

	if (target->kind == BPF_DIAG_MOD_TARGET_REG && (class == BPF_ALU || class == BPF_ALU64) &&
	    BPF_OP(insn->code) == BPF_MOV && BPF_SRC(insn->code) == BPF_X) {
		*origin = bpf_diag_reg_target(target->frameno, insn->src_reg);
		return true;
	}

	if ((target->kind != BPF_DIAG_MOD_TARGET_STACK_ARG &&
	     target->kind != BPF_DIAG_MOD_TARGET_STACK_SLOT) ||
	    class != BPF_STX)
		return false;

	frameno = env->cur_state->frame[env->cur_state->curframe]->frameno;
	*origin = bpf_diag_reg_target(frameno, insn->src_reg);
	return true;
}

void bpf_diag_record_mod(struct bpf_verifier_env *env, u32 insn_idx,
			 struct bpf_diag_mod_target target, enum bpf_diag_mod_reason reason,
			 const struct bpf_reg_state *old_reg, const struct bpf_reg_state *new_reg,
			 const struct bpf_diag_mod_target *origin)
{
	struct bpf_diag_history_event event = {
		.mod = {
			.hdr = {
				.insn_idx = insn_idx,
				.kind = BPF_DIAG_HISTORY_MOD,
			},
			.target = target,
			.reason = reason,
		},
	};

	if (old_reg && new_reg) {
		diag_snapshot_reg(&event.mod.old, old_reg);
		diag_snapshot_reg(&event.mod.new, new_reg);
		if ((reason == BPF_DIAG_MOD_WRITE || reason == BPF_DIAG_MOD_SPILL) &&
		    diag_mod_snapshot_eq(&event))
			return;
	}
	if (origin) {
		event.mod.origin = *origin;
		event.mod.origin_valid = true;
	} else {
		event.mod.origin_valid =
			diag_mod_insn_origin(env, insn_idx, &target, &event.mod.origin);
	}

	diag_append_history(env, &event);
}

static void diag_record_ref(struct bpf_verifier_env *env, u32 insn_idx, u8 kind, u32 ref_id)
{
	struct bpf_diag_history_event event = {
		.ref = {
			.hdr = {
				.insn_idx = insn_idx,
				.kind = kind,
			},
			.ref_id = ref_id,
		},
	};

	diag_append_history(env, &event);
}

void bpf_diag_record_ref_acquire(struct bpf_verifier_env *env, u32 insn_idx, u32 ref_id)
{
	diag_record_ref(env, insn_idx, BPF_DIAG_HISTORY_REF_ACQUIRE, ref_id);
}

void bpf_diag_record_ref_release(struct bpf_verifier_env *env, u32 insn_idx, u32 ref_id)
{
	diag_record_ref(env, insn_idx, BPF_DIAG_HISTORY_REF_RELEASE, ref_id);
}

void bpf_diag_record_context(struct bpf_verifier_env *env, u32 insn_idx,
			     enum bpf_diag_context_event_kind ctx_kind, bool enter, u32 depth)
{
	/*
	 * Keep leave events so context rendering can stop at a depth-zero exit
	 * and show nested-region depth accurately for the active path.
	 */
	struct bpf_diag_history_event event = {
		.ctx = {
			.hdr = {
				.insn_idx = insn_idx,
				.kind = BPF_DIAG_HISTORY_CONTEXT,
			},
			.kind = ctx_kind,
			.enter = enter,
			.depth = depth,
		},
	};

	diag_append_history(env, &event);
}

static int diag_history_context_start_idx(const struct bpf_diag_log *log,
					  const struct bpf_diag_history_opts *opts)
{
	int i;

	if (!opts->ctx_depth)
		return 0;

	/* Find the most recent outermost entry, or a depth-zero exit. */
	for (i = log->cnt; i > 0; i--) {
		const struct bpf_diag_history_event *event;

		event = diag_history_event(log, i - 1);

		if (event->kind != BPF_DIAG_HISTORY_CONTEXT || event->ctx.kind != opts->ctx_kind)
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
	unsigned long *lineage;
	u32 lineage_start;
	bool lineage_valid;
};

static bool diag_target_matches(const struct bpf_diag_mod_target *event_target,
				const struct bpf_diag_mod_target *target)
{
	int slot_off;

	if (event_target->frameno != target->frameno)
		return false;

	if (event_target->kind == BPF_DIAG_MOD_TARGET_STACK_RANGE &&
	    target->kind == BPF_DIAG_MOD_TARGET_STACK_SLOT) {
		slot_off = -(target->spi + 1) * BPF_REG_SIZE;
		return event_target->range.min_off < slot_off + BPF_REG_SIZE &&
		       event_target->range.max_off > slot_off;
	}

	if (event_target->kind != target->kind)
		return false;

	switch (target->kind) {
	case BPF_DIAG_MOD_TARGET_REG:
		return event_target->regno == target->regno;
	case BPF_DIAG_MOD_TARGET_STACK_ARG:
		return event_target->stack_arg == target->stack_arg;
	case BPF_DIAG_MOD_TARGET_STACK_SLOT:
		return event_target->spi == target->spi;
	default:
		return false;
	}
}

static bool diag_mod_keeps_lineage(struct bpf_verifier_env *env,
				   const struct bpf_diag_history_event *event)
{
	const struct bpf_insn *insn;
	u8 class;

	if (event->mod.reason != BPF_DIAG_MOD_WRITE ||
	    event->mod.target.kind != BPF_DIAG_MOD_TARGET_REG)
		return false;

	insn = &env->prog->insnsi[event->insn_idx];
	class = BPF_CLASS(insn->code);
	if (class != BPF_ALU && class != BPF_ALU64)
		return false;

	switch (BPF_OP(insn->code)) {
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

static int diag_prepare_lineage(struct bpf_verifier_env *env, const struct bpf_diag_log *log,
				struct bpf_diag_history_filter *filter)
{
	struct bpf_diag_scratch *scratch = diag_scratch(env);
	unsigned long *bitmap;
	size_t words;

	if (!log->cnt)
		return 0;

	words = BITS_TO_LONGS(log->cnt);
	if (scratch->history_bitmap_nbits < log->cnt) {
		bitmap = krealloc_array(scratch->history_bitmap, words, sizeof(*bitmap),
					GFP_KERNEL_ACCOUNT);
		if (!bitmap)
			return -ENOMEM;
		scratch->history_bitmap = bitmap;
		scratch->history_bitmap_nbits = words * BITS_PER_LONG;
	}
	bitmap_zero(scratch->history_bitmap, log->cnt);
	filter->lineage = scratch->history_bitmap;
	return 0;
}

static int diag_build_lineage(struct bpf_verifier_env *env, const struct bpf_diag_log *log,
			      struct bpf_diag_history_filter *filter)
{
	const struct bpf_diag_history_opts *opts = filter->opts;
	struct bpf_diag_mod_target target;
	int i, err;

	if (!opts)
		return 0;

	if (opts->scope == BPF_DIAG_HISTORY_SCOPE_REG)
		target = bpf_diag_reg_target(opts->frameno, opts->regno);
	else if (opts->scope == BPF_DIAG_HISTORY_SCOPE_STACK_ARG)
		target = bpf_diag_stack_arg_target(opts->frameno, opts->stack_arg_slot);
	else
		return 0;

	err = diag_prepare_lineage(env, log, filter);
	if (err)
		return err;

	/*
	 * Find the nearest mutation of the active target. A fill or spill changes
	 * the target to its origin, so the same walk follows register/stack
	 * lineage recursively until it reaches the write that created the value.
	 */
	for (i = log->cnt; i > 0; i--) {
		const struct bpf_diag_history_event *event;

		event = diag_history_event(log, i - 1);
		if (event->kind != BPF_DIAG_HISTORY_MOD ||
		    !diag_target_matches(&event->mod.target, &target))
			continue;

		__set_bit(i - 1, filter->lineage);
		filter->lineage_start = i - 1;
		filter->lineage_valid = true;

		if (event->mod.origin_valid) {
			target = event->mod.origin;
			continue;
		}
		if (event->mod.reason != BPF_DIAG_MOD_WRITE &&
		    event->mod.reason != BPF_DIAG_MOD_SPILL)
			continue;
		if (diag_mod_keeps_lineage(env, event))
			continue;
		break;
	}

	return 0;
}

static int diag_history_start_idx(const struct bpf_diag_log *log,
				  const struct bpf_diag_history_filter *filter)
{
	const struct bpf_diag_history_opts *opts = filter->opts;
	int i;

	if (!opts || opts->scope == BPF_DIAG_HISTORY_SCOPE_ALL)
		return 0;
	if (opts->scope == BPF_DIAG_HISTORY_SCOPE_CONTEXT)
		return diag_history_context_start_idx(log, opts);
	if (filter->lineage_valid)
		return filter->lineage_start;
	if (opts->scope != BPF_DIAG_HISTORY_SCOPE_REF)
		return 0;

	for (i = log->cnt; i > 0; i--) {
		const struct bpf_diag_history_event *event;

		event = diag_history_event(log, i - 1);
		if (event->kind == BPF_DIAG_HISTORY_REF_ACQUIRE &&
		    event->ref.ref_id == opts->ref_id)
			return i - 1;
	}

	return 0;
}

static bool diag_history_event_visible(const struct bpf_diag_history_event *event, u32 idx,
				       const struct bpf_diag_history_filter *filter)
{
	const struct bpf_diag_history_opts *opts = filter->opts;

	if (!opts || opts->scope == BPF_DIAG_HISTORY_SCOPE_ALL)
		return event->kind != BPF_DIAG_HISTORY_CONTEXT;

	switch (event->kind) {
	case BPF_DIAG_HISTORY_BRANCH:
		return true;
	case BPF_DIAG_HISTORY_MOD:
		return filter->lineage_valid && test_bit(idx, filter->lineage);
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

static const char *diag_s64_bound_name(s64 value)
{
	if (value == S64_MIN)
		return "S64_MIN";
	if (value == S64_MAX)
		return "S64_MAX";
	return NULL;
}

static const char *diag_u64_bound_name(u64 value)
{
	if (value == U64_MAX)
		return "U64_MAX";
	return NULL;
}

static void diag_format_s64_value(char *buf, size_t size, s64 value)
{
	const char *name = diag_s64_bound_name(value);

	if (name)
		strscpy(buf, name, size);
	else
		scnprintf(buf, size, "%lld", value);
}

static void diag_format_u64_value(char *buf, size_t size, u64 value)
{
	const char *name = diag_u64_bound_name(value);

	if (name)
		strscpy(buf, name, size);
	else
		scnprintf(buf, size, "%llu", value);
}

static bool diag_range_unknown(s64 smin, s64 smax, u64 umin, u64 umax)
{
	return smin == S64_MIN && smax == S64_MAX && umin == 0 && umax == U64_MAX;
}

static bool diag_cnum64_unknown(struct cnum64 range)
{
	return diag_range_unknown(cnum64_smin(range), cnum64_smax(range), cnum64_umin(range),
				  cnum64_umax(range));
}

static bool diag_snapshot_unknown(const struct bpf_diag_reg_snapshot *snapshot)
{
	return tnum_is_unknown(snapshot->var_off) && diag_cnum64_unknown(snapshot->r64);
}

static void diag_format_scalar_range(struct bpf_diag_reg_fmt *fmt, char *buf, size_t size,
				     struct cnum64 range)
{
	s64 smin = cnum64_smin(range);
	s64 smax = cnum64_smax(range);
	u64 umin = cnum64_umin(range);
	u64 umax = cnum64_umax(range);

	diag_format_s64_value(fmt->smin_buf, sizeof(fmt->smin_buf), smin);
	diag_format_s64_value(fmt->smax_buf, sizeof(fmt->smax_buf), smax);
	diag_format_u64_value(fmt->umin_buf, sizeof(fmt->umin_buf), umin);
	diag_format_u64_value(fmt->umax_buf, sizeof(fmt->umax_buf), umax);

	scnprintf(buf, size, "signed range [%s, %s], unsigned range [%s, %s]", fmt->smin_buf,
		  fmt->smax_buf, fmt->umin_buf, fmt->umax_buf);
}

void bpf_diag_format_s64_sum(char *buf, size_t size, s64 value, int addend)
{
	s64 sum;

	if (check_add_overflow(value, (s64)addend, &sum)) {
		if (addend < 0)
			scnprintf(buf, size, "%lld plus %d (below S64_MIN)", value, addend);
		else
			scnprintf(buf, size, "%lld plus %d (above S64_MAX)", value, addend);
		return;
	}

	scnprintf(buf, size, "%lld", sum);
}

static void diag_format_access_offset(struct bpf_verifier_env *env, char *buf, size_t size, int off,
				      const struct bpf_reg_state *reg)
{
	struct bpf_diag_scratch *scratch = diag_scratch(env);
	struct bpf_diag_reg_fmt *fmt;
	char *start;

	if (tnum_is_const(reg->var_off)) {
		start = bpf_diag_scratch_buf(env, 2, NULL);
		if (!start) {
			scnprintf(buf, size, "constant");
			return;
		}
		bpf_diag_format_s64_sum(start, BPF_DIAG_SCRATCH_STR_LEN, (s64)reg->var_off.value,
					off);
		scnprintf(buf, size, "constant %s", start);
		return;
	}

	if (tnum_is_unknown(reg->var_off) && diag_cnum64_unknown(reg->r64)) {
		scnprintf(buf, size, "unbounded");
		return;
	}

	fmt = &scratch->reg_fmt;
	memset(fmt, 0, sizeof(*fmt));

	diag_format_scalar_range(fmt, fmt->range, sizeof(fmt->range), reg->r64);
	if (off)
		scnprintf(buf, size,
			  "variable: known bits %#llx, unknown mask %#llx, plus fixed offset %d; "
			  "%s",
			  (u64)reg->var_off.value, reg->var_off.mask, off, fmt->range);
	else
		scnprintf(buf, size, "variable: known bits %#llx, unknown mask %#llx; %s",
			  (u64)reg->var_off.value, reg->var_off.mask, fmt->range);
}

void bpf_diag_report_mem_bounds(struct bpf_verifier_env *env, u32 insn_idx, int regno,
				const char *reg_name, const char *type_name, const char *proof,
				int off, int size, u32 mem_size, const struct bpf_reg_state *reg)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REG,
		.frameno = diag_current_frameno(env),
		.regno = regno,
	};
	char *offset_desc;

	if (!bpf_diag_enabled(env))
		return;

	offset_desc = bpf_diag_scratch_buf(env, 0, NULL);

	diag_format_access_offset(env, offset_desc, BPF_DIAG_SCRATCH_STR_LEN, off, reg);

	bpf_diag_report_header(env, CATEGORY_MEMORY_SAFETY, "access outside bounds");
	diag_report_reason(env,
			   "The verifier cannot prove offset + access_size <= object_size. Here, "
			   "%s. %s is %s; offset is %s; access_size is %d; object_size is %u.",
			   proof, reg_name, type_name, offset_desc, size, mem_size);

	diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "access may be outside object bounds");

	if (regno >= 0)
		diag_print_history(env, &opts);

	diag_report_suggestion(env, "Add or adjust a bounds check that proves offset + access_size "
				    "stays within the object.");
}

static const char *diag_lock_name(const struct bpf_reference_state *lock)
{
	switch (lock->type) {
	case REF_TYPE_LOCK:
		return "bpf_spin_lock";
	case REF_TYPE_RES_LOCK:
		return "resource spin lock";
	case REF_TYPE_RES_LOCK_IRQ:
		return "IRQ-saving resource spin lock";
	default:
		return "lock";
	}
}

static void diag_res_report(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
			    const char *reason)
{
	bpf_diag_report_header(env, CATEGORY_RESOURCE_LIFETIME_SAFETY, problem);
	diag_report_reason(env, "%s", reason);

	diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s", problem);
}

void bpf_diag_res(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
		  const char *reason, const char *suggestion)
{
	diag_res_report(env, insn_idx, problem, reason);
	diag_report_suggestion(env, "%s", suggestion);
}

void bpf_diag_lock(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
		   const char *reason, const char *suggestion,
		   const struct bpf_reference_state *active_lock)
{
	diag_res_report(env, insn_idx, problem, reason);

	if (active_lock) {
		diag_report_section(env, "Active lock");
		bpf_diag_report_source(env, active_lock->insn_idx, "acquired",
				       "active %s has verifier identity %d",
				       diag_lock_name(active_lock), active_lock->id);
	}

	diag_report_suggestion(env, "%s", suggestion);
}

void bpf_diag_irq(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
		  const char *reason, const char *suggestion, u32 depth)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_CONTEXT,
		.ctx_kind = BPF_DIAG_CONTEXT_IRQ,
		.ctx_depth = depth,
	};

	bpf_diag_report_header(env, CATEGORY_RESOURCE_LIFETIME_SAFETY, problem);
	diag_report_reason(env, "%s", reason);

	diag_report_section(env, "At");
	bpf_diag_report_source(env, insn_idx, "error", "%s", problem);

	if (depth)
		diag_print_history(env, &opts);

	diag_report_suggestion(env, "%s", suggestion);
}

void bpf_diag_leak(struct bpf_verifier_env *env, u32 ref_id, u32 alloc_insn, u32 fail_insn)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REF,
		.ref_id = ref_id,
	};

	bpf_diag_report_header(env, CATEGORY_RESOURCE_LIFETIME_SAFETY, "unreleased resource");
	diag_report_reason(env,
			   "Owned resource (id=%u) was acquired at instruction %u and still needs "
			   "to be released before this exit path.",
			   ref_id, alloc_insn);

	diag_report_section(env, "At");
	bpf_diag_report_source(env, fail_insn, "error",
			       "owned resource (id=%u) still needs release", ref_id);

	diag_print_history(env, &opts);

	diag_report_suggestion(env, "Release or transfer ownership of the acquired resource on "
				    "every path before the program exits.");
}

static void diag_format_var_offset(struct bpf_diag_reg_fmt *fmt, char *buf, size_t size,
				   const struct bpf_diag_reg_snapshot *snapshot)
{
	if (tnum_is_const(snapshot->var_off)) {
		scnprintf(buf, size, "at offset %lld", (s64)snapshot->var_off.value);
		return;
	}

	if (diag_snapshot_unknown(snapshot)) {
		scnprintf(buf, size, "with unknown offset");
		return;
	}

	diag_format_scalar_range(fmt, fmt->range, sizeof(fmt->range), snapshot->r64);
	scnprintf(buf, size, "with variable offset: known bits %#llx, unknown mask %#llx, %s",
		  snapshot->var_off.value, snapshot->var_off.mask, fmt->range);
}

static bool diag_format_snapshot_btf_type(char *buf, size_t size,
					  const struct bpf_diag_reg_snapshot *snapshot)
{
	if (!snapshot->btf || !snapshot->btf_id)
		return false;

	bpf_diag_format_btf_type(buf, size, snapshot->btf, snapshot->btf_id);
	return true;
}

static const char *diag_reg_map_name(const struct bpf_map *map)
{
	if (!map || !map->name[0])
		return NULL;

	return map->name;
}

static void diag_format_reg_snapshot(struct bpf_verifier_env *env, struct bpf_diag_reg_fmt *fmt,
				     char *buf, size_t size,
				     const struct bpf_diag_reg_snapshot *snapshot)
{
	const char *type_name = reg_type_str(env, snapshot->type);
	const char *map_name;
	bool has_btf_type;

	diag_format_var_offset(fmt, fmt->offset_desc, sizeof(fmt->offset_desc), snapshot);
	has_btf_type =
		diag_format_snapshot_btf_type(fmt->btf_type, sizeof(fmt->btf_type), snapshot);

	if (snapshot->type == SCALAR_VALUE) {
		if (tnum_is_const(snapshot->var_off)) {
			scnprintf(buf, size, "integer scalar value %lld",
				  (s64)snapshot->var_off.value);
			return;
		}

		if (diag_snapshot_unknown(snapshot)) {
			scnprintf(buf, size, "integer scalar with unknown value");
			return;
		}

		if (cnum64_is_const(snapshot->r64)) {
			scnprintf(buf, size, "integer scalar value %lld",
				  cnum64_smin(snapshot->r64));
			return;
		}

		diag_format_scalar_range(fmt, fmt->range, sizeof(fmt->range), snapshot->r64);
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
		map_name = diag_reg_map_name(snapshot->map_ptr);
		if (map_name) {
			scnprintf(buf, size, "%s from %s %s",
				  type_may_be_null(snapshot->type) ? "nullable map value" :
								     "map value",
				  map_name, fmt->offset_desc);
			return;
		}
		scnprintf(buf, size, "%s %s",
			  type_may_be_null(snapshot->type) ? "nullable map value" : "map value",
			  fmt->offset_desc);
		return;
	}

	if (base_type(snapshot->type) == CONST_PTR_TO_MAP) {
		map_name = diag_reg_map_name(snapshot->map_ptr);
		if (map_name)
			scnprintf(buf, size, "map pointer for map %s", map_name);
		else
			scnprintf(buf, size, "map pointer");
		return;
	}

	if (type_is_non_owning_ref(snapshot->type)) {
		if (has_btf_type)
			scnprintf(buf, size, "borrowed allocated object pointer type=%s",
				  fmt->btf_type);
		else
			scnprintf(buf, size, "borrowed allocated object pointer");
		return;
	}

	if (type_is_ptr_alloc_obj(snapshot->type)) {
		if (has_btf_type)
			scnprintf(buf, size, "owned allocated object pointer type=%s",
				  fmt->btf_type);
		else
			scnprintf(buf, size, "owned allocated object pointer");
		return;
	}

	if (base_type(snapshot->type) == PTR_TO_BTF_ID && has_btf_type) {
		scnprintf(buf, size, "%s type=%s %s", type_name, fmt->btf_type, fmt->offset_desc);
		return;
	}

	scnprintf(buf, size, "%s %s", type_name, fmt->offset_desc);
}

static const char *diag_mod_target_desc(struct bpf_verifier_env *env,
					const struct bpf_diag_mod_target *target)
{
	switch (target->kind) {
	case BPF_DIAG_MOD_TARGET_REG:
		return bpf_diag_scratch_printf(env, 0, "R%u", target->regno);
	case BPF_DIAG_MOD_TARGET_STACK_ARG:
		return bpf_diag_scratch_printf(env, 0, "stack arg%d",
					       diag_stack_argno(target->stack_arg));
	case BPF_DIAG_MOD_TARGET_STACK_SLOT:
		return bpf_diag_scratch_printf(env, 0, "stack slot fp%d",
					       -(target->spi + 1) * BPF_REG_SIZE);
	default:
		return "value";
	}
}

static void diag_print_mod(struct bpf_verifier_env *env, const struct bpf_diag_history_event *event)
{
	struct bpf_diag_scratch *scratch = diag_scratch(env);
	struct bpf_diag_reg_fmt *fmt = &scratch->reg_fmt;
	const struct bpf_diag_mod_target *target = &event->mod.target;
	const char *target_desc, *reason = NULL;
	const char *label = "update";

	if (target->kind == BPF_DIAG_MOD_TARGET_STACK_RANGE) {
		bpf_diag_report_source(env, event->insn_idx, "invalidated",
				       "variable-offset stack write may affect bytes fp%d through "
				       "fp%d",
				       target->range.min_off, target->range.max_off - 1);
		return;
	}

	memset(fmt, 0, sizeof(*fmt));
	diag_format_reg_snapshot(env, fmt, fmt->old_buf, sizeof(fmt->old_buf), &event->mod.old);
	diag_format_reg_snapshot(env, fmt, fmt->new_buf, sizeof(fmt->new_buf), &event->mod.new);
	target_desc = diag_mod_target_desc(env, target);

	switch (event->mod.reason) {
	case BPF_DIAG_MOD_REF_RELEASE:
		reason = target->kind == BPF_DIAG_MOD_TARGET_REG ? "resource release invalidated "
								   "this pointer" :
								   "resource release invalidated "
								   "this value";
		break;
	case BPF_DIAG_MOD_PKT_DATA_CHANGE:
		reason = "packet data may have moved";
		break;
	case BPF_DIAG_MOD_NON_OWN_REF:
		reason = "leaving the protected region invalidated this borrowed pointer";
		break;
	case BPF_DIAG_MOD_CALLER_SAVED:
		reason = "call invalidated this caller-saved register";
		break;
	case BPF_DIAG_MOD_WRITE:
		if (target->kind == BPF_DIAG_MOD_TARGET_STACK_SLOT)
			reason = "a later stack write overwrote this spilled value";
		break;
	case BPF_DIAG_MOD_SPILL:
		label = "spilled";
		break;
	case BPF_DIAG_MOD_VAR_WRITE:
	default:
		break;
	}

	if (reason) {
		bpf_diag_report_source(env, event->insn_idx, "invalidated",
				       "%s: %s; previous value was %s", target_desc, reason,
				       fmt->old_buf);
		return;
	}

	bpf_diag_report_source(env, event->insn_idx, label, "%s changed from %s to %s", target_desc,
			       fmt->old_buf, fmt->new_buf);
}

static void diag_print_ref_event(struct bpf_verifier_env *env,
				 const struct bpf_diag_history_event *event)
{
	const char *label;

	label = event->kind == BPF_DIAG_HISTORY_REF_ACQUIRE ? "acquired" : "released";
	bpf_diag_report_source(env, event->insn_idx, label, "owned resource (id=%u)",
			       event->ref.ref_id);
}

static void diag_print_context_event(struct bpf_verifier_env *env,
				     const struct bpf_diag_history_event *event)
{
	bpf_diag_report_source(env, event->insn_idx, "context", "%s %s; depth is now %u",
			       event->ctx.enter ? "entered" : "left",
			       diag_context_name(event->ctx.kind), event->ctx.depth);
}

static void diag_print_history(struct bpf_verifier_env *env,
			       const struct bpf_diag_history_opts *opts)
{
	const struct bpf_diag_history_event *event;
	struct bpf_diag_history_filter filter = {
		.opts = opts,
	};
	const struct bpf_diag_log *log;
	bool first = true;
	bool visible = false;
	int start_idx, err;
	u32 i;

	if (!bpf_diag_enabled(env))
		return;

	if (!env->diag)
		return;
	log = &env->diag->log;

	err = diag_build_lineage(env, log, &filter);
	if (err) {
		diag_report_section(env, "Causal path");
		diag_write(env, "  failed to allocate causal-history scratch space\n");
		return;
	}

	start_idx = diag_history_start_idx(log, &filter);
	for (i = start_idx; i < log->cnt; i++) {
		event = diag_history_event(log, i);
		if (diag_history_event_visible(event, i, &filter)) {
			visible = true;
			break;
		}
	}

	if (!visible && opts && opts->scope == BPF_DIAG_HISTORY_SCOPE_STACK_ARG)
		return;

	diag_report_section(env, "Causal path");
	for (i = start_idx; i < log->cnt; i++) {
		event = diag_history_event(log, i);
		if (!diag_history_event_visible(event, i, &filter))
			continue;

		if (!first)
			diag_write(env, "\n");
		first = false;

		switch (event->kind) {
		case BPF_DIAG_HISTORY_BRANCH:
			bpf_diag_report_source(env, event->insn_idx, "branch",
					       "took the %s branch of this conditional, goto %s",
					       event->branch.cond_true ? "true" : "false",
					       event->branch.cond_true ? "followed" : "not followed");
			break;
		case BPF_DIAG_HISTORY_MOD:
			diag_print_mod(env, event);
			break;
		case BPF_DIAG_HISTORY_REF_ACQUIRE:
		case BPF_DIAG_HISTORY_REF_RELEASE:
			diag_print_ref_event(env, event);
			break;
		case BPF_DIAG_HISTORY_CONTEXT:
			diag_print_context_event(env, event);
			break;
		default:
			break;
		}
	}

	if (!visible)
		diag_write(env, "  no retained diagnostic events on this path\n");
}
