// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

#include <linux/bitmap.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/seq_buf.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/stdarg.h>
#include <linux/string.h>

#include "disasm.h"
#include "diagnostics.h"

#define MEMORY_SAFETY "Memory Safety"
#define REGISTER_TYPE_SAFETY "Register Type Safety"
#define CALL_TYPE_SAFETY "Call Type Safety"
#define RESOURCE_LIFETIME_SAFETY "Resource Lifetime Safety"
#define EXECUTION_CONTEXT_SAFETY "Execution Context Safety"
#define PROGRAM_STRUCTURE "Program Structure"
#define POLICY "Policy"
#define VERIFIER_LIMIT "Verifier Limit"

#define BPF_DIAG_TEXT_WIDTH 100
#define BPF_DIAG_TEXT_INDENT "  "
#define BPF_DIAG_MSG_LEN 512
#define BPF_DIAG_CONTEXT 2
#define BPF_DIAG_CONTEXT_CNT (1 + BPF_DIAG_CONTEXT * 2)
#define BPF_DIAG_SOURCE_LANE_WIDTH 88
#define BPF_DIAG_TAB_WIDTH 8
#define BPF_DIAG_FMT_CHUNK_SIZE 1024
#define BPF_DIAG_FMT_BUF_SIZE 256
#define BPF_DIAG_EVENT_LOG_MAX_SIZE (1U << 20)
#define DISASM_LINE_LEN 160

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

struct bpf_diag_history_event {
	u32 insn_idx : 24;
	u32 kind : 8;
	u8 in_lineage : 1;
	union {
		struct {
			bool cond_true;
		} branch;
		struct {
			struct bpf_diag_mod_target target;
			struct bpf_diag_mod_target origin;
			struct bpf_diag_reg_snapshot old, new;
			u8 reason;
			bool origin_valid;
		} mod;
		struct {
			u32 ref_id;
		} ref;
		struct {
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
static bool diag_target_matches(const struct bpf_diag_mod_target *event_target,
				const struct bpf_diag_mod_target *target);
struct disasm_line {
	char text[DISASM_LINE_LEN];
	int idx;
	bool valid;
};

struct disasm_ctx {
	struct bpf_verifier_env *env;
	struct seq_buf seq;
};

struct diag_fmt_chunk {
	struct list_head node;
	struct seq_buf seq;
	char data[];
};

struct diag_fmt_mark {
	struct diag_fmt_chunk *chunk;
	size_t len;
};

struct bpf_diag_log {
	struct bpf_diag_history_event *events;
	u32 cnt;
	u32 cap;
	u32 dropped;
	bool capped;
};

struct bpf_diag_scratch {
	struct bpf_linfo_source source_lines[BPF_DIAG_CONTEXT_CNT];
	struct disasm_line disasm_lines[BPF_DIAG_CONTEXT_CNT];
};

struct bpf_diag_mod_scope {
	struct bpf_reg_state target_reg_snapshot;
	struct bpf_diag_mod_target target;
	struct bpf_diag_mod_target origin;
	enum bpf_diag_mod_reason reason;
	u32 insn_idx;
	bool active;
	bool origin_valid;
};

struct bpf_diag {
	struct bpf_diag_log log;
	struct bpf_diag_scratch scratch;
	struct list_head fmt_chunks;
	struct bpf_diag_mod_scope mod;
};

bool bpf_diag_enabled(const struct bpf_verifier_env *env)
{
	return env->log.level & BPF_LOG_LEVEL;
}

static void diag_write(struct bpf_verifier_env *env, const char *fmt, ...) __printf(2, 3);

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
	INIT_LIST_HEAD(&env->diag->fmt_chunks);
	return 0;
}

static struct bpf_diag_scratch *diag_scratch(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = diag_env(env);

	return diag ? &diag->scratch : NULL;
}

static char *diag_fmt_alloc(struct bpf_verifier_env *env, size_t size)
{
	struct bpf_diag *diag = diag_env(env);
	struct diag_fmt_chunk *chunk;
	size_t capacity, available;
	char *buf;

	if (!diag || !size || size > INT_MAX)
		return NULL;

	if (!list_empty(&diag->fmt_chunks)) {
		chunk = list_last_entry(&diag->fmt_chunks, struct diag_fmt_chunk, node);
		available = seq_buf_get_buf(&chunk->seq, &buf);
		if (available >= size)
			goto commit;
	}

	capacity = max_t(size_t, BPF_DIAG_FMT_CHUNK_SIZE, size);
	chunk = kmalloc(struct_size(chunk, data, capacity), GFP_KERNEL_ACCOUNT);
	if (!chunk)
		return NULL;

	seq_buf_init(&chunk->seq, chunk->data, capacity);
	list_add_tail(&chunk->node, &diag->fmt_chunks);
	available = seq_buf_get_buf(&chunk->seq, &buf);
	if (WARN_ON_ONCE(available < size))
		return NULL;

commit:
	seq_buf_commit(&chunk->seq, size);
	return buf;
}

char *bpf_diag_fmt_buf(struct bpf_verifier_env *env, size_t size)
{
	char *buf;

	buf = diag_fmt_alloc(env, size);
	if (buf)
		buf[0] = '\0';
	return buf;
}

const char *bpf_diag_vfmt(struct bpf_verifier_env *env, const char *fmt, va_list args)
{
	va_list copy;
	char *buf;
	int len;

	va_copy(copy, args);
	len = vsnprintf(NULL, 0, fmt, copy);
	va_end(copy);
	if (len < 0 || len == INT_MAX)
		return "";

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

static struct diag_fmt_mark diag_fmt_save(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = diag_env(env);
	struct diag_fmt_mark mark = {};

	if (!diag || list_empty(&diag->fmt_chunks))
		return mark;

	mark.chunk = list_last_entry(&diag->fmt_chunks, struct diag_fmt_chunk, node);
	mark.len = mark.chunk->seq.len;
	return mark;
}

static void diag_fmt_restore(struct bpf_verifier_env *env, struct diag_fmt_mark mark)
{
	struct bpf_diag *diag = diag_env(env);
	struct diag_fmt_chunk *chunk;

	if (!diag)
		return;

	while (!list_empty(&diag->fmt_chunks)) {
		chunk = list_last_entry(&diag->fmt_chunks, struct diag_fmt_chunk, node);
		if (chunk == mark.chunk)
			break;
		list_del(&chunk->node);
		kfree(chunk);
	}

	if (mark.chunk) {
		mark.chunk->seq.len = mark.len;
		seq_buf_str(&mark.chunk->seq);
	}
}

static void diag_fmt_free(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = diag_env(env);
	struct diag_fmt_chunk *chunk, *tmp;

	if (!diag)
		return;

	list_for_each_entry_safe(chunk, tmp, &diag->fmt_chunks, node) {
		list_del(&chunk->node);
		kfree(chunk);
	}
}

void bpf_diag_free(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = env->diag;

	if (!diag)
		return;

	diag_fmt_free(env);
	kvfree(diag->log.events);
	kfree(diag);
	env->diag = NULL;
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

static void diag_append_history(struct bpf_verifier_env *env,
				const struct bpf_diag_history_event *event)
{
	struct bpf_diag_history_event *events;
	struct bpf_diag_log *log;
	u32 cap, max_events;

	log = diag_event_log(env);
	if (!log)
		return;

	if (log->cnt < log->cap) {
		log->events[log->cnt++] = *event;
		return;
	}

	max_events = BPF_DIAG_EVENT_LOG_MAX_SIZE / sizeof(*events);
	if (log->capped || log->cap == max_events) {
		if (log->dropped != U32_MAX)
			log->dropped++;
		return;
	}

	cap = min_t(u32, log->cap ? log->cap * 2 : 64, max_events);
	events = kvrealloc(log->events, array_size(cap, sizeof(*events)), GFP_KERNEL_ACCOUNT);
	if (!events) {
		log->capped = true;
		if (log->dropped != U32_MAX)
			log->dropped++;
		return;
	}
	log->events = events;
	log->cap = cap;
	log->events[log->cnt++] = *event;
}

static const struct bpf_diag_history_event *diag_history_event(const struct bpf_diag_log *log,
							u32 idx)
{
	return &log->events[idx];
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

static void bpf_diag_format_btf_type(char *buf, size_t size, const struct btf *btf, u32 type_id)
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

const char *bpf_diag_fmt_btf_type(struct bpf_verifier_env *env, const struct btf *btf, u32 type_id)
{
	char *buf = bpf_diag_fmt_buf(env, BPF_DIAG_FMT_BUF_SIZE);

	if (!buf)
		return "";

	bpf_diag_format_btf_type(buf, BPF_DIAG_FMT_BUF_SIZE, btf, type_id);
	return buf;
}

static void diag_vprint_indented(struct bpf_verifier_env *env, const char *fmt, va_list args)
	__printf(2, 0);

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

static void disasm_print(void *private_data, const char *fmt, ...) __printf(2, 3);

static void disasm_print(void *private_data, const char *fmt, ...)
{
	struct disasm_ctx *ctx = private_data;
	va_list args;

	va_start(args, fmt);
	seq_buf_vprintf(&ctx->seq, fmt, args);
	va_end(args);
}

static const char *disasm_kfunc_name(void *private_data, const struct bpf_insn *insn)
{
	struct disasm_ctx *ctx = private_data;

	return bpf_disasm_kfunc_name(ctx->env, insn);
}

static void format_disasm_line(struct bpf_verifier_env *env, int insn_idx,
			       struct disasm_line *line)
{
	struct disasm_ctx ctx = { .env = env };
	struct bpf_insn *insn;
	const struct bpf_insn_cbs cbs = {
		.cb_call = disasm_kfunc_name,
		.cb_print = disasm_print,
		.private_data = &ctx,
	};

	line->idx = insn_idx;
	line->valid = false;
	seq_buf_init(&ctx.seq, line->text, sizeof(line->text));

	if (insn_idx < 0 || insn_idx >= env->prog->len)
		return;

	if (insn_idx > 0 && bpf_is_ldimm64(&env->prog->insnsi[insn_idx - 1]))
		return;

	insn = &env->prog->insnsi[insn_idx];
	if (bpf_is_ldimm64(insn) && insn_idx + 1 >= env->prog->len)
		return;

	print_bpf_insn(&cbs, insn, env->allow_ptr_leaks);
	seq_buf_str(&ctx.seq);
	ctx.seq.len = strnlen(line->text, sizeof(line->text));
	while (ctx.seq.len && line->text[ctx.seq.len - 1] == '\n')
		seq_buf_pop(&ctx.seq);
	seq_buf_str(&ctx.seq);

	line->valid = true;
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

void bpf_diag_header(struct bpf_verifier_env *env, const char *category, const char *problem)
{
	char first;

	if (!bpf_diag_enabled(env))
		return;

	category = category ?: "Verifier Error";
	problem = problem ?: "";

	if (!problem[0]) {
		diag_write(env, "\nVerification failed: %s\n", category);
		return;
	}

	first = toupper(problem[0]);
	diag_write(env, "\nVerification failed: %s: %c%s\n", category, first, problem + 1);
}

static void diag_reason(struct bpf_verifier_env *env, const char *fmt, ...) __printf(2, 3);
static void diag_suggestion(struct bpf_verifier_env *env, const char *fmt, ...)
	__printf(2, 3);

static void diag_section(struct bpf_verifier_env *env, const char *title)
{
	if (!bpf_diag_enabled(env))
		return;

	diag_write(env, "\n%s:\n", title);
}

static void diag_reason(struct bpf_verifier_env *env, const char *fmt, ...)
{
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	diag_section(env, "Reason");

	va_start(args, fmt);
	diag_vprint_indented(env, fmt, args);
	va_end(args);
}

static void diag_suggestion(struct bpf_verifier_env *env, const char *fmt, ...)
{
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	diag_section(env, "Suggestion");

	va_start(args, fmt);
	diag_vprint_indented(env, fmt, args);
	va_end(args);
	diag_write(env, "\n");
}

static void diag_print_source_annotation(struct bpf_verifier_env *env, int line_width, int indent,
					 const char *label, const char *msg)
{
	const char *first_prefix, *next_prefix, *text;

	indent = min_t(int, indent, max_t(int, 0, BPF_DIAG_SOURCE_LANE_WIDTH - line_width - 8));
	text = bpf_diag_fmt(env, "%s: %s", label, msg);
	first_prefix = bpf_diag_fmt(env, "  %*s | %*s^-- ", line_width + 4, "", indent, "");
	next_prefix = bpf_diag_fmt(env, "  %*s | %*s    ", line_width + 4, "", indent, "");

	diag_print_wrapped_prefixed(env, first_prefix, next_prefix, text);
}

void bpf_diag_source(struct bpf_verifier_env *env, u32 insn_idx, const char *label,
			    const char *fmt, ...)
{
	struct bpf_diag_scratch *scratch;
	struct bpf_linfo_source *source_lines;
	struct disasm_line *disasm_lines;
	struct bpf_linfo_source src;
	struct diag_fmt_mark mark;
	const struct bpf_line_info *linfo;
	const struct bpf_subprog_info *subprog;
	struct btf *btf = env->prog->aux->btf;
	char *source_lane;
	const char *msg;
	const char *func;
	int start_line, end_line, width, indent, insn_width, subprogno, i;
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	mark = diag_fmt_save(env);
	label = label ?: "note";
	scratch = diag_scratch(env);
	source_lines = scratch->source_lines;
	disasm_lines = scratch->disasm_lines;
	memset(source_lines, 0, sizeof(scratch->source_lines));
	memset(disasm_lines, 0, sizeof(scratch->disasm_lines));

	va_start(args, fmt);
	msg = bpf_diag_vfmt(env, fmt, args);
	va_end(args);
	if (!*msg)
		msg = "<failed to allocate diagnostic text>";

	linfo = bpf_find_linfo(env->prog, insn_idx);
	if (!btf || !linfo) {
		diag_write(env, "  insn %u\n", insn_idx);
		diag_print_source_annotation(env, 0, 0, label, msg);
		goto out_restore;
	}
	bpf_get_linfo_source(btf, linfo, &src, 0);
	if (!src.file || !*src.file || !src.line || !*src.line) {
		diag_write(env, "  insn %u\n", insn_idx);
		diag_print_source_annotation(env, 0, 0, label, msg);
		goto out_restore;
	}

	subprog = bpf_find_containing_subprog(env, insn_idx);
	subprogno = subprog ? bpf_find_subprog(env, subprog->start) : -ENOENT;
	func = subprogno >= 0 ? bpf_subprog_name(env, subprogno) : NULL;
	if (func && *func)
		diag_write(env, "  %s @ %s:%d:%d\n", func, src.file, src.line_num, src.line_col);
	else
		diag_write(env, "  %s:%d:%d\n", src.file, src.line_num, src.line_col);

	start_line = src.line_num - BPF_DIAG_CONTEXT;
	end_line = src.line_num + BPF_DIAG_CONTEXT;
	width = diag_line_width(end_line);
	indent = diag_line_indent(src.line);
	insn_width = diag_line_width(env->prog->len ? env->prog->len - 1 : 0);
	for (i = 0; i < BPF_DIAG_CONTEXT_CNT; i++)
		source_lines[i].line_num = start_line + i;

	linfo = env->prog->aux->linfo;
	for (i = 0; i < env->prog->aux->nr_linfo; i++) {
		struct bpf_linfo_source line_src;
		int idx;

		bpf_get_linfo_source(btf, &linfo[i], &line_src, 0);
		if (line_src.file_name_off != src.file_name_off ||
		    line_src.line_num < start_line || line_src.line_num > end_line ||
		    !line_src.line || !*line_src.line)
			continue;

		idx = line_src.line_num - start_line;
		if (!source_lines[idx].line)
			source_lines[idx] = line_src;
	}

	for (i = 0; i < BPF_DIAG_CONTEXT_CNT; i++) {
		int row = i - BPF_DIAG_CONTEXT;

		format_disasm_line(env, insn_idx + row, &disasm_lines[i]);
	}

	diag_write(env, "  Source context:\n");
	source_lane = bpf_diag_fmt_buf(env, BPF_DIAG_FMT_BUF_SIZE);
	if (!source_lane)
		goto out_restore;
	for (i = 0; i < BPF_DIAG_CONTEXT_CNT; i++) {
		const char *source_prefix;

		source_prefix = source_lines[i].line_num == src.line_num ? ">>> " : "    ";
		diag_format_source_lane(source_lane, BPF_DIAG_FMT_BUF_SIZE, source_prefix, width,
					source_lines[i].line_num, source_lines[i].line);
		diag_write(env, "  %s\n", source_lane);
		if (source_lines[i].line_num == src.line_num)
			diag_print_source_annotation(env, width, indent, label, msg);
	}
	diag_write(env, "  Instruction context:\n");
	for (i = 0; i < BPF_DIAG_CONTEXT_CNT; i++) {
		struct disasm_line *line = &disasm_lines[i];

		if (line->valid)
			diag_write(env, "  %s%*d | %s\n", line->idx == insn_idx ? ">>> " : "    ",
				   insn_width, line->idx, line->text);
	}

out_restore:
	diag_fmt_restore(env, mark);
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

void bpf_diag_register_type(struct bpf_verifier_env *env, u32 insn_idx, int regno,
				   const char *problem, const char *reason, const char *suggestion)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REG,
		.frameno = diag_current_frameno(env),
		.regno = regno,
	};

	bpf_diag_header(env, REGISTER_TYPE_SAFETY, problem);
	diag_reason(env, "%s", reason);

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "%s", problem);

	if (regno >= 0)
		diag_print_history(env, &opts);

	diag_suggestion(env, "%s", suggestion);
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

void bpf_diag_call_type(struct bpf_verifier_env *env, u32 insn_idx, int argno, int regno,
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

	bpf_diag_header(env, CALL_TYPE_SAFETY, "invalid call argument");
	diag_reason(env, "The %s to %s does not satisfy the verifier contract: %s.",
			   arg_desc, call_name, reason);

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "invalid %s for %s", arg_desc, call_name);

	if (print_history)
		diag_print_history(env, &opts);

	diag_suggestion(env, "%s", suggestion);
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

static const char *diag_active_context(struct bpf_verifier_env *env, u32 depth,
				       const char *context)
{
	if (depth == 1)
		return bpf_diag_fmt(env, "an active %s (depth 1)", context);
	return bpf_diag_fmt(env, "%u active %ss (depth %u)", depth, context, depth);
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
			       const char *constraint, const char *suggestion)
{
	u32 depth = diag_context_depth(env, ctx_kind);
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_CONTEXT,
		.ctx_kind = ctx_kind,
		.ctx_depth = depth,
	};

	bpf_diag_header(env, EXECUTION_CONTEXT_SAFETY,
			       "operation is not allowed in this context");
	if (constraint) {
		if (depth) {
			diag_reason(
				env, "The operation %s cannot be used in %s because %s. This path is still inside %s.",
				operation, context, constraint, diag_active_context(env, depth, context));
		} else {
			diag_reason(env, "The operation %s cannot be used in %s because %s.",
					   operation, context, constraint);
		}
	} else {
		diag_reason(env, "The operation %s cannot be used in %s.", operation,
				   context);
	}

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "%s is not allowed in %s", operation,
			       context);

	if (ctx_kind != BPF_DIAG_CONTEXT_NONE)
		diag_print_history(env, &opts);

	diag_suggestion(env, "%s", suggestion);
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

	bpf_diag_header(env, EXECUTION_CONTEXT_SAFETY,
			       "operation is not allowed in this context");
	diag_reason(
		env, "The operation %s cannot be used while this path is still inside %s. Leave the region before this operation.",
		operation, diag_active_context(env, depth, context));

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "%s is not allowed before leaving %s",
			       operation, context);

	diag_print_history(env, &opts);

	diag_suggestion(env, "%s", suggestion);
}

static void diag_ctx_underflow(struct bpf_verifier_env *env, u32 insn_idx, const char *operation,
			       enum bpf_diag_context_kind ctx_kind, const char *suggestion)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_CONTEXT,
		.ctx_kind = ctx_kind,
	};
	const char *context = diag_context_name(ctx_kind);

	bpf_diag_header(env, EXECUTION_CONTEXT_SAFETY, "unmatched context exit");
	diag_reason(
		env, "The operation %s tries to leave %s, but this path has no active %s to leave. The current depth is 0.",
		operation, context, context);

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "%s has no matching enter on this path",
			       operation);

	diag_print_history(env, &opts);

	diag_suggestion(env, "%s", suggestion);
}

void bpf_diag_ctx(struct bpf_verifier_env *env, enum bpf_diag_ctx_report report, u32 insn_idx,
		  const char *operation, enum bpf_diag_context_kind ctx_kind, const char *context,
		  const char *suggestion)
{
	switch (report) {
	case BPF_DIAG_CTX_FORBIDDEN:
		diag_ctx_forbidden(env, insn_idx, operation, ctx_kind, context,
				   diag_context_constraint(ctx_kind), suggestion);
		return;
	case BPF_DIAG_CTX_ACTIVE:
		diag_ctx_active(env, insn_idx, operation, ctx_kind, context, suggestion);
		return;
	case BPF_DIAG_CTX_UNDERFLOW:
		diag_ctx_underflow(env, insn_idx, operation, ctx_kind, suggestion);
		return;
	}
}

void bpf_diag_ctx_restricted(struct bpf_verifier_env *env, u32 insn_idx, const char *operation,
			     enum bpf_diag_context_kind ctx_kind, const char *context,
			     const char *constraint, const char *suggestion)
{
	diag_ctx_forbidden(env, insn_idx, operation, ctx_kind, context, constraint, suggestion);
}

void bpf_diag_program_structure(struct bpf_verifier_env *env, u32 insn_idx,
				       const char *problem, const char *suggestion,
				       const char *reason_fmt, ...)
{
	va_list args;

	bpf_diag_header(env, PROGRAM_STRUCTURE, problem);
	diag_section(env, "Reason");

	va_start(args, reason_fmt);
	diag_vprint_indented(env, reason_fmt, args);
	va_end(args);

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "%s", problem);

	diag_suggestion(env, "%s", suggestion);
}

void bpf_diag_policy(struct bpf_verifier_env *env, u32 insn_idx, const char *operation,
		     const char *reason, const char *suggestion)
{
	bpf_diag_header(env, POLICY, "operation is not allowed");
	diag_reason(env, "The %s is not allowed: %s.", operation, reason);

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "policy check failed for %s", operation);

	diag_suggestion(env, "%s", suggestion);
}

void bpf_diag_invalid_deref(struct bpf_verifier_env *env, u32 insn_idx, int regno,
				   const char *reg_name, const struct bpf_reg_state *reg,
				   enum bpf_diag_invalid_deref_kind kind, s64 offset)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REG,
		.frameno = diag_current_frameno(env),
		.regno = regno,
	};
	const char *type_name = bpf_diag_reg_type_plain(env, reg->type);

	bpf_diag_header(env, REGISTER_TYPE_SAFETY, "invalid dereference");

	switch (kind) {
	case BPF_DIAG_DEREF_SCALAR:
		diag_reason(env, "%s is an integer scalar here, not a pointer to memory.",
				   reg_name);
		break;
	case BPF_DIAG_DEREF_NULLABLE_PTR:
		diag_reason(
			env, "%s may be NULL here (%s). The program could dereference NULL on this path, so the verifier cannot prove this access is safe.",
			reg_name, type_name);
		break;
	case BPF_DIAG_DEREF_MODIFIED_PTR:
		diag_reason(
			env, "%s has offset %lld here, but this pointer type must be dereferenced in its original form.",
			reg_name, offset);
		break;
	case BPF_DIAG_DEREF_INVALID_PTR:
	default:
		diag_reason(
			env, "%s has type %s here, which is not valid for this memory access.",
			reg_name, type_name);
		break;
	}

	diag_section(env, "At");
	if (kind == BPF_DIAG_DEREF_MODIFIED_PTR)
		bpf_diag_source(env, insn_idx, "error",
				       "dereference requires the original %s pointer", type_name);
	else
		bpf_diag_source(env, insn_idx, "error", "invalid dereference of %s (%s)",
				       reg_name, type_name);

	if (regno >= 0)
		diag_print_history(env, &opts);

	switch (kind) {
	case BPF_DIAG_DEREF_NULLABLE_PTR:
		diag_suggestion(
			env, "Add a NULL check before the access and dereference the pointer only on the non-NULL path.");
		break;
	case BPF_DIAG_DEREF_MODIFIED_PTR:
		diag_suggestion(
			env, "Preserve the original pointer in another register, or use only offsets this pointer type permits before dereferencing it.");
		break;
	case BPF_DIAG_DEREF_SCALAR:
	case BPF_DIAG_DEREF_INVALID_PTR:
	default:
		diag_suggestion(
			env, "Preserve a pointer-valued register where needed, or reload and revalidate the pointer after scalar arithmetic, helper calls, or other operations that can invalidate it.");
		break;
	}
}

void bpf_diag_unreadable_reg(struct bpf_verifier_env *env, u32 insn_idx, int regno)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REG,
		.frameno = diag_current_frameno(env),
		.regno = regno,
	};
	const struct bpf_diag_log *log = diag_event_log(env);
	struct bpf_diag_mod_target target;
	bool invalidated = false;
	int i;

	target = bpf_diag_reg_target(opts.frameno, regno);
	for (i = log ? log->cnt : 0; i > 0; i--) {
		const struct bpf_diag_history_event *event = diag_history_event(log, i - 1);

		if (event->kind != BPF_DIAG_HISTORY_MOD ||
		    !diag_target_matches(&event->mod.target, &target))
			continue;
		invalidated = event->mod.new.type == NOT_INIT;
		break;
	}

	bpf_diag_header(env, REGISTER_TYPE_SAFETY, "unreadable register");
	if (invalidated)
		diag_reason(
			env, "R%d is not readable here. A previous operation invalidated this register, so the verifier cannot use it as an input.",
			regno);
	else if (log && !log->dropped)
		diag_reason(env,
			    "R%d has never been initialized on this path, so the verifier cannot use it as an input.",
			    regno);
	else
		diag_reason(
			env, "R%d is not readable here. It may never have been initialized, or an earlier operation may have invalidated it.",
			regno);

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "R%d is not readable", regno);

	if (regno >= 0)
		diag_print_history(env, &opts);

	if (invalidated)
		diag_suggestion(
			env, "Avoid using the register after it is invalidated, or initialize it again before this instruction.");
	else if (log && !log->dropped)
		diag_suggestion(env, "Initialize R%d on every path before this instruction.", regno);
	else
		diag_suggestion(
			env, "Initialize the register on every path, or initialize it again after any operation that invalidates it.");
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

void bpf_diag_stack_arg_uninit(struct bpf_verifier_env *env, u32 insn_idx, int nargs,
				      int stack_arg_slot, const char *callee_name,
				      const char *arg_name)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_STACK_ARG,
		.frameno = diag_current_frameno(env),
		.stack_arg_slot = stack_arg_slot,
	};
	const char *arg_buf;

	arg_buf = bpf_diag_fmt_buf(env, BPF_DIAG_FMT_BUF_SIZE);
	if (arg_buf)
		diag_format_stack_arg((char *)arg_buf, BPF_DIAG_FMT_BUF_SIZE, stack_arg_slot,
				      arg_name);
	else
		arg_buf = "";
	bpf_diag_header(env, REGISTER_TYPE_SAFETY, "missing stack argument");
	if (callee_name && *callee_name)
		diag_reason(
			env, "Function %s expects %d arguments, but %s is not initialized at this call.",
			callee_name, nargs, arg_buf);
	else
		diag_reason(
			env, "The callee expects %d arguments, but %s is not initialized at this call.",
			nargs, arg_buf);

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "%s is not initialized", arg_buf);

	if (stack_arg_slot >= 0)
		diag_print_history(env, &opts);

	diag_suggestion(
		env, "Write the outgoing stack argument after any operation that may invalidate stored pointer values, and before making this call.");
}

void bpf_diag_memory(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
			    const char *reason, const char *suggestion)
{
	bpf_diag_header(env, MEMORY_SAFETY, problem);
	diag_reason(env, "%s", reason);

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "%s", problem);

	diag_suggestion(env, "%s", suggestion);
}

void bpf_diag_record_branch(struct bpf_verifier_env *env, u32 insn_idx, bool cond_true)
{
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = BPF_DIAG_HISTORY_BRANCH,
		.branch = {
			.cond_true = cond_true,
		},
	};

	diag_append_history(env, &event);
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

static void bpf_diag_record_mod(struct bpf_verifier_env *env, u32 insn_idx,
				struct bpf_diag_mod_target target,
				enum bpf_diag_mod_reason reason,
				const struct bpf_reg_state *old_reg,
				const struct bpf_reg_state *new_reg,
				const struct bpf_diag_mod_target *origin)
{
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = BPF_DIAG_HISTORY_MOD,
		.mod = {
			.target = target,
			.reason = reason,
		},
	};

	if (old_reg)
		diag_snapshot_reg(&event.mod.old, old_reg);
	if (new_reg)
		diag_snapshot_reg(&event.mod.new, new_reg);
	if (old_reg && new_reg &&
	    (reason == BPF_DIAG_MOD_WRITE || reason == BPF_DIAG_MOD_SPILL) &&
	    diag_snapshot_eq(&event.mod.old, &event.mod.new))
		return;
	if (origin) {
		event.mod.origin = *origin;
		event.mod.origin_valid = true;
	} else if (diag_mod_insn_origin(env, insn_idx, &target, &event.mod.origin)) {
		event.mod.origin_valid = true;
	}

	diag_append_history(env, &event);
}

static struct bpf_func_state *diag_func_state(struct bpf_verifier_env *env, u32 frameno)
{
	struct bpf_verifier_state *vstate = env->cur_state;
	int frame;

	for (frame = 0; frame <= vstate->curframe; frame++) {
		if (vstate->frame[frame]->frameno == frameno)
			return vstate->frame[frame];
	}
	return NULL;
}

static struct bpf_reg_state *target_to_reg(struct bpf_verifier_env *env,
					   const struct bpf_diag_mod_target *target)
{
	struct bpf_func_state *state = diag_func_state(env, target->frameno);

	if (!state)
		return NULL;

	switch (target->kind) {
	case BPF_DIAG_MOD_TARGET_REG:
		if (target->regno >= MAX_BPF_REG)
			return NULL;
		return &state->regs[target->regno];
	case BPF_DIAG_MOD_TARGET_STACK_ARG:
		if (target->stack_arg >= state->out_stack_arg_cnt)
			return NULL;
		return &state->stack_arg_regs[target->stack_arg];
	case BPF_DIAG_MOD_TARGET_STACK_SLOT:
		if (target->spi >= state->allocated_stack / BPF_REG_SIZE)
			return NULL;
		return &state->stack[target->spi].spilled_ptr;
	default:
		return NULL;
	}
}

static bool reg_to_target(struct bpf_verifier_env *env, const struct bpf_reg_state *reg,
			  struct bpf_diag_mod_target *target)
{
	struct bpf_verifier_state *vstate = env->cur_state;
	unsigned long addr = (unsigned long)reg;
	int frame;

	for (frame = 0; frame <= vstate->curframe; frame++) {
		struct bpf_func_state *state = vstate->frame[frame];
		unsigned long start, end;
		u32 nslots = state->allocated_stack / BPF_REG_SIZE;
		int spi;

		start = (unsigned long)state->regs;
		end = (unsigned long)(state->regs + MAX_BPF_REG);
		if (addr >= start && addr < end) {
			*target = bpf_diag_reg_target(state->frameno, reg - state->regs);
			return true;
		}

		start = (unsigned long)state->stack_arg_regs;
		end = (unsigned long)(state->stack_arg_regs + state->out_stack_arg_cnt);
		if (state->out_stack_arg_cnt && addr >= start && addr < end) {
			*target = bpf_diag_stack_arg_target(state->frameno,
							    reg - state->stack_arg_regs);
			return true;
		}

		start = (unsigned long)state->stack;
		end = (unsigned long)(state->stack + nslots);
		if (nslots && addr >= start && addr < end) {
			spi = ((const char *)reg - (const char *)state->stack) /
			      sizeof(*state->stack);
			*target = bpf_diag_stack_slot_target(state->frameno, spi);
			return true;
		}
	}
	return false;
}

void bpf_diag_mod_begin(struct bpf_verifier_env *env, const struct bpf_reg_state *reg,
			const struct bpf_reg_state *origin, enum bpf_diag_mod_reason reason)
{
	struct bpf_diag *diag = diag_env(env);

	if (!diag)
		return;
	diag->mod.active = reg_to_target(env, reg, &diag->mod.target);
	if (!diag->mod.active)
		return;
	diag->mod.target_reg_snapshot = *reg;
	diag->mod.insn_idx = env->insn_idx;
	diag->mod.reason = reason;
	diag->mod.origin_valid = origin && reg_to_target(env, origin, &diag->mod.origin);
}

void bpf_diag_mod_end(struct bpf_verifier_env *env)
{
	struct bpf_diag *diag = diag_env(env);
	const struct bpf_reg_state *new_reg;

	if (!diag || !diag->mod.active)
		return;
	diag->mod.active = false;
	/*
	 * Resolve the target again because the enclosing function state's stack
	 * may have been reallocated while the modification was in progress.
	 */
	new_reg = target_to_reg(env, &diag->mod.target);
	if (!new_reg)
		return;
	bpf_diag_record_mod(env, diag->mod.insn_idx, diag->mod.target, diag->mod.reason,
			    &diag->mod.target_reg_snapshot, new_reg,
			    diag->mod.origin_valid ? &diag->mod.origin : NULL);
}

void bpf_diag_record_scrub(struct bpf_verifier_env *env, const struct bpf_reg_state *reg,
			   enum bpf_diag_mod_reason reason)
{
	struct bpf_diag_mod_target target;

	if (!diag_env(env) || reg->type == NOT_INIT || !reg_to_target(env, reg, &target))
		return;
	bpf_diag_record_mod(env, env->insn_idx, target, reason, reg, NULL, NULL);
}

void bpf_diag_record_scrub_stack(struct bpf_verifier_env *env, u32 frameno, s16 min_off,
				 s16 max_off, enum bpf_diag_mod_reason reason)
{
	bpf_diag_record_mod(env, env->insn_idx,
			    bpf_diag_stack_range_target(frameno, min_off, max_off), reason,
			    NULL, NULL, NULL);
}

static void diag_record_ref(struct bpf_verifier_env *env, u32 insn_idx, u8 kind, u32 ref_id)
{
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = kind,
		.ref = {
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
			     enum bpf_diag_context_kind ctx_kind, bool enter, u32 depth)
{
	/*
	 * Keep leave events so context rendering can stop at a depth-zero exit
	 * and show nested-region depth accurately for the active path.
	 */
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = BPF_DIAG_HISTORY_CONTEXT,
		.ctx = {
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

static void diag_build_lineage(struct bpf_verifier_env *env, struct bpf_diag_log *log,
			       struct bpf_diag_history_filter *filter)
{
	const struct bpf_diag_history_opts *opts = filter->opts;
	struct bpf_diag_mod_target target;
	int i;

	for (i = 0; i < log->cnt; i++)
		log->events[i].in_lineage = false;

	if (!opts)
		return;

	if (opts->scope == BPF_DIAG_HISTORY_SCOPE_REG)
		target = bpf_diag_reg_target(opts->frameno, opts->regno);
	else if (opts->scope == BPF_DIAG_HISTORY_SCOPE_STACK_ARG)
		target = bpf_diag_stack_arg_target(opts->frameno, opts->stack_arg_slot);
	else
		return;

	/*
	 * Find the nearest mutation of the active target. A fill or spill changes
	 * the target to its origin, so the same walk follows register/stack
	 * lineage recursively until it reaches the write that created the value.
	 */
	for (i = log->cnt; i > 0; i--) {
		struct bpf_diag_history_event *event;

		event = &log->events[i - 1];
		if (event->kind != BPF_DIAG_HISTORY_MOD ||
		    !diag_target_matches(&event->mod.target, &target))
			continue;

		event->in_lineage = true;
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

static bool diag_history_event_visible(const struct bpf_diag_history_event *event,
				       const struct bpf_diag_history_filter *filter)
{
	const struct bpf_diag_history_opts *opts = filter->opts;

	if (!opts || opts->scope == BPF_DIAG_HISTORY_SCOPE_ALL)
		return event->kind != BPF_DIAG_HISTORY_CONTEXT;

	switch (event->kind) {
	case BPF_DIAG_HISTORY_BRANCH:
		return true;
	case BPF_DIAG_HISTORY_MOD:
		return filter->lineage_valid && event->in_lineage;
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

static const char *diag_s64_str(struct bpf_verifier_env *env, s64 value)
{
	return diag_s64_bound_name(value) ?: bpf_diag_fmt(env, "%lld", value);
}

static const char *diag_u64_str(struct bpf_verifier_env *env, u64 value)
{
	return diag_u64_bound_name(value) ?: bpf_diag_fmt(env, "%llu", value);
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

static const char *diag_scalar_range(struct bpf_verifier_env *env, struct cnum64 range)
{
	return bpf_diag_fmt(env, "signed range [%s, %s], unsigned range [%s, %s]",
			    diag_s64_str(env, cnum64_smin(range)),
			    diag_s64_str(env, cnum64_smax(range)),
			    diag_u64_str(env, cnum64_umin(range)),
			    diag_u64_str(env, cnum64_umax(range)));
}

const char *bpf_diag_fmt_s64_sum(struct bpf_verifier_env *env, s64 value, int addend)
{
	s64 sum;

	if (check_add_overflow(value, (s64)addend, &sum))
		return bpf_diag_fmt(env, "%lld plus %d (%s)", value, addend,
				    addend < 0 ? "below S64_MIN" : "above S64_MAX");

	return bpf_diag_fmt(env, "%lld", sum);
}

static const char *diag_access_offset(struct bpf_verifier_env *env, int off,
				      const struct bpf_reg_state *reg)
{
	if (tnum_is_const(reg->var_off))
		return bpf_diag_fmt(env, "constant %s",
				    bpf_diag_fmt_s64_sum(env, (s64)reg->var_off.value, off));

	if (tnum_is_unknown(reg->var_off) && diag_cnum64_unknown(reg->r64))
		return bpf_diag_fmt(env, "unbounded");

	if (off)
		return bpf_diag_fmt(env,
			"variable: known bits %#llx, unknown mask %#llx, plus fixed offset %d; %s",
			(u64)reg->var_off.value, reg->var_off.mask, off,
			diag_scalar_range(env, reg->r64));
	return bpf_diag_fmt(env, "variable: known bits %#llx, unknown mask %#llx; %s",
			    (u64)reg->var_off.value, reg->var_off.mask,
			    diag_scalar_range(env, reg->r64));
}

void bpf_diag_mem_bounds(struct bpf_verifier_env *env, u32 insn_idx, int regno,
				const char *reg_name, const char *type_name, const char *proof,
				int off, int size, u32 mem_size, const struct bpf_reg_state *reg)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REG,
		.frameno = diag_current_frameno(env),
		.regno = regno,
	};
	const char *offset_desc;

	if (!bpf_diag_enabled(env))
		return;

	offset_desc = diag_access_offset(env, off, reg);

	bpf_diag_header(env, MEMORY_SAFETY, "access outside bounds");
	diag_reason(
		env, "The verifier cannot prove offset + access_size <= object_size. Here, %s. %s is %s; offset is %s; access_size is %d; object_size is %u.",
		proof, reg_name, type_name, offset_desc, size, mem_size);

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "access may be outside object bounds");

	if (regno >= 0)
		diag_print_history(env, &opts);

	diag_suggestion(
		env, "Add or adjust a bounds check that proves offset + access_size stays within the object.");
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
	bpf_diag_header(env, RESOURCE_LIFETIME_SAFETY, problem);
	diag_reason(env, "%s", reason);

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "%s", problem);
}

void bpf_diag_res(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
		  const char *reason, const char *suggestion)
{
	diag_res_report(env, insn_idx, problem, reason);
	diag_suggestion(env, "%s", suggestion);
}

void bpf_diag_lock(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
		   const char *reason, const char *suggestion,
		   const struct bpf_reference_state *active_lock)
{
	diag_res_report(env, insn_idx, problem, reason);

	if (active_lock) {
		diag_section(env, "Active lock");
		bpf_diag_source(env, active_lock->insn_idx, "acquired",
				       "active %s has verifier identity %d",
				       diag_lock_name(active_lock), active_lock->id);
	}

	diag_suggestion(env, "%s", suggestion);
}

void bpf_diag_irq(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
		  const char *reason, const char *suggestion, u32 depth)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_CONTEXT,
		.ctx_kind = BPF_DIAG_CONTEXT_IRQ,
		.ctx_depth = depth,
	};

	bpf_diag_header(env, RESOURCE_LIFETIME_SAFETY, problem);
	diag_reason(env, "%s", reason);

	diag_section(env, "At");
	bpf_diag_source(env, insn_idx, "error", "%s", problem);

	if (depth)
		diag_print_history(env, &opts);

	diag_suggestion(env, "%s", suggestion);
}

void bpf_diag_leak(struct bpf_verifier_env *env, u32 ref_id, u32 alloc_insn, u32 fail_insn)
{
	struct bpf_diag_history_opts opts = {
		.scope = BPF_DIAG_HISTORY_SCOPE_REF,
		.ref_id = ref_id,
	};

	bpf_diag_header(env, RESOURCE_LIFETIME_SAFETY, "unreleased resource");
	diag_reason(
		env, "Owned resource (id=%u) was acquired at instruction %u and still needs to be released before this exit path.",
		ref_id, alloc_insn);

	diag_section(env, "At");
	bpf_diag_source(env, fail_insn, "error",
			       "owned resource (id=%u) still needs release", ref_id);

	diag_print_history(env, &opts);

	diag_suggestion(
		env, "Release or transfer ownership of the acquired resource on every path before the program exits.");
}

static const char *diag_var_offset(struct bpf_verifier_env *env,
				   const struct bpf_diag_reg_snapshot *snapshot)
{
	if (tnum_is_const(snapshot->var_off))
		return bpf_diag_fmt(env, "at offset %lld", (s64)snapshot->var_off.value);

	if (diag_snapshot_unknown(snapshot))
		return bpf_diag_fmt(env, "with unknown offset");

	return bpf_diag_fmt(env,
			    "with variable offset: known bits %#llx, unknown mask %#llx, %s",
			    snapshot->var_off.value, snapshot->var_off.mask,
			    diag_scalar_range(env, snapshot->r64));
}

static const char *diag_snapshot_btf_type(struct bpf_verifier_env *env,
					  const struct bpf_diag_reg_snapshot *snapshot)
{
	if (!snapshot->btf || !snapshot->btf_id)
		return NULL;

	return bpf_diag_fmt_btf_type(env, snapshot->btf, snapshot->btf_id);
}

static const char *diag_reg_map_name(const struct bpf_map *map)
{
	if (!map || !map->name[0])
		return NULL;

	return map->name;
}

static const char *diag_reg_snapshot(struct bpf_verifier_env *env,
				     const struct bpf_diag_reg_snapshot *snapshot)
{
	const char *type_name = reg_type_str(env, snapshot->type);
	const char *offset = diag_var_offset(env, snapshot);
	const char *btf = diag_snapshot_btf_type(env, snapshot);
	const char *map_name;

	if (snapshot->type == SCALAR_VALUE) {
		if (tnum_is_const(snapshot->var_off))
			return bpf_diag_fmt(env, "integer scalar value %lld",
					    (s64)snapshot->var_off.value);
		if (diag_snapshot_unknown(snapshot))
			return bpf_diag_fmt(env, "integer scalar with unknown value");
		if (cnum64_is_const(snapshot->r64))
			return bpf_diag_fmt(env, "integer scalar value %lld",
					    cnum64_smin(snapshot->r64));
		return bpf_diag_fmt(env, "integer scalar with %s",
				    diag_scalar_range(env, snapshot->r64));
	}

	if (snapshot->type == NOT_INIT)
		return bpf_diag_fmt(env, "uninitialized value");

	if (base_type(snapshot->type) == PTR_TO_CTX)
		return bpf_diag_fmt(env, "context pointer %s", offset);

	if (base_type(snapshot->type) == PTR_TO_STACK)
		return bpf_diag_fmt(env, "stack pointer %s", offset);

	if (base_type(snapshot->type) == PTR_TO_MAP_VALUE) {
		const char *kind = type_may_be_null(snapshot->type) ? "nullable map value" :
								      "map value";

		map_name = diag_reg_map_name(snapshot->map_ptr);
		if (map_name)
			return bpf_diag_fmt(env, "%s from %s %s", kind, map_name, offset);
		return bpf_diag_fmt(env, "%s %s", kind, offset);
	}

	if (base_type(snapshot->type) == CONST_PTR_TO_MAP) {
		map_name = diag_reg_map_name(snapshot->map_ptr);
		if (map_name)
			return bpf_diag_fmt(env, "map pointer for map %s", map_name);
		return bpf_diag_fmt(env, "map pointer");
	}

	if (type_is_non_owning_ref(snapshot->type)) {
		if (btf)
			return bpf_diag_fmt(env, "borrowed allocated object pointer type=%s", btf);
		return bpf_diag_fmt(env, "borrowed allocated object pointer");
	}

	if (type_is_ptr_alloc_obj(snapshot->type)) {
		if (btf)
			return bpf_diag_fmt(env, "owned allocated object pointer type=%s", btf);
		return bpf_diag_fmt(env, "owned allocated object pointer");
	}

	if (base_type(snapshot->type) == PTR_TO_BTF_ID && btf)
		return bpf_diag_fmt(env, "%s type=%s %s", type_name, btf, offset);

	return bpf_diag_fmt(env, "%s %s", type_name, offset);
}

static const char *diag_mod_target_desc(struct bpf_verifier_env *env,
					const struct bpf_diag_mod_target *target)
{
	switch (target->kind) {
	case BPF_DIAG_MOD_TARGET_REG:
		return bpf_diag_fmt(env, "R%u", target->regno);
	case BPF_DIAG_MOD_TARGET_STACK_ARG:
		return bpf_diag_fmt(env, "stack arg%d", diag_stack_argno(target->stack_arg));
	case BPF_DIAG_MOD_TARGET_STACK_SLOT:
		return bpf_diag_fmt(env, "stack slot fp%d", -(target->spi + 1) * BPF_REG_SIZE);
	default:
		return "value";
	}
}

static void diag_print_mod(struct bpf_verifier_env *env, const struct bpf_diag_history_event *event)
{
	const struct bpf_diag_mod_target *target = &event->mod.target;
	const char *target_desc, *reason = NULL, *old, *new;
	const char *label = "update";

	if (target->kind == BPF_DIAG_MOD_TARGET_STACK_RANGE) {
		bpf_diag_source(
			env, event->insn_idx, "invalidated",
			"variable-offset stack write may affect bytes fp%d through fp%d",
			target->range.min_off, target->range.max_off - 1);
		return;
	}

	old = diag_reg_snapshot(env, &event->mod.old);
	new = diag_reg_snapshot(env, &event->mod.new);
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
		bpf_diag_source(env, event->insn_idx, "invalidated",
				       "%s: %s; previous value was %s", target_desc, reason, old);
		return;
	}

	bpf_diag_source(env, event->insn_idx, label, "%s changed from %s to %s", target_desc,
			       old, new);
}

static void diag_print_ref_event(struct bpf_verifier_env *env,
				 const struct bpf_diag_history_event *event)
{
	const char *label;

	label = event->kind == BPF_DIAG_HISTORY_REF_ACQUIRE ? "acquired" : "released";
	bpf_diag_source(env, event->insn_idx, label, "owned resource (id=%u)",
			       event->ref.ref_id);
}

static void diag_print_context_event(struct bpf_verifier_env *env,
				     const struct bpf_diag_history_event *event)
{
	bpf_diag_source(env, event->insn_idx, "context", "%s %s; depth is now %u",
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
	struct bpf_diag_log *log;
	struct diag_fmt_mark mark;
	bool first = true;
	bool visible = false;
	int start_idx;
	u32 i;

	if (!bpf_diag_enabled(env))
		return;

	if (!env->diag)
		return;
	log = &env->diag->log;

	diag_build_lineage(env, log, &filter);

	start_idx = diag_history_start_idx(log, &filter);
	for (i = start_idx; i < log->cnt; i++) {
		event = diag_history_event(log, i);
		if (diag_history_event_visible(event, &filter)) {
			visible = true;
			break;
		}
	}

	if (!visible && !log->dropped && opts && opts->scope == BPF_DIAG_HISTORY_SCOPE_STACK_ARG)
		return;

	diag_section(env, "Causal path");
	mark = diag_fmt_save(env);
	for (i = start_idx; i < log->cnt; i++) {
		event = diag_history_event(log, i);
		if (!diag_history_event_visible(event, &filter))
			continue;

		diag_fmt_restore(env, mark);

		if (!first)
			diag_write(env, "\n");
		first = false;

		switch (event->kind) {
		case BPF_DIAG_HISTORY_BRANCH:
			bpf_diag_source(env, event->insn_idx, "branch",
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
	if (log->dropped)
		diag_write(env, "  %u causal-history event%s not retained after diagnostic event "
			   "storage was exhausted\n",
			   log->dropped, log->dropped == 1 ? "" : "s");
	diag_fmt_restore(env, mark);
}
