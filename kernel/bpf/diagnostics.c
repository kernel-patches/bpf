// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/stdarg.h>
#include <linux/string.h>

#include "disasm.h"
#include "diagnostics.h"

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)
#define BPF_DIAG_TEXT_WIDTH 120
#define BPF_DIAG_TEXT_INDENT "  "
#define BPF_DIAG_MSG_LEN 512
#define BPF_DIAG_SOURCE_CONTEXT 2
#define BPF_DIAG_INSN_CONTEXT 2
#define BPF_DIAG_COLUMN_GAP 3
#define BPF_DIAG_SOURCE_LANE_WIDTH 88
#define BPF_DIAG_TAB_WIDTH 8
#define BPF_DIAG_REG_DESC_LEN 512

struct bpf_diag_source {
	const char *file;
	const char *line;
	u32 file_name_off;
	int line_num;
	int line_col;
};

struct bpf_diag_insn {
	char text[160];
	int idx;
	bool valid;
};

struct bpf_diag_insn_buf {
	char *buf;
	size_t size;
	size_t len;
};

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

		if (line[len] && line[len] != '\n' && last_space > 0)
			len = last_space;

		verbose(env, "%s%.*s\n", prefix, len, line);

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

void bpf_diag_format_btf_type(char *buf, size_t size,
			      const struct btf_type *type,
			      const char *type_name)
{
	const char *kind;

	switch (BTF_INFO_KIND(type->info)) {
	case BTF_KIND_STRUCT:
		kind = "struct";
		break;
	case BTF_KIND_UNION:
		kind = "union";
		break;
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		kind = "enum";
		break;
	default:
		kind = btf_type_str(type);
		break;
	}

	if (type_name && *type_name)
		scnprintf(buf, size, "'%s %s'", kind, type_name);
	else
		scnprintf(buf, size, "'%s'", kind);
}

static void bpf_diag_vprint_indented(struct bpf_verifier_env *env,
				     const char *fmt, va_list args)
{
	char buf[1024];

	if (!bpf_verifier_log_needed(&env->log))
		return;

	vscnprintf(buf, sizeof(buf), fmt, args);
	bpf_diag_print_wrapped_text(env, buf);
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

	if (!env->prog->aux->func_info || !env->prog->aux->btf)
		return NULL;

	subprog = bpf_find_containing_subprog(env, insn_idx);
	if (!subprog)
		return NULL;

	subprogno = subprog - env->subprog_info;
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

	file = btf_name_by_offset(env->prog->aux->btf, linfo->file_name_off);
	line = btf_name_by_offset(env->prog->aux->btf, linfo->line_off);
	if (!file || !*file || !line || !*line)
		return false;

	src->file = kbasename(file);
	src->line = line;
	src->file_name_off = linfo->file_name_off;
	src->line_num = BPF_LINE_INFO_LINE_NUM(linfo->line_col);
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

static const char *bpf_diag_find_source_line(struct bpf_verifier_env *env,
					     u32 file_name_off, int line_num)
{
	const struct bpf_line_info *linfo = env->prog->aux->linfo;
	struct bpf_diag_source src;
	u32 i;

	for (i = 0; i < env->prog->aux->nr_linfo; i++) {
		if (linfo[i].file_name_off != file_name_off ||
		    BPF_LINE_INFO_LINE_NUM(linfo[i].line_col) != line_num)
			continue;
		if (bpf_diag_fill_source(env, &linfo[i], &src))
			return src.line;
	}

	return NULL;
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

static const char *bpf_diag_marker_label(char marker)
{
	switch (marker) {
	case '!':
		return "error";
	case '?':
		return "branch";
	case '~':
		return "update";
	case 'x':
		return "invalidated";
	case '+':
		return "acquired";
	case '-':
		return "released";
	case '@':
		return "context";
	default:
		return "note";
	}
}

static const char *bpf_diag_reg_map_name(const struct bpf_map *map)
{
	if (!map || !map->name[0])
		return NULL;

	return map->name;
}

static void bpf_diag_insn_print(void *private_data, const char *fmt, ...)
{
	struct bpf_diag_insn_buf *buf = private_data;
	va_list args;

	if (buf->len >= buf->size)
		return;

	va_start(args, fmt);
	buf->len += vscnprintf(buf->buf + buf->len, buf->size - buf->len,
			       fmt, args);
	va_end(args);
}

static const char *bpf_diag_kfunc_name(void *private_data,
				       const struct bpf_insn *insn)
{
	const struct btf_type *func;
	struct btf *btf;

	(void)private_data;

	if (insn->src_reg != BPF_PSEUDO_KFUNC_CALL || insn->off)
		return NULL;

	btf = bpf_get_btf_vmlinux();
	if (IS_ERR_OR_NULL(btf))
		return NULL;

	func = btf_type_by_id(btf, insn->imm);
	if (!func)
		return NULL;

	return btf_name_by_offset(btf, func->name_off);
}

static void bpf_diag_format_insn(struct bpf_verifier_env *env, int insn_idx,
				 struct bpf_diag_insn *diag_insn)
{
	struct bpf_insn *insn;
	struct bpf_diag_insn_buf buf = {
		.buf = diag_insn->text,
		.size = sizeof(diag_insn->text),
	};
	const struct bpf_insn_cbs cbs = {
		.cb_call = bpf_diag_kfunc_name,
		.cb_print = bpf_diag_insn_print,
		.private_data = &buf,
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
	while (buf.len && (diag_insn->text[buf.len - 1] == '\n' ||
			   diag_insn->text[buf.len - 1] == '\r'))
		diag_insn->text[--buf.len] = '\0';

	diag_insn->valid = true;
}

static void bpf_diag_format_source_text(char *buf, size_t size,
					const char *line, int width)
{
	bool truncated = false;
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

	if (*line)
		truncated = true;
	if (truncated) {
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
					    int line_num, const char *line,
					    const struct bpf_diag_insn *diag_insn,
					    int focus_insn_idx,
					    int insn_width)
{
	char source_lane[BPF_DIAG_SOURCE_LANE_WIDTH + 1];

	bpf_diag_format_source_lane(source_lane, sizeof(source_lane),
				    source_prefix, source_line_width,
				    line_num, line);

	verbose(env, "  %-*s%*s", BPF_DIAG_SOURCE_LANE_WIDTH,
		source_lane, BPF_DIAG_COLUMN_GAP, "");
	if (diag_insn->valid)
		verbose(env, "%s%*d | %s",
			diag_insn->idx == focus_insn_idx ? ">>> " : "    ",
			insn_width, diag_insn->idx, diag_insn->text);
	verbose(env, "\n");
}

static const char *bpf_diag_category_name(enum bpf_diag_category category)
{
	switch (category) {
	case BPF_DIAG_CATEGORY_MEMORY_SAFETY:
		return "Memory Safety";
	case BPF_DIAG_CATEGORY_REGISTER_TYPE_SAFETY:
		return "Register Type Safety";
	case BPF_DIAG_CATEGORY_CALL_TYPE_SAFETY:
		return "Call Type Safety";
	case BPF_DIAG_CATEGORY_RESOURCE_LIFETIME_SAFETY:
		return "Resource Lifetime Safety";
	case BPF_DIAG_CATEGORY_EXECUTION_CONTEXT_SAFETY:
		return "Execution Context Safety";
	case BPF_DIAG_CATEGORY_PROGRAM_STRUCTURE:
		return "Program Structure";
	case BPF_DIAG_CATEGORY_POLICY:
		return "Policy";
	case BPF_DIAG_CATEGORY_VERIFIER_LIMIT:
		return "Verifier Limit";
	case BPF_DIAG_CATEGORY_VERIFIER_INTERNAL_ERROR:
	default:
		return "Verifier Internal Error";
	}
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

void bpf_diag_report_header(struct bpf_verifier_env *env,
			    enum bpf_diag_category category,
			    const char *problem)
{
	char problem_buf[BPF_DIAG_MSG_LEN];

	strscpy(problem_buf, problem ?: "", sizeof(problem_buf));
	if (problem_buf[0] >= 'a' && problem_buf[0] <= 'z')
		problem_buf[0] += 'A' - 'a';

	verbose(env, "\nVerification failed: %s: %s\n",
		bpf_diag_category_name(category), problem_buf);
}

void bpf_diag_report_reason(struct bpf_verifier_env *env, const char *fmt, ...)
{
	va_list args;

	bpf_diag_report_section(env, "Reason");

	va_start(args, fmt);
	bpf_diag_vprint_indented(env, fmt, args);
	va_end(args);
}

void bpf_diag_report_section(struct bpf_verifier_env *env, const char *title)
{
	verbose(env, "\n%s:\n", title);
}

void bpf_diag_report_suggestion(struct bpf_verifier_env *env, const char *fmt, ...)
{
	va_list args;

	bpf_diag_report_section(env, "Suggestion");

	va_start(args, fmt);
	bpf_diag_vprint_indented(env, fmt, args);
	va_end(args);
	verbose(env, "\n");
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

static bool bpf_diag_var_off_unknown(u64 value, u64 mask)
{
	return value == 0 && mask == U64_MAX;
}

static bool bpf_diag_snapshot_unknown(const struct bpf_diag_reg_snapshot *snapshot)
{
	return bpf_diag_var_off_unknown(snapshot->var_off_value,
					snapshot->var_off_mask) &&
	       bpf_diag_range_unknown(snapshot->smin_value, snapshot->smax_value,
				      snapshot->umin_value, snapshot->umax_value);
}

static void bpf_diag_format_scalar_range(char *buf, size_t size,
					 s64 smin, s64 smax,
					 u64 umin, u64 umax)
{
	char smin_buf[32], smax_buf[32], umin_buf[32], umax_buf[32];

	bpf_diag_format_s64_value(smin_buf, sizeof(smin_buf), smin);
	bpf_diag_format_s64_value(smax_buf, sizeof(smax_buf), smax);
	bpf_diag_format_u64_value(umin_buf, sizeof(umin_buf), umin);
	bpf_diag_format_u64_value(umax_buf, sizeof(umax_buf), umax);

	scnprintf(buf, size,
		  "signed range [%s, %s], unsigned range [%s, %s]",
		  smin_buf, smax_buf, umin_buf, umax_buf);
}

static void bpf_diag_print_source_annotation(struct bpf_verifier_env *env,
					     int line_width, int indent,
					     const char *label,
					     const char *msg)
{
	char first_prefix[128], next_prefix[128], text[BPF_DIAG_MSG_LEN];

	scnprintf(first_prefix, sizeof(first_prefix), "  %*s | %*s^-- ",
		  line_width + 4, "", indent, "");
	scnprintf(next_prefix, sizeof(next_prefix), "  %*s | %*s    ",
		  line_width + 4, "", indent, "");
	scnprintf(text, sizeof(text), "%s: %s", label, msg);

	bpf_diag_print_wrapped_prefixed(env, first_prefix, next_prefix, text);
}

void bpf_diag_report_source(struct bpf_verifier_env *env, u32 insn_idx,
			    char marker, const char *fmt, ...)
{
	struct bpf_diag_source src;
	struct bpf_diag_insn diag_insn[1 + BPF_DIAG_INSN_CONTEXT * 2];
	char msg[BPF_DIAG_MSG_LEN];
	const char *func, *label;
	int start_line, end_line, line_num, indent, width;
	int insn_width, i;
	va_list args;

	va_start(args, fmt);
	vscnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);
	label = bpf_diag_marker_label(marker);

	if (!bpf_diag_get_source(env, insn_idx, &src)) {
		verbose(env, "  insn %u\n", insn_idx);
		bpf_diag_print_source_annotation(env, 0, 0, label, msg);
		return;
	}

	func = bpf_diag_func_name(env, insn_idx);
	if (func && *func)
		verbose(env, "  %s @ %s:%d:%d\n", func, src.file,
			src.line_num, src.line_col);
	else
		verbose(env, "  %s:%d:%d\n", src.file, src.line_num,
			src.line_col);

	start_line = max_t(int, 1, src.line_num - BPF_DIAG_SOURCE_CONTEXT);
	end_line = src.line_num + BPF_DIAG_SOURCE_CONTEXT;
	width = bpf_diag_line_width(end_line);
	indent = bpf_diag_line_indent(src.line);
	insn_width = bpf_diag_line_width(env->prog->len ? env->prog->len - 1 : 0);

	for (i = 0; i < ARRAY_SIZE(diag_insn); i++) {
		int row = i - BPF_DIAG_INSN_CONTEXT;

		bpf_diag_format_insn(env, insn_idx + row, &diag_insn[i]);
	}

	for (line_num = start_line; line_num <= end_line; line_num++) {
		const char *line;
		int row = line_num - src.line_num;

		line = line_num == src.line_num ?
		       src.line :
		       bpf_diag_find_source_line(env, src.file_name_off, line_num);

		bpf_diag_print_source_insn_line(env,
						line_num == src.line_num ?
						">>> " : "    ",
						width, line_num, line,
						&diag_insn[row + BPF_DIAG_INSN_CONTEXT],
						insn_idx, insn_width);
		if (line_num == src.line_num)
			bpf_diag_print_source_annotation(env, width, indent,
							 label, msg);
	}
}

void bpf_diag_clear_history(struct bpf_verifier_state *state)
{
	kfree(state->diag_history);
	state->diag_history = NULL;
	state->diag_history_cnt = 0;
	state->diag_history_omitted = 0;
}

void bpf_diag_copy_history(struct bpf_verifier_state *dst,
			   const struct bpf_verifier_state *src)
{
	struct bpf_diag_history_event *history;

	if (!src->diag_history_cnt) {
		bpf_diag_clear_history(dst);
		dst->diag_history_omitted = src->diag_history_omitted;
		return;
	}

	history = krealloc_array(dst->diag_history, src->diag_history_cnt,
				 sizeof(*history), GFP_KERNEL_ACCOUNT);
	if (!history) {
		kfree(dst->diag_history);
		dst->diag_history = NULL;
		dst->diag_history_cnt = 0;
		dst->diag_history_omitted = src->diag_history_omitted +
					    src->diag_history_cnt;
		return;
	}

	dst->diag_history = history;
	memcpy(dst->diag_history, src->diag_history,
	       src->diag_history_cnt * sizeof(*dst->diag_history));
	dst->diag_history_cnt = src->diag_history_cnt;
	dst->diag_history_omitted = src->diag_history_omitted;
}

static void
bpf_diag_drop_oldest_and_append_history(struct bpf_verifier_state *state,
					const struct bpf_diag_history_event *event)
{
	if (!state->diag_history_cnt) {
		state->diag_history_omitted++;
		return;
	}

	memmove(state->diag_history, state->diag_history + 1,
		(state->diag_history_cnt - 1) * sizeof(*state->diag_history));
	state->diag_history[state->diag_history_cnt - 1] = *event;
	state->diag_history_omitted++;
}

static void bpf_diag_append_history(struct bpf_verifier_state *state,
				    const struct bpf_diag_history_event *event)
{
	struct bpf_diag_history_event *history;

	if (!state)
		return;

	if (state->diag_history_cnt < BPF_DIAG_HISTORY_MAX) {
		history = krealloc_array(state->diag_history,
					 state->diag_history_cnt + 1,
					 sizeof(*history), GFP_KERNEL_ACCOUNT);
		if (!history) {
			bpf_diag_drop_oldest_and_append_history(state, event);
			return;
		}

		state->diag_history = history;
		state->diag_history[state->diag_history_cnt++] = *event;
		return;
	}

	bpf_diag_drop_oldest_and_append_history(state, event);
}

void bpf_diag_record_branch(struct bpf_verifier_state *state, u32 insn_idx,
			    bool cond_true)
{
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = BPF_DIAG_HISTORY_BRANCH,
		.branch.cond_true = cond_true,
	};

	bpf_diag_append_history(state, &event);
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
	snapshot->var_off_known = tnum_is_const(reg->var_off);
	snapshot->var_off_value = reg->var_off.value;
	snapshot->var_off_mask = reg->var_off.mask;
	snapshot->smin_value = reg_smin(reg);
	snapshot->smax_value = reg_smax(reg);
	snapshot->umin_value = reg_umin(reg);
	snapshot->umax_value = reg_umax(reg);
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
	       old->var_off_known == new->var_off_known &&
	       old->var_off_value == new->var_off_value &&
	       old->var_off_mask == new->var_off_mask &&
	       old->smin_value == new->smin_value &&
	       old->smax_value == new->smax_value &&
	       old->umin_value == new->umin_value &&
	       old->umax_value == new->umax_value;
}

static bool bpf_diag_reg_snapshot_eq(const struct bpf_diag_history_event *event)
{
	return bpf_diag_snapshot_eq(&event->reg.old, &event->reg.new);
}

static void bpf_diag_record_reg_mod_reason(struct bpf_verifier_state *state,
					   u32 insn_idx, u8 dst_reg,
					   bool src_valid, u8 src_reg,
					   u8 opcode,
					   enum bpf_diag_reg_mod_reason reason,
					   const struct bpf_reg_state *old_reg,
					   const struct bpf_reg_state *new_reg)
{
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = BPF_DIAG_HISTORY_REG_MOD,
		.reg.dst_reg = dst_reg,
		.reg.src_reg = src_reg,
		.reg.opcode = opcode,
		.reg.src_valid = src_valid,
	};

	if (state && state->frame[state->curframe])
		event.reg.frameno = state->frame[state->curframe]->frameno;

	bpf_diag_snapshot_reg(&event, reason, old_reg, new_reg);
	if (reason == BPF_DIAG_REG_MOD_WRITE &&
	    bpf_diag_reg_snapshot_eq(&event))
		return;

	bpf_diag_append_history(state, &event);
}

void bpf_diag_record_reg_mod(struct bpf_verifier_state *state, u32 insn_idx,
			     u8 dst_reg, bool src_valid, u8 src_reg, u8 opcode,
			     const struct bpf_reg_state *old_reg,
			     const struct bpf_reg_state *new_reg)
{
	bpf_diag_record_reg_mod_reason(state, insn_idx, dst_reg, src_valid,
				       src_reg, opcode, BPF_DIAG_REG_MOD_WRITE,
				       old_reg, new_reg);
}

void bpf_diag_record_reg_invalidate(struct bpf_verifier_state *state,
				    u32 insn_idx, u8 dst_reg,
				    enum bpf_diag_reg_mod_reason reason,
				    const struct bpf_reg_state *old_reg,
				    const struct bpf_reg_state *new_reg)
{
	bpf_diag_record_reg_mod_reason(state, insn_idx, dst_reg, false, 0, 0,
				       reason, old_reg, new_reg);
}

void bpf_diag_record_stack_arg(struct bpf_verifier_state *state, u32 insn_idx,
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

	bpf_diag_append_history(state, &event);
}

static void bpf_diag_record_ref(struct bpf_verifier_state *state, u32 insn_idx,
				u8 kind, u32 ref_id)
{
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = kind,
		.ref.ref_id = ref_id,
	};

	bpf_diag_append_history(state, &event);
}

void bpf_diag_record_ref_acquire(struct bpf_verifier_state *state, u32 insn_idx,
				 u32 ref_id)
{
	bpf_diag_record_ref(state, insn_idx, BPF_DIAG_HISTORY_REF_ACQUIRE,
			    ref_id);
}

void bpf_diag_record_ref_release(struct bpf_verifier_state *state, u32 insn_idx,
				 u32 ref_id)
{
	bpf_diag_record_ref(state, insn_idx, BPF_DIAG_HISTORY_REF_RELEASE,
			    ref_id);
}

void bpf_diag_record_context(struct bpf_verifier_state *state, u32 insn_idx,
			     enum bpf_diag_context_kind ctx_kind, bool enter,
			     u32 depth)
{
	struct bpf_diag_history_event event = {
		.insn_idx = insn_idx,
		.kind = BPF_DIAG_HISTORY_CONTEXT,
		.ctx.kind = ctx_kind,
		.ctx.enter = enter,
		.ctx.depth = depth,
	};

	if (ctx_kind == BPF_DIAG_CONTEXT_NONE)
		return;

	bpf_diag_append_history(state, &event);
}

static int bpf_diag_history_start_idx(const struct bpf_verifier_state *state,
				      const struct bpf_diag_history_opts *opts)
{
	int i;

	if (!opts || opts->scope == BPF_DIAG_HISTORY_SCOPE_ALL)
		return 0;

	for (i = state->diag_history_cnt; i > 0; i--) {
		const struct bpf_diag_history_event *event = &state->diag_history[i - 1];

		if (opts->scope == BPF_DIAG_HISTORY_SCOPE_REG &&
		    event->kind == BPF_DIAG_HISTORY_REG_MOD &&
		    event->reg.dst_reg == opts->regno &&
		    event->reg.frameno == opts->frameno)
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
		if (opts->scope == BPF_DIAG_HISTORY_SCOPE_CONTEXT &&
		    event->kind == BPF_DIAG_HISTORY_CONTEXT &&
		    event->ctx.enter &&
		    event->ctx.kind == opts->ctx_kind)
			return i - 1;
	}

	if (opts->scope == BPF_DIAG_HISTORY_SCOPE_CONTEXT)
		return state->diag_history_cnt;

	return 0;
}

static bool bpf_diag_history_event_visible(const struct bpf_diag_history_event *event,
					   const struct bpf_diag_history_opts *opts)
{
	if (!opts || opts->scope == BPF_DIAG_HISTORY_SCOPE_ALL)
		return true;

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

static void bpf_diag_format_var_offset(char *buf, size_t size,
				       const struct bpf_diag_reg_snapshot *snapshot)
{
	char range[BPF_DIAG_REG_DESC_LEN];

	if (snapshot->var_off_known) {
		scnprintf(buf, size, "at offset %lld",
			  snapshot->var_off_value);
		return;
	}

	if (bpf_diag_snapshot_unknown(snapshot)) {
		scnprintf(buf, size, "with unknown offset");
		return;
	}

	bpf_diag_format_scalar_range(range, sizeof(range),
				     snapshot->smin_value, snapshot->smax_value,
				     snapshot->umin_value, snapshot->umax_value);
	scnprintf(buf, size,
		  "with variable offset: known bits %#llx, unknown mask %#llx, %s",
		  (u64)snapshot->var_off_value, snapshot->var_off_mask,
		  range);
}

static bool bpf_diag_format_snapshot_btf_type(char *buf, size_t size,
					      const struct bpf_diag_reg_snapshot *snapshot)
{
	const struct btf_type *type;
	const char *name;

	if (!snapshot->btf || !snapshot->btf_id)
		return false;

	type = btf_type_by_id(snapshot->btf, snapshot->btf_id);
	if (!type)
		return false;

	name = btf_name_by_offset(snapshot->btf, type->name_off);
	bpf_diag_format_btf_type(buf, size, type, name);
	return true;
}

static void bpf_diag_format_reg_snapshot(struct bpf_verifier_env *env, char *buf,
					 size_t size,
					 const struct bpf_diag_reg_snapshot *snapshot)
{
	const char *type_name = reg_type_str(env, snapshot->type);
	char offset_desc[BPF_DIAG_REG_DESC_LEN];
	char btf_type[BPF_DIAG_REG_DESC_LEN];
	const char *map_name;
	bool has_btf_type;

	bpf_diag_format_var_offset(offset_desc, sizeof(offset_desc), snapshot);
	has_btf_type = bpf_diag_format_snapshot_btf_type(btf_type,
							 sizeof(btf_type),
							 snapshot);

	if (snapshot->type == SCALAR_VALUE) {
		char range[BPF_DIAG_REG_DESC_LEN];

		if (snapshot->var_off_known) {
			scnprintf(buf, size, "integer scalar value %lld",
				  snapshot->var_off_value);
			return;
		}

		if (bpf_diag_snapshot_unknown(snapshot)) {
			scnprintf(buf, size, "integer scalar with unknown value");
			return;
		}

		if (snapshot->smin_value == snapshot->smax_value &&
		    snapshot->umin_value == snapshot->umax_value) {
			scnprintf(buf, size, "integer scalar value %lld",
				  snapshot->smin_value);
			return;
		}

		bpf_diag_format_scalar_range(range, sizeof(range),
					     snapshot->smin_value,
					     snapshot->smax_value,
					     snapshot->umin_value,
					     snapshot->umax_value);
		scnprintf(buf, size,
			  "integer scalar with %s", range);
		return;
	}

	if (snapshot->type == NOT_INIT) {
		scnprintf(buf, size, "uninitialized value");
		return;
	}

	if (base_type(snapshot->type) == PTR_TO_CTX) {
		scnprintf(buf, size, "context pointer %s", offset_desc);
		return;
	}

	if (base_type(snapshot->type) == PTR_TO_STACK) {
		scnprintf(buf, size, "stack pointer %s", offset_desc);
		return;
	}

	if (base_type(snapshot->type) == PTR_TO_MAP_VALUE) {
		map_name = bpf_diag_reg_map_name(snapshot->map_ptr);
		if (map_name) {
			scnprintf(buf, size, "%s from %s %s",
				  type_may_be_null(snapshot->type) ?
				  "nullable map value" : "map value",
				  map_name, offset_desc);
			return;
		}
		scnprintf(buf, size, "%s %s",
			  type_may_be_null(snapshot->type) ?
			  "nullable map value" : "map value",
			  offset_desc);
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
				  btf_type);
		else
			scnprintf(buf, size, "borrowed allocated object pointer");
		return;
	}

	if (type_is_ptr_alloc_obj(snapshot->type)) {
		if (has_btf_type)
			scnprintf(buf, size,
				  "owned allocated object pointer type=%s",
				  btf_type);
		else
			scnprintf(buf, size, "owned allocated object pointer");
		return;
	}

	if (base_type(snapshot->type) == PTR_TO_BTF_ID && has_btf_type) {
		scnprintf(buf, size, "%s type=%s %s", type_name, btf_type,
			  offset_desc);
		return;
	}

	scnprintf(buf, size, "%s %s", type_name, offset_desc);
}

static void bpf_diag_print_reg_mod(struct bpf_verifier_env *env,
				   const struct bpf_diag_history_event *event)
{
	char old_buf[BPF_DIAG_REG_DESC_LEN], new_buf[BPF_DIAG_REG_DESC_LEN];
	const char *reason = NULL;

	bpf_diag_format_reg_snapshot(env, old_buf, sizeof(old_buf),
				     &event->reg.old);
	bpf_diag_format_reg_snapshot(env, new_buf, sizeof(new_buf),
				     &event->reg.new);

	switch (event->reg.reason) {
	case BPF_DIAG_REG_MOD_REF_RELEASE:
		reason = "resource release invalidated this pointer";
		break;
	case BPF_DIAG_REG_MOD_PKT_DATA_CHANGE:
		reason = "packet data may have moved";
		break;
	case BPF_DIAG_REG_MOD_WRITE:
	default:
		break;
	}

	if (reason) {
		bpf_diag_report_source(env, event->insn_idx, 'x',
				       "R%d: %s; previous value was %s",
				       event->reg.dst_reg, reason, old_buf);
		return;
	}

	bpf_diag_report_source(env, event->insn_idx, '~',
			       "R%d changed from %s to %s",
			       event->reg.dst_reg, old_buf, new_buf);
}

static void bpf_diag_print_ref_event(struct bpf_verifier_env *env,
				     const struct bpf_diag_history_event *event)
{
	if (event->kind == BPF_DIAG_HISTORY_REF_ACQUIRE) {
		bpf_diag_report_source(env, event->insn_idx, '+',
				       "owned resource (id=%u)",
				       event->ref.ref_id);
		return;
	}

	bpf_diag_report_source(env, event->insn_idx, '-',
			       "owned resource (id=%u)",
			       event->ref.ref_id);
}

static void bpf_diag_print_context_event(struct bpf_verifier_env *env,
					 const struct bpf_diag_history_event *event)
{
	bpf_diag_report_source(env, event->insn_idx, '@',
			       "%s %s; depth is now %u",
			       event->ctx.enter ? "entered" : "left",
			       bpf_diag_context_name(event->ctx.kind),
			       event->ctx.depth);
}

void bpf_diag_print_history(struct bpf_verifier_env *env,
			    const struct bpf_diag_history_opts *opts)
{
	const struct bpf_verifier_state *state = env->cur_state;
	const struct bpf_diag_history_event *event;
	bool printed = false;
	int start_idx;
	u32 i;

	bpf_diag_report_section(env, "Causal path");

	if (!state)
		return;

	start_idx = bpf_diag_history_start_idx(state, opts);
	if (state->diag_history_omitted && start_idx == 0)
		verbose(env, "  ... %u earlier diagnostic events omitted by display limit ...\n",
			state->diag_history_omitted);

	for (i = start_idx; i < state->diag_history_cnt; i++) {
		event = &state->diag_history[i];
		if (!bpf_diag_history_event_visible(event, opts))
			continue;

		switch (event->kind) {
		case BPF_DIAG_HISTORY_BRANCH:
			bpf_diag_report_source(env, event->insn_idx, '?',
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

	if (!printed && !state->diag_history_omitted)
		verbose(env, "  no recorded diagnostic events on this path\n");
}
