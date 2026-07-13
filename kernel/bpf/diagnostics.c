// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

#include <linux/bpf_verifier.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/stdarg.h>
#include <linux/string.h>

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

bool bpf_diag_enabled(const struct bpf_verifier_env *env)
{
	return env->log.level & BPF_LOG_LEVEL;
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
