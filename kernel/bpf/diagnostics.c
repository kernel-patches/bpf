// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

#include <linux/bpf_verifier.h>
#include <linux/stdarg.h>
#include <linux/string.h>

#include "diagnostics.h"

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)
#define BPF_DIAG_TEXT_WIDTH 120
#define BPF_DIAG_TEXT_INDENT "  "
#define BPF_DIAG_MSG_LEN 512

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

static void bpf_diag_vprint_indented(struct bpf_verifier_env *env,
				     const char *fmt, va_list args)
{
	char buf[1024];

	if (!bpf_verifier_log_needed(&env->log))
		return;

	vscnprintf(buf, sizeof(buf), fmt, args);
	bpf_diag_print_wrapped_text(env, buf);
}

void bpf_diag_report_header(struct bpf_verifier_env *env,
			    const char *category, const char *problem)
{
	char problem_buf[BPF_DIAG_MSG_LEN];

	strscpy(problem_buf, problem ?: "", sizeof(problem_buf));
	if (problem_buf[0] >= 'a' && problem_buf[0] <= 'z')
		problem_buf[0] += 'A' - 'a';

	verbose(env, "\nVerification failed: %s: %s\n", category,
		problem_buf);
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
