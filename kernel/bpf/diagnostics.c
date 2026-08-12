// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

#include <linux/bpf_verifier.h>
#include <linux/ctype.h>
#include <linux/stdarg.h>

#include "diagnostics.h"

#define MEMORY_SAFETY "Memory Safety"
#define REGISTER_TYPE_SAFETY "Register Type Safety"
#define CALL_TYPE_SAFETY "Call Type Safety"
#define RESOURCE_LIFETIME_SAFETY "Resource Lifetime Safety"
#define EXECUTION_CONTEXT_SAFETY "Execution Context Safety"
#define PROGRAM_STRUCTURE "Program Structure"
#define POLICY "Policy"
#define VERIFIER_LIMIT "Verifier Limit"

bool bpf_diag_enabled(const struct bpf_verifier_env *env)
{
	return env->log.level & BPF_LOG_LEVEL;
}

static void diag_write(struct bpf_verifier_env *env, const char *fmt, ...) __printf(2, 3);

static void diag_write(struct bpf_verifier_env *env, const char *fmt, ...)
{
	va_list args;

	if (!bpf_diag_enabled(env))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(&env->log, fmt, args);
	va_end(args);
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
