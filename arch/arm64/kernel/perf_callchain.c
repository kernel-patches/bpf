// SPDX-License-Identifier: GPL-2.0-only
/*
 * arm64 callchain support
 *
 * Copyright (C) 2015 ARM Limited
 */
#include <linux/perf_event.h>
#include <linux/stacktrace.h>
#include <linux/uaccess.h>

#include <asm/pointer_auth.h>

static bool callchain_trace(void *data, unsigned long pc)
{
	struct perf_callchain_entry_ctx *entry = data;

	return perf_callchain_store(entry, pc) == 0;
}

void perf_callchain_user(struct perf_callchain_entry_ctx *entry,
			 struct pt_regs *regs)
{
	if (perf_guest_state()) {
		/* We don't support guest os callchain now */
		return;
	}

	arch_stack_walk_user(callchain_trace, entry, regs);
}

/*
 * Determine whether the regs were taken from an exception handler rather than
 * from perf_arch_fetch_caller_regs().
 */
static bool perf_hw_regs(struct pt_regs *regs)
{
	return (regs->pstate & PSR_MODE_MASK) != PSR_MODE_EL1t;
}

struct caller_regs_callchain {
	struct perf_callchain_entry_ctx *entry;
	bool skip_leaf;
};

static bool caller_regs_callchain_trace(void *data, unsigned long pc)
{
	struct caller_regs_callchain *cc = data;

	if (cc->skip_leaf) {
		cc->skip_leaf = false;
		return true;
	}
	return callchain_trace(cc->entry, pc);
}

void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
			   struct pt_regs *regs)
{
	if (perf_guest_state()) {
		/* We don't support guest os callchain now */
		return;
	}

	if (perf_hw_regs(regs)) {
		arch_stack_walk(callchain_trace, entry, current, regs);
	} else {
		struct caller_regs_callchain cc = { .entry = entry, .skip_leaf = true };

		arch_stack_walk(caller_regs_callchain_trace, &cc, current, regs);
	}
}
