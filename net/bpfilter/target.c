// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "target.h"

#include <linux/err.h>
#include <linux/list.h>
#include <linux/netfilter/x_tables.h>

#include <errno.h>
#include <string.h>

#include "codegen.h"
#include "context.h"
#include "map-common.h"

static const struct target_ops *target_ops_map_find(struct hsearch_data *map, const char *name)
{
	const size_t namelen = strnlen(name, BPFILTER_EXTENSION_MAXNAMELEN);

	if (namelen < BPFILTER_EXTENSION_MAXNAMELEN)
		return map_find(map, name);

	return ERR_PTR(-EINVAL);
}

static int standard_target_check(struct context *ctx, const struct bpfilter_ipt_target *ipt_target)
{
	const struct bpfilter_ipt_standard_target *standard_target;

	standard_target = (const struct bpfilter_ipt_standard_target *)ipt_target;

	// Positive values of verdict denote a jump offset into a blob.
	if (standard_target->verdict > 0)
		return 0;

	// Special values like ACCEPT, DROP, RETURN are encoded as negative values.
	if (standard_target->verdict < 0) {
		if (standard_target->verdict == BPFILTER_RETURN)
			return 0;

		switch (convert_verdict(standard_target->verdict)) {
		case BPFILTER_NF_ACCEPT:
		case BPFILTER_NF_DROP:
		case BPFILTER_NF_QUEUE:
			return 0;
		}
	}

	BFLOG_DEBUG(ctx, "invalid verdict: %d\n", standard_target->verdict);

	return -EINVAL;
}

static int standard_target_gen_inline(struct codegen *ctx, const struct target *target)
{
	const struct bpfilter_ipt_standard_target *standard_target;
	int err;

	standard_target = (const struct bpfilter_ipt_standard_target *)target->ipt_target;

	if (standard_target->verdict >= 0) {
		struct codegen_subprog_desc *subprog;
		struct codegen_fixup_desc *fixup;

		subprog = malloc(sizeof(*subprog));
		if (!subprog)
			return -ENOMEM;

		INIT_LIST_HEAD(&subprog->list);
		subprog->type = CODEGEN_SUBPROG_USER_CHAIN;
		subprog->insn = 0;
		subprog->offset = standard_target->verdict;

		fixup = malloc(sizeof(*fixup));
		if (!fixup) {
			free(subprog);
			return -ENOMEM;
		}

		INIT_LIST_HEAD(&fixup->list);
		fixup->type = CODEGEN_FIXUP_JUMP_TO_CHAIN;
		fixup->insn = ctx->len_cur;
		fixup->offset = standard_target->verdict;

		list_add_tail(&fixup->list, &ctx->fixup);

		err = codegen_push_awaiting_subprog(ctx, subprog);
		if (err)
			return err;

		EMIT(ctx, BPF_JMP_IMM(BPF_JA, 0, 0, 0));

		return 0;
	}

	if (standard_target->verdict == BPFILTER_RETURN) {
		EMIT(ctx, BPF_EXIT_INSN());

		return 0;
	}

	err = ctx->codegen_ops->emit_ret_code(ctx, convert_verdict(standard_target->verdict));
	if (err)
		return err;

	EMIT(ctx, BPF_EXIT_INSN());

	return 0;
}

const struct target_ops standard_target_ops = {
	.name = "",
	.revision = 0,
	.size = sizeof(struct xt_standard_target),
	.check = standard_target_check,
	.gen_inline = standard_target_gen_inline,
};

static int error_target_check(struct context *ctx, const struct bpfilter_ipt_target *ipt_target)
{
	const struct bpfilter_ipt_error_target *error_target;
	size_t maxlen;

	error_target = (const struct bpfilter_ipt_error_target *)&ipt_target;
	maxlen = sizeof(error_target->error_name);
	if (strnlen(error_target->error_name, maxlen) == maxlen) {
		BFLOG_DEBUG(ctx, "cannot check error target: too long errorname\n");
		return -EINVAL;
	}

	return 0;
}

static int error_target_gen_inline(struct codegen *ctx, const struct target *target)
{
	return -EINVAL;
}

const struct target_ops error_target_ops = {
	.name = "ERROR",
	.revision = 0,
	.size = sizeof(struct xt_error_target),
	.check = error_target_check,
	.gen_inline = error_target_gen_inline,
};

int init_target(struct context *ctx, const struct bpfilter_ipt_target *ipt_target,
		struct target *target)
{
	const size_t maxlen = sizeof(ipt_target->u.user.name);
	const struct target_ops *found;
	int err;

	if (strnlen(ipt_target->u.user.name, maxlen) == maxlen) {
		BFLOG_DEBUG(ctx, "cannot init target: too long target name\n");
		return -EINVAL;
	}

	found = target_ops_map_find(&ctx->target_ops_map, ipt_target->u.user.name);
	if (IS_ERR(found)) {
		BFLOG_DEBUG(ctx, "cannot find target by name: '%s'\n", ipt_target->u.user.name);
		return PTR_ERR(found);
	}

	if (found->size != ipt_target->u.target_size ||
	    found->revision != ipt_target->u.user.revision) {
		BFLOG_DEBUG(ctx, "invalid target: '%s'\n", ipt_target->u.user.name);
		return -EINVAL;
	}

	err = found->check(ctx, ipt_target);
	if (err)
		return err;

	target->target_ops = found;
	target->ipt_target = ipt_target;

	return 0;
}
