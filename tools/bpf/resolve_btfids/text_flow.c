// SPDX-License-Identifier: GPL-2.0-only
/* Which values does a function return? See text_flow.h */

#include <linux/bits.h>
#include <linux/compiler.h>

#include "text_flow.h"

/* Return the index of the instruction which runs after I if I does not branch */
static u32 next_insn(const struct text_flow *flow, u32 i)
{
	const struct text_insn *insn = &flow->insns[i];

	/* A function and its cold subfunctions are not adjacent */
	return i + 1 < flow->nr_insns && insn[1].addr == insn->addr + insn->len ?
	       i + 1 : TEXT_NO_INSN;
}

static u64 alu(const struct text_insn *insn, u64 v)
{
	switch (insn->op) {
	case TEXT_AND:
		v &= insn->imm;
		break;
	case TEXT_XOR:
		v ^= insn->imm;
		break;
	case TEXT_SUB:
		v -= insn->imm;
		break;
	}
	return insn->is32 ? (u32)v : v;
}

void text_flow_fold(struct text_flow *flow)
{
	/* The instruction which has left a constant in each register */
	u32 def[TEXT_MAX_REGS], i, r;

	for (i = 0; i < flow->nr_insns; i++) {
		struct text_insn *insn = &flow->insns[i];
		u32 defs = insn->defs;

		/* The function or a cold subfunction begins */
		if (!i || next_insn(flow, i - 1) == TEXT_NO_INSN)
			for (r = 0; r < TEXT_MAX_REGS; r++)
				def[r] = TEXT_NO_INSN;
		if (insn->kind == TEXT_ALU_IMM && def[insn->src] != TEXT_NO_INSN) {
			insn->kind = TEXT_MOV_IMM;
			insn->imm2 = alu(insn, flow->insns[def[insn->src]].imm2);
			insn->imm = alu(insn, flow->insns[def[insn->src]].imm);
		}
		if (insn->kind == TEXT_BRANCH || insn->kind == TEXT_RETURN)
			defs = TEXT_ALL_REGS;
		else if (insn->kind == TEXT_CALL)
			defs |= flow->arch->caller_saved;
		else if (insn->kind != TEXT_OTHER && insn->kind != TEXT_COND_BRANCH)
			defs |= BIT(insn->dst);
		for (r = 0; defs && r < TEXT_MAX_REGS; r++)
			if (defs & BIT(r))
				def[r] = TEXT_NO_INSN;
		if (insn->kind == TEXT_MOV_IMM)
			def[insn->dst] = i;
	}
}

static u32 insn_at(const struct text_flow *flow, u64 addr)
{
	u32 lo = 0, hi = flow->nr_insns;

	while (lo < hi) {
		u32 mid = lo + (hi - lo) / 2;

		if (flow->insns[mid].addr < addr)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo < flow->nr_insns && flow->insns[lo].addr == addr ? lo : TEXT_NO_INSN;
}

static void join(struct text_facts *facts, const struct text_flow *flow, u32 i)
{
	if (i == TEXT_NO_INSN)
		return;
	facts->same |= flow->facts[i].same;
	facts->zext |= flow->facts[i].zext;
	facts->sext |= flow->facts[i].sext;
}

static void kill(struct text_facts *facts, u32 regs)
{
	facts->same &= ~regs;
	facts->zext &= ~regs;
	facts->sext &= ~regs;
}

enum cast { SAME, ZEXT, SEXT };

/* The facts of DST behind "dst = cast(src)" are those of SRC before it */
static void copy(struct text_facts *in, const struct text_facts *out, u8 dst, u8 src,
		 enum cast cast)
{
	bool same = out->same & BIT(dst), zext = out->zext & BIT(dst), sext = out->sext & BIT(dst);

	if (same && cast == SAME)
		in->same |= BIT(src);
	if (zext || (same && cast == ZEXT))
		in->zext |= BIT(src);
	if (sext || (same && cast == SEXT))
		in->sext |= BIT(src);
}

/* Return the facts before instruction I */
static struct text_facts transfer(const struct text_flow *flow, u32 i)
{
	const struct text_insn *insn = &flow->insns[i];
	struct text_facts out = {}, in;
	enum cast cast;

	switch (insn->kind) {
	case TEXT_RETURN:
		out.same = BIT(flow->arch->retval);
		return out;
	case TEXT_BRANCH:
		join(&out, flow, insn->target);
		return out;
	case TEXT_COND_BRANCH:
		join(&out, flow, insn->target);
		break;
	}
	join(&out, flow, next_insn(flow, i));

	in = out;
	kill(&in, insn->defs);
	switch (insn->kind) {
	case TEXT_CALL:
		kill(&in, flow->arch->caller_saved);
		break;
	case TEXT_MOV_IMM:
	case TEXT_ALU_IMM:
		kill(&in, BIT(insn->dst));
		break;
	case TEXT_MOV:
	case TEXT_SEXT32:
	case TEXT_SELECT:
	case TEXT_SELECT_IMM:
		cast = insn->kind == TEXT_SEXT32 ? SEXT : insn->is32 ? ZEXT : SAME;
		kill(&in, BIT(insn->dst));
		copy(&in, &out, insn->dst, insn->src, cast);
		if (insn->kind == TEXT_SELECT)
			copy(&in, &out, insn->dst, insn->src2, cast);
		break;
	}
	return in;
}

/*
 * Sweep from the last instruction to the first one until nothing changes. The
 * sets only grow, and one more sweep is needed only for what goes around a loop.
 */
void text_flow_solve(struct text_flow *flow)
{
	bool changed;
	u32 i;

	for (i = 0; i < flow->nr_insns; i++) {
		struct text_insn *insn = &flow->insns[i];

		flow->facts[i] = (struct text_facts){};
		insn->target = TEXT_NO_INSN;
		if ((insn->kind == TEXT_BRANCH || insn->kind == TEXT_COND_BRANCH) && insn->imm)
			insn->target = insn_at(flow, insn->imm);
	}
	do {
		changed = false;
		for (i = flow->nr_insns; i--; ) {
			struct text_facts *old = &flow->facts[i], new = transfer(flow, i);

			if (new.same == old->same && new.zext == old->zext && new.sext == old->sext)
				continue;
			*old = new;
			changed = true;
		}
	} while (changed);
}

struct text_facts text_flow_out(const struct text_flow *flow, u32 i)
{
	struct text_facts out = {};

	join(&out, flow, next_insn(flow, i));
	return out;
}
