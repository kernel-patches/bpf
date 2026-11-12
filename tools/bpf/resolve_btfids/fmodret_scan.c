// SPDX-License-Identifier: GPL-2.0-only
/*
 * Find the errors which a function of an image returns, in the machine code:
 * the constants -MAX_ERRNO..-1 which an instruction loads into a register and
 * which copies may carry from there to the return value register at a return.
 *
 * This file brings the function into the form which the analysis in text_flow.c
 * takes, and collects the results.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bits.h>

#include "fmodret_scan.h"
#include "text_flow.h"

#define MAX_ERRNO	4095
#define MAX_SUBFUNCS	3

/* The function at an address, whatever its names are. See scan_set_proto() */
struct callee {
	uint64_t addr;
	u32 pointers;	/* the registers */
	bool effect;
};

struct scan {
	const struct image *img;
	uint64_t return_thunk;
	uint64_t entry_hook;
	struct callee *callees;		/* one for each of img->funcs, sorted by address */
	/* The function which is being looked at */
	struct text_flow flow;
	size_t max_insns;
	int64_t *values;
	size_t nr_values, max_values;
};

static int cmp_callee(const void *va, const void *vb)
{
	const struct callee *a = va, *b = vb;

	return a->addr > b->addr ? 1 : a->addr < b->addr ? -1 : 0;
}

/* Of two names for ADDR always the same one is found */
static struct callee *callee_at(const struct scan *s, uint64_t addr)
{
	const struct callee key = { .addr = addr };

	return bsearch(&key, s->callees, s->img->nr_funcs, sizeof(key), cmp_callee);
}

void scan_set_proto(struct scan *s, const struct image_func *f, unsigned int pointers, bool effect)
{
	struct callee *callee = callee_at(s, f->addr);
	unsigned int i;

	callee->effect = effect;
	callee->pointers = 0;
	for (i = 0; i < s->flow.arch->nr_args; i++)
		if (pointers & BIT(i))
			callee->pointers |= BIT(s->flow.arch->args[i]);
}

/* Append the instructions of SIZE bytes at ADDR */
static int decode(struct scan *s, uint64_t addr, uint64_t size)
{
	struct text_flow *flow = &s->flow;
	const unsigned char *code;
	uint64_t off;
	size_t avail;

	code = image_bytes(s->img, addr, &avail);
	if (!code || avail < size)
		return -EINVAL;
	for (off = 0; off < size; off += flow->insns[flow->nr_insns++].len) {
		const struct image_reloc *reloc;
		const struct callee *callee;
		struct text_insn *insn;

		if (flow->nr_insns == s->max_insns) {
			size_t max = s->max_insns ? 2 * s->max_insns : 1024;
			struct text_facts *facts = realloc(flow->facts, max * sizeof(*facts));
			struct text_reach *reach;

			if (!facts)
				return -ENOMEM;
			flow->facts = facts;
			reach = realloc(flow->reach, max * sizeof(*reach));
			if (!reach)
				return -ENOMEM;
			flow->reach = reach;
			insn = realloc(flow->insns, max * sizeof(*insn));
			if (!insn)
				return -ENOMEM;
			flow->insns = insn;
			s->max_insns = max;
		}
		insn = &flow->insns[flow->nr_insns];
		if (flow->arch->decode(code + off, size - off, addr + off, insn) < 0)
			return -EINVAL;
		insn->addr = addr + off;

		if (insn->kind < TEXT_BRANCH || !insn->imm)
			continue;
		/* The field is relative to its own address, and 0 in a relocatable file */
		reloc = image_reloc(s->img, insn->addr, insn->len);
		if (reloc)
			insn->imm += reloc->target - reloc->addr;
		if (insn->kind == TEXT_BRANCH && insn->imm == s->return_thunk)
			insn->kind = TEXT_RETURN;
		if (insn->kind != TEXT_CALL)
			continue;
		callee = callee_at(s, insn->imm);
		if (insn->imm == s->entry_hook)
			insn->kind = TEXT_OTHER;
		else if (callee && callee->effect)
			insn->pointers = callee->pointers;
	}
	return 0;
}

static int cmp_addr(const void *va, const void *vb)
{
	const struct image_func * const *a = va, * const *b = vb;

	return (*a)->addr > (*b)->addr ? 1 : (*a)->addr < (*b)->addr ? -1 : 0;
}

/*
 * Decode F and its cold subfunctions: compilers move unlikely blocks of F to a
 * symbol of their own, F.cold or F.__part.1. By name they follow F.
 */
static int decode_func(struct scan *s, const struct image_func *f)
{
	const struct image_func *funcs[1 + MAX_SUBFUNCS] = { f }, *g;
	const struct image_func *end = s->img->funcs + s->img->nr_funcs;
	size_t len = strlen(f->name);
	unsigned int nr = 1, i;
	int err = 0;

	for (g = f + 1; g < end && !strncmp(g->name, f->name, len) && g->name[len] == '.'; g++)
		if (nr <= MAX_SUBFUNCS &&
		    (!strncmp(g->name + len, ".cold", 5) || !strncmp(g->name + len, ".__part.", 8)))
			funcs[nr++] = g;
	qsort(funcs, nr, sizeof(*funcs), cmp_addr);
	s->flow.nr_insns = 0;
	for (i = 0; !err && i < nr; i++)
		err = decode(s, funcs[i]->addr, funcs[i]->size);
	return err;
}

/* The return value register may hold V */
static int add_value(struct scan *s, int64_t v)
{
	size_t i;

	if ((int32_t)v < -MAX_ERRNO || (int32_t)v >= 0)
		return 0;
	for (i = 0; i < s->nr_values; i++)
		if (s->values[i] == v)
			return 0;
	if (s->nr_values == s->max_values) {
		size_t max = s->max_values ? 2 * s->max_values : 16;
		int64_t *values = realloc(s->values, max * sizeof(*values));

		if (!values)
			return -ENOMEM;
		s->values = values;
		s->max_values = max;
	}
	s->values[s->nr_values++] = v;
	return 0;
}

int scan_func(struct scan *s, const struct image_func *f, const int64_t **values)
{
	const struct text_flow *flow = &s->flow;
	int err = decode_func(s, f);
	u32 i;

	if (err)
		return err;
	s->flow.entry = f->addr;
	s->flow.args = callee_at(s, f->addr)->pointers;
	text_flow_fold(&s->flow);
	text_flow_solve(&s->flow);

	s->nr_values = 0;
	for (i = 0; i < flow->nr_insns && !err; i++) {
		const struct text_insn *insn = &flow->insns[i];
		uint64_t imm[2] = { insn->imm, insn->imm2 };
		struct text_facts out;
		unsigned int n;

		if (insn->kind != TEXT_MOV_IMM && insn->kind != TEXT_SELECT_IMM)
			continue;
		if (flow->reach[i].path == TEXT_EFFECT_PATH)
			continue;
		out = text_flow_out(flow, i);
		for (n = 0; n < 2 && !err; n++) {
			if (out.same & BIT(insn->dst))
				err = add_value(s, imm[n]);
			if (!err && out.zext & BIT(insn->dst))
				err = add_value(s, (uint32_t)imm[n]);
			if (!err && out.sext & BIT(insn->dst))
				err = add_value(s, (int32_t)imm[n]);
		}
	}
	*values = s->values;
	return err ?: s->nr_values;
}

struct scan *scan_open(const struct image *img)
{
	struct scan *s = calloc(1, sizeof(*s));
	GElf_Ehdr ehdr;
	size_t i;

	if (!s || !gelf_getehdr(img->elf, &ehdr))
		goto err;
	s->flow.arch = text_arch_init(ehdr.e_machine);
	if (!s->flow.arch) {
		fprintf(stderr, "FAILED: no decoder for the code of ELF machine %u\n", ehdr.e_machine);
		goto err;
	}
	s->img = img;
	if (s->flow.arch->return_thunk)
		s->return_thunk = image_symbol(img, s->flow.arch->return_thunk);
	if (s->flow.arch->entry_hook)
		s->entry_hook = image_symbol(img, s->flow.arch->entry_hook);
	s->callees = calloc(img->nr_funcs, sizeof(*s->callees));
	if (!s->callees)
		goto err;
	for (i = 0; i < img->nr_funcs; i++)
		s->callees[i].addr = img->funcs[i].addr;
	qsort(s->callees, img->nr_funcs, sizeof(*s->callees), cmp_callee);
	return s;
err:
	free(s);
	return NULL;
}

void scan_close(struct scan *s)
{
	if (!s)
		return;
	free(s->flow.insns);
	free(s->flow.facts);
	free(s->flow.reach);
	free(s->callees);
	free(s->values);
	free(s);
}
