// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include "linux/cnum.h"
#include <linux/bpf_verifier.h>
#include <linux/jhash.h>
#include <linux/bug.h>
#include <linux/tnum.h>
#include <linux/overflow.h>

#define REGS_NUM BPF_SCEV_REGS_NUM
#define UNKNOWN_EXPR_ID 0
#define OPAQUE_EXPR_ID  1

/*
 * BPF instructions use 'code', 'src_reg', 'off' and 'imm' fields for instruction encoding.
 * For scalar evolution purpose we want to reuse most of the opcode definitions,
 * but also add a few custom operations (REG and IMM).
 * Use the enum below to uniformly represent all operations relevant for SCEV.
 */
enum expr_op {
	/* leave range 0..255 for standard bpf opcodes */
	UNKNOWN = 256, /* start custom opcodes from the second byte */
	REG,
	IMM,
	SDIV, SMOD,
	SEXT8, SEXT16, SEXT32,
	ZEXT8, ZEXT16, ZEXT32,
	BSWAP16, BSWAP32, BSWAP64,
	/* during the loop body execution the value can be either of param[0] or param[1] */
	ANY,
	/* some value that verifier is not going to track precisely */
	OPAQUE,
	/* '*(u8/16/32 *)(r10 + X) = Y' writes define slot contents only partially */
	SPILL8, SPILL16, SPILL32,
	/*
	 * SCEV expression corresponding to linear equation 'param[0] + param[1] * k',
	 * where k is a loop iteration number. Loop here refers to innermost loop
	 * containing instruction associated with this expression, as returned by
	 * bpf_loop_at_index().
	 */
	LINEAR_SCEV,
};

struct expr {
	u32 op;
	union {
		u32 params[2];
		s64 imm;
	};
};

struct expr_bucket {
	u32 cnt;
	u32 cap;
	u32 ids[];
};

struct env {
	bool empty;
	u32 reg2expr[REGS_NUM];
	u32 reg2scev[REGS_NUM];
};

struct insn_envs {
	u32 cnt;
	struct {
		int loop_header;
		struct env *env;
	} entries[];
};

#define NUM_BUCKETS 256
#define EXPR_STACK_DEPTH 8

struct expr_stack_elt {
	u32 id:28;
	u32 pre:1;
	u32 next_param:2;
};

struct scev {
	/*
	 * Expressions are identified by id, exprs_ht ensures that
         * each expression exists as a unique instance.
	 * This allows for fast equivalence check: id1 === id2.
	 */
	struct expr_bucket *exprs_ht[NUM_BUCKETS]; // Don't want to add struct hlist_node to expr
	struct bpf_min_heap worklist;
	struct insn_envs **envs;
	struct expr *exprs;
	/*
	 * Loops are analyzed one by one, this array keeps track if a particular
	 * instruction was visited on a current pass.
	 */
	u32 *discovered;
	int exprs_cnt;
	int exprs_cap;
	int envs_cnt;
	int stack_sz;
	struct expr_stack_elt expr_stack[EXPR_STACK_DEPTH];
	u32 ids_buf[EXPR_STACK_DEPTH];
};

static u32 expr_hash(struct expr *e)
{
	return jhash_3words(e->op, e->params[0], e->params[1], 0);
}

static int expr_eq(struct expr *a, struct expr *b)
{
	return a->op == b->op && a->imm == b->imm;
}

static int add_expr(struct scev *scev, struct expr e)
{
	struct expr_bucket *bucket;
	u32 i, id, hash, new_cap;
	void *tmp;

	hash = expr_hash(&e) % NUM_BUCKETS;
	bucket = scev->exprs_ht[hash];

	if (bucket) {
		for (i = 0; i < bucket->cnt; i++) {
			id = bucket->ids[i];
			if (expr_eq(&e, &scev->exprs[id]))
				return id;
		}
	}

	if (!bucket || bucket->cap == bucket->cnt) {
		new_cap = bucket ? bucket->cap * 2 : 32;
		bucket = kvrealloc(bucket, sizeof(*bucket) + sizeof(u32) * new_cap, GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!bucket)
			return -ENOMEM;
		scev->exprs_ht[hash] = bucket;
		bucket->cap = new_cap;
	}

	if (scev->exprs_cnt == scev->exprs_cap) {
		new_cap = scev->exprs_cap + 256;
		tmp = kvrealloc(scev->exprs, sizeof(struct expr) * new_cap, GFP_KERNEL_ACCOUNT);
		if (!tmp)
			return -ENOMEM;
		scev->exprs = tmp;
		scev->exprs_cap = new_cap;
	}

	id = scev->exprs_cnt++;
	scev->exprs[id] = e;
	bucket->ids[bucket->cnt++] = id;
	return id;
}

static int expr2(struct scev *scev, u32 op, int a, int b)
{
	if (a < 0)
		return a;
	if (b < 0)
		return b;
	return add_expr(scev, (struct expr){ .op = op, .params = {a, b} });
}

static int expr1(struct scev *scev, u32 op, int a)
{
	if (a < 0)
		return a;
	return expr2(scev, op, a, 0);
}

static int expr0(struct scev *scev, u32 op)
{
	return expr2(scev, op, 0, 0);
}

static bool is_expr1(struct expr *expr, u32 op, int a)
{
	return expr->op == op && expr->params[0] == a;
}

static int imm_expr(struct scev *scev, s64 value)
{
	return add_expr(scev, (struct expr){ .op = IMM, .imm = value });
}

static bool same_exprs(struct scev *scev, int id_a, int id_b)
{
	return id_a == id_b;
}

static bool is_imm(struct scev *scev, int id, s64 *imm)
{
	if (scev->exprs[id].op != IMM)
		return false;
	*imm = scev->exprs[id].imm;
	return true;
}

static bool is_op(struct scev *scev, int id, u32 op)
{
	if (scev->exprs[id].op != op)
		return false;
	return true;
}

static bool is_unop(struct scev *scev, enum expr_op op, int id, u32 *p0)
{
	if (scev->exprs[id].op != op)
		return false;
	*p0 = scev->exprs[id].params[0];
	return true;
}

static bool is_binop(struct scev *scev, enum expr_op op, int id, u32 *p0, u32 *p1)
{
	if (scev->exprs[id].op != op)
		return false;
	*p0 = scev->exprs[id].params[0];
	*p1 = scev->exprs[id].params[1];
	return true;
}

static bool is_reg(struct scev *scev, int id, u32 *reg)
{
	return is_unop(scev, REG, id, reg);
}

static bool is_add(struct scev *scev, int id, u32 *left, u32 *right)
{
	return is_binop(scev, BPF_ADD, id, left, right);
}

static bool is_zext32(struct scev *scev, int id, u32 *left)
{
	return is_unop(scev, ZEXT32, id, left);
}

static bool is_any(struct scev *scev, int id, u32 *left, u32 *right)
{
	return is_binop(scev, ANY, id, left, right);
}

static bool is_linear(struct scev *scev, int id, u32 *base, u32 *slope)
{
	return is_binop(scev, LINEAR_SCEV, id, base, slope);
}

static bool is_opaque(struct scev *scev, int id)
{
	return is_op(scev, id, OPAQUE);
}

static void log_reg(struct bpf_verifier_env *env, u32 reg)
{
	if (reg < MAX_BPF_REG)
		bpf_log(&env->log, "r%d", reg);
	else
		bpf_log(&env->log, "*fp%d", (MAX_BPF_REG - reg - 1) * 8);
}

static const char *op_str(u32 op)
{
	switch (op) {
	case BPF_ADD:  return "+";
	case BPF_SUB:  return "-";
	case BPF_MUL:  return "*";
	case BPF_DIV:  return "/";
	case SDIV:     return "s/";
	case BPF_OR:   return "|";
	case BPF_AND:  return "&";
	case BPF_LSH:  return "<<";
	case BPF_RSH:  return ">>";
	case BPF_NEG:  return "-";
	case BPF_MOD:  return "%";
	case SMOD:     return "s%";
	case BPF_XOR:  return "^";
	case BPF_ARSH: return "s>>";
	case SEXT8:    return "sext8";
	case SEXT16:   return "sext16";
	case SEXT32:   return "sext32";
	case ZEXT8:    return "zext8";
	case ZEXT16:   return "zext16";
	case ZEXT32:   return "zext32";
	case BSWAP16:  return "bswap16";
	case BSWAP32:  return "bswap32";
	case BSWAP64:  return "bswap64";
	case SPILL8:   return "spill8";
	case SPILL16:  return "spill16";
	case SPILL32:  return "spill32";
	case ANY:      return "any";
	case LINEAR_SCEV:  return "linear";
	}
	return NULL;
}

static u32 op_params_num(u32 op)
{
	switch (op) {
	case BPF_ADD:
	case BPF_SUB:
	case BPF_MUL:
	case BPF_DIV:
	case BPF_MOD:
	case BPF_OR:
	case BPF_XOR:
	case BPF_AND:
	case BPF_LSH:
	case BPF_RSH:
	case BPF_ARSH:
	case SDIV:
	case SMOD:
	case ANY:
	case LINEAR_SCEV:
		return 2;
	case BPF_NEG:
	case SEXT8:
	case SEXT16:
	case SEXT32:
	case ZEXT8:
	case ZEXT16:
	case ZEXT32:
	case BSWAP16:
	case BSWAP32:
	case BSWAP64:
	case SPILL8:
	case SPILL16:
	case SPILL32:
		return 1;
	case REG:
	case IMM:
	case OPAQUE:
		return 0;
	default:
		return 0;
	}
}

static bool expr_stack_push(struct scev *scev, u32 id)
{
	if (scev->stack_sz >= EXPR_STACK_DEPTH)
		return false;
	scev->expr_stack[scev->stack_sz].id = id;
	scev->expr_stack[scev->stack_sz].pre = true;
	scev->expr_stack[scev->stack_sz].next_param = 0;
	scev->stack_sz++;
	return true;
}

enum {
	PRE = BIT(1), POST = BIT(2), DEPTH_LIMIT = BIT(3)
};

static bool expr_next(struct scev *scev, u32 *id, u32 *order)
{
	struct expr_stack_elt *elt;
	struct expr *expr;
	u32 num_params;

	if (scev->stack_sz == 0)
		return false;

	elt = &scev->expr_stack[scev->stack_sz - 1];
	*id = elt->id;
	*order = 0;
	expr = &scev->exprs[elt->id];
	num_params = op_params_num(expr->op);
	if (elt->pre) {
		elt->pre = false;
		*order = PRE;
		return true;
	}
	if (elt->next_param == num_params) {
		*order = POST;
		scev->stack_sz--;
		return true;
	}
	if (scev->stack_sz == EXPR_STACK_DEPTH) {
		*order = POST | DEPTH_LIMIT;
		scev->stack_sz--;
		return true;
	}
	expr_stack_push(scev, expr->params[elt->next_param]);
	elt->next_param++;
	return expr_next(scev, id, order);
}

static void log_expr(struct bpf_verifier_env *env, u32 id)
{
	struct bpf_verifier_log *log = &env->log;
	struct scev *scev = env->scev;
	struct expr *expr;
	const char *str;
	u32 order;

	scev->stack_sz = 0;
	expr_stack_push(scev, id);
	while (expr_next(scev, &id, &order)) {
		if ((order & PRE) && scev->stack_sz > 1)
			bpf_log(log, " ");
		expr = &scev->exprs[id];
		switch (expr->op) {
		case UNKNOWN:
			if (order & PRE)
				bpf_log(log, "?");
			break;
		case OPAQUE:
			if (order & PRE)
				bpf_log(log, "_");
			break;
		case REG:
			if (order & PRE)
				log_reg(env, expr->params[0]);
			break;
		case IMM:
			if (order & PRE)
				bpf_log(log, "%lld", expr->imm);
			break;
		default:
			if (order & PRE) {
				str = op_str(expr->op);
				bpf_log(log, "(");
				if (str)
					bpf_log(log, "%s", str);
				else
					bpf_log(log, "bad-expr-op %x", expr->op);
			}
			if (order & DEPTH_LIMIT)
				bpf_log(log, "...");
			if (order & POST)
				bpf_log(log, ")");
		}
	}
}

enum print_env_flags {
	PRINT_SCEV = BIT(1)
};

static bool reg_alive_at(struct bpf_verifier_env *env, u32 reg, u32 insn_idx)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	u16 live_regs = aux[insn_idx].live_regs_before;

	return reg < MAX_BPF_REG
	       ? (BIT(reg) & live_regs)
	       : test_bit(reg - MAX_BPF_REG, aux[insn_idx].live_stack_before);
}

static void print_env(struct bpf_verifier_env *env, struct env *e, u32 insn_idx, u32 flags)
{
	struct bpf_verifier_log *log = &env->log;
	struct scev *scev = env->scev;
	bool printed_some = false;
	bool print_scev = flags & PRINT_SCEV;
	bool is_self_scev;
	bool is_self_reg;
	int i, r;

	if (e->empty) {
		bpf_log(log, "  <empty>\n");
		return;
	}

	for (i = 0; i < REGS_NUM; i++) {
		if (!reg_alive_at(env, i, insn_idx))
			continue;
		is_self_reg = is_reg(scev, e->reg2expr[i], &r) && i == r;
		is_self_scev = is_reg(scev, e->reg2scev[i], &r) && i == r;
		if (is_self_reg && (!print_scev || is_self_scev))
			continue;
		printed_some = true;
		bpf_log(log, "  ");
		log_reg(env, i);
		bpf_log(log, "=");
		log_expr(env, e->reg2expr[i]);
		if (print_scev && e->reg2expr[i] != UNKNOWN_EXPR_ID) {
			bpf_log(log, " / ");
			log_expr(env, e->reg2scev[i]);
		}
		bpf_log(log, "\n");
	}
	if (!printed_some)
		bpf_log(log, "  <all regs unchanged>\n");
}
static struct env *find_loop_env(struct scev *scev, int loop_header, int insn_idx)
{
	struct insn_envs *envs = scev->envs[insn_idx];
	u32 i;

	if (!envs)
		return NULL;
	for (i = 0; i < envs->cnt; i++)
		if (envs->entries[i].loop_header == loop_header)
			return envs->entries[i].env;
	return NULL;
}

static struct env *find_header_env(struct scev *scev, int header)
{
	return find_loop_env(scev, header, header);
}

static struct env *get_loop_env(struct scev *scev, int loop_header, int insn_idx)
{
	struct insn_envs *envs = scev->envs[insn_idx];
	u32 cnt = envs ? envs->cnt : 0;
	struct insn_envs *tmp;
	struct env *e;

	e = find_loop_env(scev, loop_header, insn_idx);
	if (e)
		return e;

	e = kzalloc(sizeof(*e), GFP_KERNEL_ACCOUNT);
	if (!e)
		return NULL;

	tmp = krealloc(envs, struct_size(envs, entries, cnt + 1), GFP_KERNEL_ACCOUNT);
	if (!tmp) {
		kfree(e);
		return NULL;
	}

	e->empty = true;
	tmp->entries[cnt].loop_header = loop_header;
	tmp->entries[cnt].env = e;
	tmp->cnt = cnt + 1;
	scev->envs[insn_idx] = tmp;
	return e;
}

static void setup_initial_loop_env(struct bpf_verifier_env *env, struct env *e, int insn_idx)
{
	struct scev *scev = env->scev;
	int i;

	for (i = 0; i < REGS_NUM; i++)
		e->reg2expr[i] = expr1(scev, REG, i);
}

static int replace_reg(struct scev *scev, struct env *e, u32 reg, int id)
{
	if (id < 0)
		return id;
	e->reg2expr[reg] = id;
	return 0;
}

static void forget_call_regs(struct env *e)
{
	int i;

	for (i = BPF_REG_0; i <= BPF_REG_5; i++)
		e->reg2expr[i] = UNKNOWN_EXPR_ID;
}

static u32 spill_spi(struct bpf_insn *insn)
{
	return -insn->off / BPF_REG_SIZE - 1;
}

static u32 off_to_reg(struct bpf_insn *insn)
{
	return spill_spi(insn) + MAX_BPF_REG;
}

static bool is_spill_off(int off)
{
	return off % BPF_REG_SIZE == 0 &&
	       off <= -BPF_REG_SIZE &&
	       off >= -MAX_BPF_STACK_JIT;
}

static void mark_opaque(struct env *e, int off, int size)
{
	int b, spi;

	for (b = off; b < off + size; b++) {
		if (b >= 0 || b < -MAX_BPF_STACK_JIT)
			continue;
		spi = (-b - 1) / BPF_REG_SIZE;
		e->reg2expr[MAX_BPF_REG + spi] = OPAQUE_EXPR_ID;
	}
}

static int mk_spill(struct scev *scev, u8 size, int id)
{
	switch (size) {
	case BPF_B:  return expr1(scev, SPILL8,  id);
	case BPF_H:  return expr1(scev, SPILL16, id);
	case BPF_W:  return expr1(scev, SPILL32, id);
	case BPF_DW: return id;
	}
	return UNKNOWN_EXPR_ID;
}

static int mk_fill(struct scev *scev, int id, u8 code)
{
	bool sx = BPF_MODE(code) == BPF_MEMSX;

	switch (BPF_SIZE(code)) {
	case BPF_B:  return expr1(scev, sx ? SEXT8  : ZEXT8,  id);
	case BPF_H:  return expr1(scev, sx ? SEXT16 : ZEXT16, id);
	case BPF_W:  return expr1(scev, sx ? SEXT32 : ZEXT32, id);
	case BPF_DW: return sx ? UNKNOWN_EXPR_ID : id; /* DW sign-extended load is invalid */
	}
	return UNKNOWN_EXPR_ID;
}

static int maybe_store_fp(struct scev *scev, struct env *e, struct bpf_insn *insn, int id)
{
	u8 size = BPF_SIZE(insn->code);

	if (insn->dst_reg != BPF_REG_FP)
		return 0;
	if (is_spill_off(insn->off))
		return replace_reg(scev, e, off_to_reg(insn), mk_spill(scev, size, id));
	mark_opaque(e, insn->off, bpf_size_to_bytes(size));
	return 0;
}

static int maybe_load_fp(struct scev *scev, struct env *e, struct bpf_insn *insn)
{
	int id;

	if (insn->src_reg == BPF_REG_FP && is_spill_off(insn->off))
		id = mk_fill(scev, e->reg2expr[off_to_reg(insn)], insn->code);
	else
		id = OPAQUE_EXPR_ID;
	return replace_reg(scev, e, insn->dst_reg, id);
}

static int transfer(struct bpf_verifier_env *env, struct env *e, int idx)
{
	const bool little_endian = htons(0x3412) == 0x1234;
	struct bpf_insn *insn = &env->prog->insnsi[idx];
	struct scev *scev = env->scev;
	u32 *reg2expr = e->reg2expr;
	u8 class = BPF_CLASS(insn->code);
	u8 x_or_k = BPF_SRC(insn->code);
	u8 opcode = BPF_OP(insn->code);
	u8 mode = BPF_MODE(insn->code);
	u32 dst = insn->dst_reg;
	u32 src = insn->src_reg;
	u32 op, sext;
	int i, id;
	s64 imm;

	switch (class) {
	case BPF_ALU:
	case BPF_ALU64:
		switch (opcode) {
		case BPF_MOV:
			switch (insn->off) {
			case 0: sext = 0; break;
			case 8: sext = SEXT8; break;
			case 16: sext = SEXT16; break;
			case 32: sext = SEXT32; break;
			default:
				goto mark_dst_unknown;
			}

			if (x_or_k == BPF_X && insn->imm == 0)
				id = reg2expr[src];
			else if (x_or_k == BPF_K && src == 0 && insn->off == 0)
				id = imm_expr(scev, insn->imm);
			else
				goto mark_dst_unknown;

			if (sext)
				id = expr1(scev, sext, id);
			if (class == BPF_ALU)
				id = expr1(scev, ZEXT32, id);

			return replace_reg(scev, e, dst, id);

		case BPF_ADD:
		case BPF_SUB:
		case BPF_MUL:
		case BPF_DIV:
		case BPF_MOD:
		case BPF_OR:
		case BPF_XOR:
		case BPF_AND:
		case BPF_LSH:
		case BPF_RSH:
		case BPF_ARSH:
			if (opcode == BPF_DIV && insn->off == 1)
				op = SDIV;
			else if (opcode == BPF_MOD && insn->off == 1)
				op = SMOD;
			else if (insn->off == 0)
				op = opcode;
			else
				goto mark_dst_unknown;

			if (x_or_k == BPF_X && insn->imm == 0)
				id = reg2expr[src];
			else if (x_or_k == BPF_K && src == 0)
				id = imm_expr(scev, insn->imm);
			else
				goto mark_dst_unknown;

			id = expr2(scev, op, reg2expr[dst], id);

			if (class == BPF_ALU)
				id = expr1(scev, ZEXT32, id);

			return replace_reg(scev, e, dst, id);

		case BPF_NEG:
			if (src == 0 && insn->off == 0 && insn->imm == 0)
				id = expr1(scev, BPF_NEG, reg2expr[dst]);
			else
				goto mark_dst_unknown;

			if (class == BPF_ALU)
				id = expr1(scev, ZEXT32, id);

			return replace_reg(scev, e, dst, id);

		case BPF_END:
			switch (insn->imm) {
			case 16: op = BSWAP16; break;
			case 32: op = BSWAP32; break;
			case 64: op = BSWAP64; break;
			default:
				goto mark_dst_unknown;
			}

			if (class == BPF_ALU && x_or_k == BPF_TO_LE && insn->off == 0 && little_endian)
				op = 0; /* little-endian to little-endian is noop */
			else if (class == BPF_ALU && x_or_k == BPF_TO_BE && insn->off == 0 && !little_endian)
				op = 0; /* big-endian to big-endian is noop */
			else if (class == BPF_ALU64 && x_or_k == 0 && insn->off == 0)
				/* always swap */;
			else
				goto mark_dst_unknown;

			id = reg2expr[dst];
			if (op)
				id = expr1(scev, op, reg2expr[dst]);

			if (class == BPF_ALU)
				id = expr1(scev, ZEXT32, id);

			return replace_reg(scev, e, dst, id);
		default:
			goto mark_dst_unknown;
		}
		break;
	case BPF_LDX:
		switch (mode) {
		case BPF_MEM:
		case BPF_MEMSX:
			return maybe_load_fp(scev, e, insn);
		default:
			goto mark_dst_unknown;
		}
	case BPF_STX:
		switch (mode) {
		case BPF_MEM:
			return maybe_store_fp(scev, e, insn, reg2expr[src]);
		case BPF_ATOMIC:
			if (insn->imm == BPF_LOAD_ACQ)
				return maybe_load_fp(scev, e, insn);
			if (insn->imm == BPF_STORE_REL) {
				return maybe_store_fp(scev, e, insn, reg2expr[src]);
			}
			/*
			 * verifier does not track other atomic ops precisely,
			 * hence mark the results as opaque.
			 */
			if (insn->dst_reg == BPF_REG_FP)
				mark_opaque(e, insn->off, bpf_size_to_bytes(BPF_SIZE(insn->code)));
			if (insn->imm == BPF_CMPXCHG)
				return replace_reg(scev, e, BPF_REG_0, OPAQUE_EXPR_ID);
			if (insn->imm & BPF_FETCH)
				return replace_reg(scev, e, src, OPAQUE_EXPR_ID);
			break;
		}
		break;
	case BPF_ST:
		if (insn->dst_reg == BPF_REG_FP) {
			id = imm_expr(scev, insn->imm);
			if (id < 0)
				return id;
			return maybe_store_fp(scev, e, insn, id);
		}
		break;
	case BPF_JMP:
	case BPF_JMP32:
		if (opcode == BPF_CALL)
			forget_call_regs(e);
		/* for non-CALL there are no changes in register states */
		break;
	case BPF_LD:
		switch (mode) {
		case BPF_IMM:
			/* rX = imm ll */
			if (BPF_SIZE(insn->code) == BPF_DW && insn->src_reg == 0) {
				imm = ((u64)(insn + 1)->imm << 32) | (u32)insn->imm;
				return replace_reg(scev, e, dst, imm_expr(scev, imm));
			}
			/* map, map value, BTF id, function */
			if (BPF_SIZE(insn->code) == BPF_DW)
				return replace_reg(scev, e, dst, OPAQUE_EXPR_ID);
			goto mark_dst_unknown;
		case BPF_ABS:
		case BPF_IND:
			forget_call_regs(e);
			break;
		default:
			goto mark_dst_unknown;
		}
		break;
	default:
		/* unknown instruction, nuke state */
		for (i = 0; i < REGS_NUM; i++)
			reg2expr[i] = UNKNOWN_EXPR_ID;
		break;
	}
	return 0;

mark_dst_unknown:
	reg2expr[dst] = UNKNOWN_EXPR_ID;
	return 0;
}

/*
 * Construct minimal 'ANY' expression by traversing 'a' and 'b'
 * and accumulating non-duplicated non-ANY entries.
 */
static int mk_any(struct scev *scev, u32 a, u32 b)
{
	struct expr_stack_elt *elt;
	struct expr *expr;
	u32 i, j, ids_buf_sz;
	u32 roots[2] = {a, b};
	int id;

	ids_buf_sz = 0;
	for (i = 0; i < ARRAY_SIZE(roots); i++) {
		scev->stack_sz = 0;
		expr_stack_push(scev, roots[i]);
		while (scev->stack_sz) {
			elt = &scev->expr_stack[--scev->stack_sz];
			id = elt->id;
			expr = &scev->exprs[elt->id];
			if (expr->op == ANY) {
				if (!expr_stack_push(scev, expr->params[0]) ||
				    !expr_stack_push(scev, expr->params[1]))
					return UNKNOWN_EXPR_ID;
			} else {
				for (j = 0; j < ids_buf_sz; j++) {
					if (same_exprs(scev, scev->ids_buf[j], id))
						goto next;
				}
				if (ids_buf_sz == ARRAY_SIZE(scev->ids_buf))
					return UNKNOWN_EXPR_ID;
				scev->ids_buf[ids_buf_sz++] = id;
			}
next:;
		}
	}
	if (WARN_ON(ids_buf_sz == 0))
		return -EFAULT;
	id = scev->ids_buf[0];
	for (i = 1; i < ids_buf_sz; i++) {
		id = expr2(scev, ANY, id, scev->ids_buf[i]);
		if (id < 0)
			return id;
	}
	return id;
}

static int join(struct scev *scev, struct env *acc, struct env *cur)
{
	int i, id;

	if (acc->empty) {
		memcpy(acc, cur, sizeof(*acc));
		acc->empty = false;
		return 0;
	}

	for (i = 0; i < REGS_NUM; i++) {
		if (!same_exprs(scev, acc->reg2expr[i], cur->reg2expr[i])) {
			id = mk_any(scev, acc->reg2expr[i], cur->reg2expr[i]);
			if (id < 0)
				return id;
			acc->reg2expr[i] = id;
		}
	}
	return 0;
}

/* Mark any register modified in 'header_env' as unknown in 'acc'. */
static void forget_non_invariants(struct scev *scev, struct env *acc, struct env *header_env)
{
	struct expr *header_expr;
	int i;

	if (acc->empty)
		acc->empty = false;

	for (i = 0; i < REGS_NUM; i++) {
		header_expr = &scev->exprs[header_env->reg2expr[i]];
		if (is_expr1(header_expr, REG, i))
			continue;
		acc->reg2expr[i] = UNKNOWN_EXPR_ID;
	}
}

static int worklist_push(struct scev *scev, int loop_header, int idx)
{
	u32 tag = (u32)loop_header + 1;
	int err;

	if (scev->discovered[idx] == tag)
		return 0;

	err = bpf_min_heap_push(&scev->worklist, idx);
	if (err)
		return err;

	scev->discovered[idx] = tag;
	return 0;
}

static bool reg_alive_at_succ(struct bpf_verifier_env *env, u32 r, u32 insn_idx)
{
	struct bpf_iarray *succ = bpf_insn_successors(env, insn_idx);
	u32 i;

	for (i = 0; i < succ->cnt; i++)
		if (reg_alive_at(env, r, succ->items[i]))
			return true;
	return false;
}

enum changes_at {
	LOG_AT_TRANSFER,
	LOG_AT_JOIN,
};

static void log_env_changes(struct bpf_verifier_env *env, enum changes_at at,
			    struct env *old, struct env *new, int insn_idx)
{
	struct bpf_verifier_log *log = &env->log;
	struct scev *scev = env->scev;
	u64 null_pos = log->end_pos;
	bool any_changes = false;
	u32 old_id, new_id;
	u64 len;
	int r;

	bpf_log(log, "%s %4d: ", at == LOG_AT_TRANSFER ? "t" : "j", insn_idx);
	bpf_verbose_insn(env, &env->prog->insnsi[insn_idx]);
	len = log->end_pos - null_pos;
	bpf_log(log, "%*s", max(37 - (int)len, 1), " ");
	bpf_log(log, " ; ");
	for (r = 0; r < REGS_NUM; r++) {
		old_id = old->reg2expr[r];
		new_id = new->reg2expr[r];
		if (at == LOG_AT_TRANSFER && !reg_alive_at_succ(env, r, insn_idx))
			continue;
		if (at == LOG_AT_JOIN && !reg_alive_at(env, r, insn_idx))
			continue;
		if (same_exprs(scev, old_id, new_id))
			continue;
		if (any_changes)
			bpf_log(log, ", ");
		log_reg(env, r);
		bpf_log(log, " ");
		log_expr(env, old_id);
		bpf_log(log, " -> ");
		log_expr(env, new_id);
		any_changes = true;
	}
	bpf_log(log, "\n");
	if (!any_changes)
		bpf_vlog_reset(log, null_pos);
}

static bool is_probe_read_helper(u32 func_id)
{
	return func_id == BPF_FUNC_probe_read ||
	       func_id == BPF_FUNC_probe_read_kernel ||
	       func_id == BPF_FUNC_probe_read_user ||
	       func_id == BPF_FUNC_probe_read_str ||
	       func_id == BPF_FUNC_probe_read_kernel_str ||
	       func_id == BPF_FUNC_probe_read_user_str;
}

/*
 * If instruction is an indirect write to stack, invalidate SCEVs for spi's
 * that this instruction can touch.
 */
static void reset_scevs_at_indirect_writes(struct bpf_verifier_env *env, struct env *cur_env, int idx)
{
	struct bpf_insn *insn = &env->prog->insnsi[idx];
	struct scev *scev = env->scev;
	u8 class = BPF_CLASS(insn->code);
	const unsigned long *mask;
	u32 spi, reg;
	bool opaque;

	/* Direct fp stores are fine. */
	if ((class == BPF_ST || class == BPF_STX) && insn->dst_reg == BPF_REG_FP)
		return;

	mask = bpf_may_write_mask(env, idx);
	opaque = bpf_helper_call(insn) && is_probe_read_helper(insn->imm);
	for_each_set_bit(spi, mask, MAX_BPF_STACK_SLOTS) {
		reg = MAX_BPF_REG + spi;
		if (cur_env->reg2expr[reg] == UNKNOWN_EXPR_ID)
			continue;
		replace_reg(scev, cur_env, reg, opaque ? OPAQUE_EXPR_ID : UNKNOWN_EXPR_ID);
	}
}

/* OR the loop-entry registers referenced by expr 'id' into 'mask'. */
static void or_expr_regs(struct bpf_verifier_env *env, u32 id, unsigned long *mask)
{
	struct scev *scev = env->scev;
	u32 order;

	scev->stack_sz = 0;
	expr_stack_push(scev, id);
	while (expr_next(scev, &id, &order)) {
		if ((order & PRE) && scev->exprs[id].op == REG)
			__set_bit(scev->exprs[id].params[0], mask);
	}
}

/* Mask of argument registers (R1..R5) a call at 'idx' passes by register. */
static u16 call_params_mask(struct bpf_verifier_env *env, int idx)
{
	struct bpf_insn *insn = &env->prog->insnsi[idx];
	struct bpf_call_summary cs;
	int n = bpf_get_call_summary(env, insn, &cs) ? cs.arg_slot_cnt : MAX_BPF_FUNC_REG_ARGS;

	return n ? GENMASK(BPF_REG_1 + n - 1, BPF_REG_1) : 0;
}

/*
 * For instructions like:
 * - *(u64 *)(rBase + off) = rX
 * - rX = *(u64 *)(rBase + off)
 * - calls that construct objects on stack (e.g. dynptr_from_mem(rBase, ...))
 * When 'rBase' can be a stack pointer and is derived from some registers Rs
 * defined at loop entry, record Rs into 'mask'.
 */
static void collect_store_base_regs(struct bpf_verifier_env *env,
				    struct env *cur_env, int idx, unsigned long *mask)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_insn *insn = &env->prog->insnsi[idx];
	u8 class = BPF_CLASS(insn->code);
	u8 size = BPF_SIZE(insn->code);
	u16 base_regs = 0;
	u32 r;

	if (size == BPF_W || size == BPF_DW) {
		if ((class == BPF_STX || class == BPF_ST) && insn->dst_reg != BPF_REG_FP)
			base_regs |= BIT(insn->dst_reg);
		else if (class == BPF_LDX && insn->src_reg != BPF_REG_FP)
			base_regs |= BIT(insn->src_reg);
	}

	if (class == BPF_JMP && BPF_OP(insn->code) == BPF_CALL &&
	    bpf_needs_fixed_stack_off(env, idx))
		base_regs |= call_params_mask(env, idx);

	base_regs &= aux[idx].stack_ptrs;
	for (r = 0; r < MAX_BPF_REG; r++)
		if (base_regs & BIT(r))
			or_expr_regs(env, cur_env->reg2expr[r], mask);
}

/* Find the topmost loop header containing idx inside cur_header, or -1 if none. */
static int topmost_nested_loop(struct bpf_verifier_env *env, int idx, int cur_header)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int header;

	for (header = bpf_loop_at_index(env, idx); header >= 0;
	     header = aux[header].loop_header)
		if (aux[header].loop_header == cur_header)
			return header;

	return -1;
}

/*
 * Join cur_env into the successor's environment and schedule their traversal.
 * Map successors in nested loops to their topmost nested header.
 * Ignore successors outside the current loop and its nested loops.
 */
static int join_successor(struct bpf_verifier_env *env, int cur_header, int succ_idx,
			  struct env *old_env, struct env *cur_env)
{
	bool log_level2 = env->log.level & BPF_LOG_LEVEL2;
	struct scev *scev = env->scev;
	int err, nested_header;
	struct env *succ_env;

	/*
	 * There are several possibilities for a successor:
	 * - succ_idx can be a part of a loop outside of the cur_header's loop,
	 *   such edges are ignored.
	 * - succ_idx can be a part of the same loop as cur_header,
	 *   for such edges succ_idx environment is updated:
	 *     e[succ_idx] = join(e[succ_idx], cur_env)
	 * - succ_idx can be a part of some loop inner to cur_header,
	 *   in such a case there exists some loop header H,
	 *   such that H.loop_header == cur_header
	 *   and H is the same as succ_idx's loop or contains it.
	 */
	if (bpf_loop_at_index(env, succ_idx) != cur_header) {
		/*
		 * topmost_nested_loop() either finds H or returns -1,
		 * in case if succ_idx is a part of a loop outer to cur_header.
		 */
		nested_header = topmost_nested_loop(env, succ_idx, cur_header);
		if (nested_header < 0)
			return 0;
		succ_idx = nested_header;
	}
	succ_env = get_loop_env(scev, cur_header, succ_idx);
	if (!succ_env)
		return -ENOMEM;
	if (log_level2)
		memcpy(old_env, succ_env, sizeof(*old_env));
	err = join(scev, succ_env, cur_env);
	if (err)
		return err;
	err = worklist_push(scev, cur_header, succ_idx);
	if (err)
		return err;
	if (log_level2)
		log_env_changes(env, LOG_AT_JOIN, old_env, succ_env, succ_idx);
	return 0;
}

static int compute_scev_for_loop(struct bpf_verifier_env *env, int cur_header)
{
	struct bpf_min_heap *worklist = &env->scev->worklist;
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_loop *cur_loop = aux[cur_header].loop;
	struct env *header_env, *nested_header_env;
	struct scev *scev = env->scev;
	struct bpf_loop *nested_loop;
	struct env *cur_env = NULL;
	struct env *old_env = NULL;
	struct bpf_iarray *succ;
	bool log_level2 = env->log.level & BPF_LOG_LEVEL2;
	int s, i, err, idx, succ_idx;
	u32 r;

	if (log_level2)
		bpf_log(&env->log, "Computing SCEV for loop at %d:\n", cur_header);

	/*
	 * For irreducible loops, and for loops nesting a loop with a truncated
	 * exit list, just assume that everything is clobbered for now.
	 */
	if (cur_loop->irreducible || cur_loop->exits_overflow) {
		header_env = get_loop_env(scev, cur_header, cur_header);
		if (!header_env)
			return -ENOMEM;
		/* The freshly allocated environment has all expressions unknown. */
		bitmap_fill(cur_loop->store_base_regs, REGS_NUM);
		header_env->empty = false;
		return 0;
	}

	cur_env = kzalloc(sizeof(*cur_env), GFP_KERNEL_ACCOUNT);
	if (!cur_env)
		goto nomem;
	if (log_level2) {
		old_env = kzalloc(sizeof(*old_env), GFP_KERNEL_ACCOUNT);
		if (!old_env)
			goto nomem;
	}
	header_env = get_loop_env(scev, cur_header, cur_header);
	if (!header_env)
		goto nomem;
	setup_initial_loop_env(env, header_env, cur_header);
	err = worklist_push(scev, cur_header, cur_header);
	if (err)
		goto out;

	for (;;) {
		if (!bpf_min_heap_pop(worklist, &idx))
			break;

		/* join_successor() maps nested-loop entries to their representative header. */
		nested_loop = idx != cur_header ? aux[idx].loop : NULL;
		memcpy(cur_env, find_loop_env(scev, cur_header, idx), sizeof(*cur_env));
		if (nested_loop) {
			/*
			 * Process nested loop as a single instruction by
			 * forgetting anything non-invariant in the nested loop
			 */
			if (log_level2)
				memcpy(old_env, cur_env, sizeof(*old_env));
			/* Pull the nested loop's stack-store base dependencies up. */
			for_each_set_bit(r, nested_loop->store_base_regs, BPF_SCEV_REGS_NUM)
				or_expr_regs(env, cur_env->reg2expr[r], cur_loop->store_base_regs);
			nested_header_env = find_header_env(scev, idx);
			forget_non_invariants(scev, cur_env, nested_header_env);
			if (log_level2)
				log_env_changes(env, LOG_AT_TRANSFER, old_env, cur_env, idx);
			/*
			 * Treat nested loop exits as successors,
			 * join cur_env into successor's envs.
			 */
			for (i = 0; i < nested_loop->exits_cnt; i++) {
				s = nested_loop->exits[i].to;
				err = join_successor(env, cur_header, s, old_env, cur_env);
				if (err)
					goto out;
			}
		} else {
			/*
			 * Iterate instructions within a single basic block
			 * starting at 'idx' mutating 'cur_env'.
			 */
			for (;;) {
				if (log_level2)
					memcpy(old_env, cur_env, sizeof(*old_env));
				collect_store_base_regs(env, cur_env, idx, cur_loop->store_base_regs);
				err = transfer(env, cur_env, idx);
				if (err)
					goto out;
				reset_scevs_at_indirect_writes(env, cur_env, idx);
				if (log_level2)
					log_env_changes(env, LOG_AT_TRANSFER, old_env, cur_env, idx);
				succ = bpf_insn_successors(env, idx);
				if (succ->cnt != 1)
					break;
				succ_idx = succ->items[0];
				if (aux[idx].bb_end || aux[succ_idx].need_scev ||
				    bpf_loop_at_index(env, succ_idx) != cur_header)
					break;
				idx = succ_idx;
			}
			/* Join cur_env into basic block successor's envs. */
			iarray_for_each(s, succ) {
				err = join_successor(env, cur_header, s, old_env, cur_env);
				if (err)
					goto out;
			}
		}
	}

	err = 0;
out:
	kfree(cur_env);
	kfree(old_env);
	return err;
nomem:
	err = -ENOMEM;
	goto out;
}

static void mark_latches(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_loop *loop;
	int len = env->prog->len;
	int i, j, latch;

	for (i = 0; i < len; i++) {
		loop = aux[i].loop;
		if (!loop)
			continue;
		aux[i].need_scev = true;
		if (loop->irreducible)
			continue;
		for (j = 0; j < loop->backedges_cnt; j++) {
			latch = loop->backedges[j].latch;
			if (latch >= 0)
				aux[latch].need_scev = true;
		}
	}
}

static bool is_any_imm_reg_opaque(struct scev *scev, u32 id)
{
	u32 l, r, reg, order;
	s64 imm;

	scev->stack_sz = 0;
	expr_stack_push(scev, id);
	while (expr_next(scev, &id, &order)) {
		if (order & DEPTH_LIMIT)
			return false;
		if (!(order & PRE) ||
		    is_imm(scev, id, &imm) ||
		    is_reg(scev, id, &reg) ||
		    is_opaque(scev, id) ||
		    is_any(scev, id, &l, &r))
			continue;
		return false;
	}
	return true;
}

/*
 * Can implement explicit stack version, but it is harder to read.
 * Stick with recursive version for now.
 */
static int transform_expr_once(struct scev *scev, u32 lvl, u32 root, void *priv,
                               int (*fn)(struct scev *scev, u32 id, void *priv))
{
	struct expr expr;
	int p0, p1, id;

	if (lvl >= EXPR_STACK_DEPTH)
		return UNKNOWN_EXPR_ID;

        expr = scev->exprs[root]; /* snapshot the expr before potential realloc */
	switch (op_params_num(expr.op)) {
	case 0:
		id = root;
		break;
	case 1:
		p0 = transform_expr_once(scev, lvl + 1, expr.params[0], priv, fn);
		id = expr1(scev, expr.op, p0);
		break;
	case 2:
		p0 = transform_expr_once(scev, lvl + 1, expr.params[0], priv, fn);
		p1 = transform_expr_once(scev, lvl + 1, expr.params[1], priv, fn);
		id = expr2(scev, expr.op, p0, p1);
		break;
	}
	return id < 0 ? id : fn(scev, id, priv);
}

static int transform_expr(struct scev *scev, u32 root, void *priv,
                          int (*fn)(struct scev *scev, u32 id, void *priv))
{
	int id_old, id_new = root;

	do {
		id_old = id_new;
		id_new = transform_expr_once(scev, 0, id_old, priv, fn);
		if (id_new < 0)
			return id_new;
	} while (id_old != id_new);
	return id_new;
}

static int simplify(struct scev *scev, u32 id, void *priv)
{
	u32 l, r, base, slope;
	s64 imm1, imm2;

	/* (+ (linear base slope) imm) -> (linear (+ base imm) slope) */
	if (is_add(scev, id, &l, &r) &&
	    is_linear(scev, l, &base, &slope) &&
	    is_imm(scev, r, &imm1))
		return expr2(scev, LINEAR_SCEV, expr2(scev, BPF_ADD, base, r), slope);

	/* (+ imm imm) -> imm */
	if (is_add(scev, id, &l, &r) &&
	    is_imm(scev, l, &imm1) &&
	    is_imm(scev, r, &imm2))
		return imm_expr(scev, imm1 + imm2);

	if (is_zext32(scev, id, &l) && is_imm(scev, l, &imm1))
		return imm_expr(scev, (u64)(u32)imm1);

	return id;
}

static int compute_header_scevs(struct bpf_verifier_env *env, struct env *header_env)
{
	struct scev *scev = env->scev;
	u32 ra, rb, l, r, ra_expr;
	s64 imm;
	int id;

	for (ra = 0; ra < REGS_NUM; ra++) {
		id = transform_expr(scev, header_env->reg2expr[ra], NULL, simplify);
		if (id < 0)
			return id;
		header_env->reg2expr[ra] = id;
		ra_expr = header_env->reg2expr[ra];
		/* rA = (+ rA IMM) */
		if (is_add(scev, ra_expr, &l, &r) &&
		    is_reg(scev, l, &rb) &&
		    is_imm(scev, r, &imm) &&
		    ra == rb) {
			id = expr2(scev, LINEAR_SCEV, l, r);
			if (id < 0)
				return id;
			header_env->reg2scev[ra] = id;
			continue;
		}
		/* rA = rA */
		if (is_reg(scev, ra_expr, &rb) && ra == rb) {
			header_env->reg2scev[ra] = ra_expr;
			continue;
		}
		/* rA = (any 1 2 3 4 ...) */
		if (is_any_imm_reg_opaque(scev, ra_expr)) {
			header_env->reg2scev[ra] = ra_expr;
			continue;
		}

	}
	return 0;
}
static int instantiate_header_scevs(struct scev *scev, u32 id, void *priv)
{
	u32 reg, base, slope, *reg2scev = priv;

	/* (reg r) -> (linear ...), where r is a LINEAR_SCEV in the header */
	if (is_reg(scev, id, &reg) &&
	    is_linear(scev, reg2scev[reg], &base, &slope))
		return reg2scev[reg];
	return id;
}

static int compute_insn_scevs(struct bpf_verifier_env *env, struct env *eheader, struct env *einsn)
{
	struct scev *scev = env->scev;
	int id, reg;

	for (reg = 0; reg < REGS_NUM; reg++) {
		id = einsn->reg2expr[reg];
		id = transform_expr_once(scev, 0, id, eheader->reg2scev, instantiate_header_scevs);
		if (id < 0)
			return id;
		id = transform_expr(scev, id, NULL, simplify);
		if (id < 0)
			return id;
		einsn->reg2scev[reg] = id;
	}

	return 0;
}

static void log_scevs(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_verifier_log *log = &env->log;
	struct scev *scev = env->scev;
	struct bpf_loop *loop;
	int i, j, len, latch;

	len = env->prog->len;
	for (i = 0; i < len; i++) {
		loop = aux[i].loop;
		if (!loop)
			continue;
		bpf_log(log, "scev at header %d:\n", i);
		print_env(env, find_header_env(scev, i), i, PRINT_SCEV);
		if (loop->irreducible)
			continue;
		for (j = 0; j < loop->backedges_cnt; j++) {
			latch = loop->backedges[j].latch;
			if (latch < 0)
				continue;
			bpf_log(log, " scev at latch %d:\n", latch);
			print_env(env, find_loop_env(scev, bpf_loop_at_index(env, latch), latch),
				  latch, PRINT_SCEV);
		}
	}
}

int bpf_compute_scev(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct scev *scev = env->scev;
	int *postorder = env->cfg.insn_postorder;
	int cnt = env->cfg.cur_postorder;
	int i, idx, err, header;

	mark_latches(env);
	/*
	 * Visit loop headers in postorder, to guarantee that scevs
         * for innermost loops are computed first.
	 */
	for (i = 0; i < cnt; i++) {
		idx = postorder[i];
		if (!aux[idx].loop)
			continue;
		err = compute_scev_for_loop(env, idx);
		if (err)
			return err;
	}

	/*
	 * Compute scevs from exprs collected on a previous step. Iterate instructions in
	 * reverse post-order so that each loop header is processed before instructions
	 * reachable from it.
	 */
	for (i = cnt - 1; i >= 0; i--) {
		idx = postorder[i];
		if (!aux[idx].need_scev)
			continue;
		header = bpf_loop_at_index(env, idx);
		err = aux[idx].loop
		      ? compute_header_scevs(env, find_header_env(scev, header))
		      : compute_insn_scevs(env, find_header_env(scev, header),
				   find_loop_env(scev, header, idx));
		if (err)
			return err;
	}

	for (i = 0; i < env->prog->len; i++)
		if (aux[i].loop)
			aux[i].prune_point = true;

	if (env->log.level & BPF_LOG_LEVEL2)
		log_scevs(env);

	return 0;
}

static int reverse_ranked_compare(int a, int b, void *arg)
{
	int *rank = arg;

	return rank[b] - rank[a];
}

void bpf_free_scev(struct bpf_verifier_env *env)
{
	struct scev *scev = env->scev;
	struct insn_envs *envs;
	int i;
	u32 j;

	if (!scev)
		return;
	for (i = 0; i < scev->envs_cnt; i++) {
		envs = scev->envs[i];
		if (!envs)
			continue;
		for (j = 0; j < envs->cnt; j++)
			kfree(envs->entries[j].env);
		kfree(envs);
	}
	for (i = 0; i < ARRAY_SIZE(scev->exprs_ht); i++)
		kvfree(scev->exprs_ht[i]);
	bpf_min_heap_free(&scev->worklist);
	kvfree(scev->envs);
	kvfree(scev->exprs);
	kvfree(scev->discovered);
	kfree(scev);
	env->scev = NULL;
}

int bpf_init_scev(struct bpf_verifier_env *env)
{
	struct scev *scev;

	scev = kzalloc(sizeof(struct scev), GFP_KERNEL_ACCOUNT);
	if (!scev)
		return -ENOMEM;
	env->scev = scev;
	bpf_mark_reg_not_init(env, &env->scev_not_init_reg);
	/* Order worklist in reverse post-order. */
	bpf_min_heap_init(&scev->worklist, reverse_ranked_compare, env->cfg.postorder_nums);
	if (expr0(scev, UNKNOWN) < 0 || expr0(scev, OPAQUE)  < 0)
		goto nomem;
	scev->envs = kvcalloc(env->prog->len, sizeof(*scev->envs), GFP_KERNEL_ACCOUNT);
	scev->discovered = kvcalloc(env->prog->len, sizeof(*scev->discovered), GFP_KERNEL_ACCOUNT);
	if (!scev->envs || !scev->discovered)
		goto nomem;
	/*
	 * Remember original program length, in case bpf_free_scev()
         * is called after bpf program rewrites that increase program
         * length.
	 */
	scev->envs_cnt = env->prog->len;
	return 0;
nomem:
	bpf_free_scev(env);
	return -ENOMEM;
}

static struct bpf_reg_state *scev_regno_to_reg(struct bpf_verifier_env *env,
					    struct bpf_func_state *st, u32 r)
{
	int spi, slots_available;

	if (r < MAX_BPF_REG)
		return &st->regs[r];

	slots_available = st->allocated_stack / BPF_REG_SIZE;
	spi = r - MAX_BPF_REG;
	if (spi < slots_available)
		return &st->stack[spi].spilled_ptr;

	return &env->scev_not_init_reg;
}

static bool scev_reg_alive(struct bpf_verifier_env *env, struct bpf_verifier_state *st, u32 r)
{
	int insn_idx = bpf_frame_insn_idx(st, st->curframe);
	u16 live_regs = env->insn_aux_data[insn_idx].live_regs_before;
	int spi;

	if (r < MAX_BPF_REG) {
		return BIT(r) & live_regs;
	} else {
		spi = r - MAX_BPF_REG;
		return bpf_stack_slot_alive(env, st->curframe, spi * 2) ||
		       bpf_stack_slot_alive(env, st->curframe, spi * 2 + 1);
	}
}

/*
 * Latch is a condition deciding if execution remains inside a loop.
 * Linear latch represents a condition 'if <reg> <op> <loop invariant> goto <loop-header>',
 * where equation '<base> + i * <step> <op> <bound>' describes values taken by register <reg>,
 * 'i' is the loop iteration number, starting from 0.
 */
struct linear_latch {
	u32 insn_idx;
	u32 base_expr;
	u32 step_expr;
	u32 bound_expr;
	u32 reg_expr;
	u32 reg;
	u32 op;
};

static bool loop_invariant(struct scev *scev, u32 id)
{
	s64 imm;
	u32 reg;

	return is_reg(scev, id, &reg) || is_imm(scev, id, &imm);
}

static int match_linear_latch(struct bpf_verifier_env *env,
			      u32 latch_idx,
			      struct linear_latch *latch)
{
	struct bpf_insn *insn = &env->prog->insnsi[latch_idx];
	struct scev *scev = env->scev;
	struct env *latch_env = find_loop_env(scev, bpf_loop_at_index(env, latch_idx), latch_idx);
	u32 true_branch_tgt;
	u32 l, r, op, base;
	u32 src_reg_scev;
	u32 dst_reg_scev;
	int id;

	/* 32-bit arithmetic is not handled yet */
	if (BPF_CLASS(insn->code) != BPF_JMP)
		return false;
	op = BPF_OP(insn->code);
	/* Flip the condition if true branch jumps out of the loop */
	true_branch_tgt = latch_idx + bpf_jmp_offset(insn) + 1;
	if (bpf_loop_at_index(env, true_branch_tgt) != bpf_loop_at_index(env, latch_idx))
		op = bpf_rev_opcode(op);
	switch (op) {
	case BPF_JSLT:
	case BPF_JSLE:
	case BPF_JSGT:
	case BPF_JSGE:
	case BPF_JLT:
	case BPF_JLE:
	case BPF_JGT:
	case BPF_JGE:
	case BPF_JNE:
		break;
	default:
		return false;
	}

	latch->op = op;
	latch->insn_idx = latch_idx;

	dst_reg_scev = latch_env->reg2scev[insn->dst_reg];
	src_reg_scev = latch_env->reg2scev[insn->src_reg];
	if (!is_linear(scev, dst_reg_scev, &base, &latch->step_expr))
		return false;

	if (BPF_SRC(insn->code) == BPF_K) {
		id = imm_expr(scev, insn->imm);
		if (id < 0)
			return id;
		latch->bound_expr = id;
	} else {
		latch->bound_expr = src_reg_scev;
	}

	if (is_reg(scev, base, &latch->reg)) {
		id = imm_expr(scev, 0);
		if (id < 0)
			return id;
		latch->base_expr = id;
		latch->reg_expr = base;
	} else if (is_add(scev, base, &l, &r) &&
		   is_reg(scev, l, &latch->reg)) {
		latch->base_expr = r;
		latch->reg_expr = l;
	} else {
		return false;
	}

	if (!loop_invariant(scev, latch->base_expr) ||
	    !loop_invariant(scev, latch->step_expr) ||
	    !loop_invariant(scev, latch->bound_expr))
		return false;

	return true;
}

static bool eval_expr(struct bpf_verifier_env *env, struct scev *scev, struct bpf_func_state *st, u32 id, u64 *result)
{
	struct bpf_reg_state *reg;
	u32 regno;
	s64 imm;

	if (is_reg(scev, id, &regno)) {
		reg = scev_regno_to_reg(env, st, regno);
		if (reg->type == NOT_INIT)
			return false;
		if (tnum_is_const(reg->var_off)) {
			*result = reg->var_off.value;
			return true;
		}
	} else if (is_imm(scev, id, &imm)) {
		*result = imm;
		return true;
	}
	return false;
}

/* Like DIV_ROUND_UP() but overflow safe */
static u64 div_round_up(u64 a, u64 b)
{
	return a / b + (a % b != 0);
}

/*
 * Loop with post-condition:
 *
 *    r0 = 0
 * l: ...                r0 ∈ [0,1,2] header executed 3 times
 *    r0 += 1            r0 ∈ [0,1,2]
 *    ...                r0 ∈ [1,2,3]
 *    if r0 != 3 goto l  r0 ∈ [1,2,3] backedge taken 2 times
 *    ...                r0 ∈ [3]
 *
 * SCEV at header: r0 = k
 * SCEV at latch:  r0 = 1 + k
 *
 * Loop with pre-condition:
 *
 *    r0 = 0
 * l: ...                r0 ∈ [0,1,2,3] header executed 4 times
 *    if r0 == 3 goto e  r0 ∈ [0,1,2,3] backedge taken 3 times
 *    r0 += 1            r0 ∈ [0,1,2]
 *    ...                r0 ∈ [1,2,3]
 *    goto l             r0 ∈ [1,2,3]
 * e: ...                r0 ∈ [3]
 *
 * SCEV at header: r0 = k
 * SCEV at latch:  r0 = k
 */
static bool compute_max_iters(struct bpf_verifier_env *env,
			      struct bpf_func_state *st,
			      struct linear_latch *latch,
			      struct bpf_loop_iters *iters)
{
	u64 base, step, diff, bound, initial, max_iters;
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_loop *loop = aux[bpf_loop_at_index(env, latch->insn_idx)].loop;
	struct scev *scev = env->scev;
	u8 op = latch->op;

	if (!eval_expr(env, scev, st, latch->base_expr, &base) ||
	    !eval_expr(env, scev, st, latch->step_expr, &step) ||
	    !eval_expr(env, scev, st, latch->bound_expr, &bound) ||
	    !eval_expr(env, scev, st, latch->reg_expr, &initial))
		return false;

	if (step == 0)
		return false;
	if ((s64)step == S64_MIN)
		return false;
	if ((s64)step < 0) {
		/* Multiply both sides of the equation by -1, e.g. -2*i > -3 becomes 2*i < 3 */
		op = bpf_flip_opcode(op);
		step = -step;
		swap(bound, initial);
	}
	diff = bound - initial;
	if (diff / step == U64_MAX)
		return false;
	switch (op) {
	case BPF_JLT:
		max_iters = (u64)initial >= (u64)bound ? 0 : div_round_up(diff, step);
		break;
	case BPF_JLE:
		max_iters = (u64)initial >  (u64)bound ? 0 : diff / step + 1;
		break;
	case BPF_JSLT:
		max_iters = (s64)initial >= (s64)bound ? 0 : div_round_up(diff, step);
		break;
	case BPF_JSLE:
		max_iters = (s64)initial >  (s64)bound ? 0 : diff / step + 1;
		break;
	case BPF_JNE:
		max_iters = diff % step ? U32_MAX : div_round_up(diff, step);
		break;
	default:
		return false;
	}

	if (max_iters > U32_MAX)
		return false;

	/*
	 * The latch is a conditional jump with one jump target exiting the loop.
	 * Linear latch is matched only if the loop has a single backedge.
	 * The loop still, however can have multiple exits.
	 * In such case, conservatively assume that non-latch exit can happen
	 * at any iteration, thus setting minimal number of iterations as 0.
	 */
	iters->max_header_count = max_iters + (base == 0 ? 1 : 0);
	iters->min_header_count = loop->exits_cnt == 1 ? iters->max_header_count : 0;
	iters->pre_cond = base == 0;
	return true;
}

static void mark_scev_reg_scratched(struct bpf_verifier_env *env, u32 r)
{
	if (r < MAX_BPF_REG)
		mark_reg_scratched(env, r);
	else
		mark_stack_slot_scratched(env, r - __MAX_BPF_REG);
}

/* Main logic in verifier.c forbids varying offsets for certain register types. */
static bool is_widenable_reg_type(const struct bpf_reg_state *reg)
{
	switch (base_type(reg->type)) {
	case SCALAR_VALUE:
	case PTR_TO_MAP_VALUE:
	case PTR_TO_MAP_KEY:
	case PTR_TO_STACK:
	case PTR_TO_PACKET:
	case PTR_TO_PACKET_META:
	case PTR_TO_MEM:
	case PTR_TO_BUF:
	case PTR_TO_BTF_ID:
		return true;
	default:
		return false;
	}
}

/* Check that ANY leaves can be unioned with r's loop-entry value. */
static bool is_any_imm_reg(struct bpf_verifier_env *env, struct bpf_func_state *loop_entry,
			   struct env *header_env, u32 r, u32 id)
{
	struct scev *scev = env->scev;
	struct bpf_reg_state *reg, *leaf_reg;
	u32 l, rr, leaf, ra, order;
	s64 imm;

	if (!is_any(scev, id, &l, &rr))
		return false;
	reg = scev_regno_to_reg(env, loop_entry, r);
	if (!is_widenable_reg_type(reg))
		return false;

	scev->stack_sz = 0;
	expr_stack_push(scev, id);
	while (expr_next(scev, &id, &order)) {
		if (order & DEPTH_LIMIT)
			return false;
		if (!(order & PRE) || is_any(scev, id, &l, &rr))
			continue;
		if (is_imm(scev, id, &imm)) {
			if (reg->type != SCALAR_VALUE)
				return false;
		} else if (is_reg(scev, id, &leaf)) {
			/* Other leaves must denote loop-invariant registers. */
			if (leaf != r &&
			    !(is_reg(scev, header_env->reg2scev[leaf], &ra) && ra == leaf))
				return false;
			leaf_reg = scev_regno_to_reg(env, loop_entry, leaf);
			if (leaf_reg->type != reg->type)
				return false;
		} else {
			return false;
		}
	}
	return true;
}

struct bounds {
	struct cnum64 range;
	u16 step;
};

static bool is_simple_linear(struct scev *scev, u32 id, u32 *base_reg, s64 *slope_imm)
{
	u32 base, slope;

	return is_linear(scev, id, &base, &slope) &&
	       is_reg(scev, base, base_reg) &&
	       is_imm(scev, slope, slope_imm) &&
	       *slope_imm <= S16_MAX &&
	       *slope_imm >= S16_MIN &&
	       *slope_imm != 0;
}

/*
 * Compute the range an induction variable in `reg` spans over the loop.
 * Returns false if the computation overflows s64.
 */
static bool linear_bounds(struct bpf_reg_state *reg, struct bpf_loop_iters *iters, s64 slope,
			  struct bounds *out)
{
	s64 slope_abs = slope < 0 ? -slope : slope;
	s64 min_val = reg_smin(reg);
	s64 max_val = reg_smax(reg);
	s64 total_change;
	u16 step;

	if (check_mul_overflow(slope, (s64)iters->max_header_count - 1, &total_change))
		return false;
	if (slope > 0) {
		if (check_add_overflow(max_val, total_change, &max_val))
			return false;
	} else {
		if (check_add_overflow(min_val, total_change, &min_val))
			return false;
	}
	/*
	 * If the entry value is a single point the value set is 'v + slope * k',
	 * so the step is |slope|. Otherwise, only the power-of-two alignment
	 * shared by the entry value and the slope.
	 */
	if (cnum64_is_const(reg->r64))
		step = slope_abs;
	else
		step = 1u << min_t(u32, tnum_alignment(reg->var_off), __ffs(slope_abs));
	out->range = cnum64_from_srange(min_val, max_val);
	out->step = step;
	return true;
}

int bpf_compute_loop_iters(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			   struct bpf_loop_iters *iters)
{
	struct bpf_func_state *cur_func = st->frame[st->curframe];
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_verifier_log *log = &env->log;
	struct scev *scev = env->scev;
	struct env *header_env;
	struct linear_latch latch;
	struct bpf_loop *loop;
	struct bounds bounds;
	int insn_idx = st->insn_idx;
	int linear_latch;
	u32 r, base_reg;
	int latch_idx;
	s64 slope_imm;
	int err;

	/*
	 * If insn_idx is a loop header for a reducible loop with a single backedge.
	 * loop is NULL for secondary entries to irreducible loops.
	 */
	loop = aux[insn_idx].loop;
	if (!loop || loop->irreducible || loop->backedges_cnt != 1 || loop->backedges_overflow ||
	    loop->exits_overflow) {
		if (log->level & BPF_LOG_LEVEL2)
			bpf_log(log, "loop header at %d, unsupported loop:%s%s%s\n", insn_idx,
				!loop || loop->irreducible ? " irreducible" : "",
				loop && loop->backedges_cnt > 1 ? " multiple backedges" : "",
				loop && loop->exits_overflow ? " too many exits" : "");
		return 0;
	}

	/* If this backedge has a latch */
	latch_idx = loop->backedges[0].latch;
	if (latch_idx < 0)
		return 0;

	linear_latch = match_linear_latch(env, latch_idx, &latch);
	if (linear_latch < 0)
		return linear_latch;

	if (!linear_latch) {
		if (log->level & BPF_LOG_LEVEL2)
			bpf_log(log, "loop header at %d, non-linear latch at %d\n",
				insn_idx, latch_idx);
		return 0;
	}

	if (!compute_max_iters(env, cur_func, &latch, iters)) {
		if (log->level & BPF_LOG_LEVEL2)
			bpf_log(log, "loop header at %d, can't compute iterations count\n", insn_idx);
		return 0;
	}

	if (iters->max_header_count == 0) {
		if (log->level & BPF_LOG_LEVEL2)
			bpf_log(log, "loop header at %d, 0 iterations count\n", insn_idx);
		return 0;
	}

	if (iters->max_header_count == U32_MAX) {
		if (log->level & BPF_LOG_LEVEL2)
			bpf_log(log, "loop header at %d, inf iterations count\n", insn_idx);
		return 0;
	}

	if (log->level & BPF_LOG_LEVEL2) {
		bpf_log(log, "loop header at %d, header_count is ", insn_idx);
		if (iters->min_header_count == iters->max_header_count)
			bpf_log(log, "%u ", iters->max_header_count);
		else
			bpf_log(log, "[%u..%u] ", iters->min_header_count, iters->max_header_count);
		bpf_log(log, "%s\n", iters->pre_cond ? "pre-cond" : "post-cond");
	}

	err = bpf_live_stack_query_init(env, st);
	if (err)
		return err;

	header_env = find_header_env(scev, insn_idx);
	for (r = 0; r < REGS_NUM; r++) {
		struct bpf_reg_state *reg;
		u32 ra, r_scev, r_expr;
		bool spill_base = false;

		if (!scev_reg_alive(env, st, r))
			continue;

		r_scev = header_env->reg2scev[r];
		reg = scev_regno_to_reg(env, cur_func, r);
		/* If SCEV for r is (linear <reg> <slope>) */
		if (is_simple_linear(scev, r_scev, &base_reg, &slope_imm) &&
		    is_widenable_reg_type(reg)) {
			if (base_reg == r) {
				/* Can't widen if the iteration range overflows */
				if (!linear_bounds(reg, iters, slope_imm, &bounds))
					goto cant_widen;
				/* Spills at varying offsets lose precision */
				if (test_bit(r, loop->store_base_regs)) {
					spill_base = true;
					goto cant_widen;
				}
			}
			continue;
		}

		/* rA = rA, loop does not change this reg */
		if (is_reg(scev, r_scev, &ra) && r == ra)
			continue;

		/* (any 1 (any 2 (any 3 4))) */
		if (is_any_imm_reg(env, cur_func, header_env, r, r_scev))
			continue;

cant_widen:
		if (log->level & BPF_LOG_LEVEL2) {
			r_expr = header_env->reg2expr[r];
			bpf_log(log, "loop header at %d, can't widen ", insn_idx);
			log_reg(env, r);
			bpf_log(log, ", expr is ");
			log_expr(env, r_expr);
			if (spill_base)
				bpf_log(log, ", requires exact stack-offset tracking");
			bpf_log(log, "\n");
		}
		return 0;
	}

	return 1;
}

static void scratch_scalar_id(struct bpf_reg_state *reg)
{
	if (reg->type == SCALAR_VALUE)
		reg->id = 0;
}

/* The filtering pass has checked that every leaf can be unioned into acc. */
static int union_any_reg(struct bpf_verifier_env *env, struct bpf_func_state *loop_entry,
			 struct bpf_reg_state *acc, u32 id)
{
	struct bpf_reg_state *tmp = &env->fake_reg[0], *leaf_reg;
	struct scev *scev = env->scev;
	u32 l, r, leaf, order;
	s64 imm;
	int err;

	scev->stack_sz = 0;
	expr_stack_push(scev, id);
	while (expr_next(scev, &id, &order)) {
		if (order & DEPTH_LIMIT) {
			verifier_bug(env, "scev ANY union exceeds expression depth limit");
			return -EFAULT;
		}
		if (!(order & PRE) || is_any(scev, id, &l, &r))
			continue;
		if (is_imm(scev, id, &imm)) {
			bpf_mark_reg_known_scalar(tmp, imm);
			leaf_reg = tmp;
		} else if (is_reg(scev, id, &leaf)) {
			leaf_reg = scev_regno_to_reg(env, loop_entry, leaf);
		} else {
			verifier_bug(env, "scev ANY union has an unsupported leaf");
			return -EFAULT;
		}
		err = bpf_reg_union(env, acc, leaf_reg);
		if (err)
			return err;
	}
	return 0;
}

int bpf_widen_scev_regs(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			struct bpf_verifier_state *loop_entry, struct bpf_loop_iters *iters)
{
	struct bpf_func_state *cur_func = st->frame[st->curframe];
	struct bpf_func_state *entry_func = loop_entry->frame[loop_entry->curframe];
	struct bpf_verifier_log *log = &env->log;
	struct scev *scev = env->scev;
	struct bpf_reg_state *reg;
	struct env *header_env;
	struct bounds bounds;
	u32 r, base_reg, r_expr, a, b;
	int insn_idx = st->insn_idx;
	s64 slope_imm;
	int err;

	header_env = find_header_env(scev, insn_idx);
	for (r = 0; r < REGS_NUM; r++) {
		if (!scev_reg_alive(env, st, r))
			continue;

		r_expr = header_env->reg2scev[r];
		/* If SCEV for r is (linear <reg> <slope>)*/
		if (is_simple_linear(scev, r_expr, &base_reg, &slope_imm) &&
		    base_reg == r) {
			reg = scev_regno_to_reg(env, cur_func, r);
			/* Feasibility was checked in the filtering pass above. */
			if (!linear_bounds(reg, iters, slope_imm, &bounds)) {
				verifier_bug(env, "scev widen bounds overflow for r%d", r);
				return -EFAULT;
			}
			if (log->level & BPF_LOG_LEVEL2) {
				bpf_log(log, "loop header at %d, widening ", insn_idx);
				log_reg(env, r);
				bpf_log(log, " to %lld..%lld step %u\n",
					cnum64_smin(bounds.range), cnum64_smax(bounds.range),
					bounds.step);
			}
			scratch_scalar_id(reg);
			err = bpf_set_reg_range(env, reg, bounds.range, bounds.step);
			if (err)
				return err;
			mark_scev_reg_scratched(env, r);
		} else if (is_any(scev, r_expr, &a, &b)) {
			reg = scev_regno_to_reg(env, cur_func, r);
			err = union_any_reg(env, entry_func, reg, r_expr);
			if (err)
				return err;
			if (log->level & BPF_LOG_LEVEL2) {
				bpf_log(log, "loop header at %d, widening ", insn_idx);
				log_reg(env, r);
				bpf_log(log, " to %lld..%lld step %u\n",
					reg_smin(reg), reg_smax(reg), reg->step);
			}
			scratch_scalar_id(reg);
			mark_scev_reg_scratched(env, r);
		}
	}
	return 1;
}

int bpf_clamp_scev_regs(struct bpf_verifier_env *env, struct bpf_func_state *cur_func_state, u32 insn_idx,
			struct bpf_verifier_state *entry_state, struct bpf_loop_iters *iters)
{
	struct bpf_func_state *entry_st = entry_state->frame[entry_state->curframe];
	struct bpf_verifier_log *log = &env->log;
	struct bpf_reg_state *reg, *entry_reg;
	struct scev *scev = env->scev;
	struct env *header_env;
	struct bounds bounds;
	u32 r, base_reg;
	s64 slope_imm;
	int err;

	if (entry_state->curframe != cur_func_state->frameno) {
		verifier_bug(env, "clamping registers for a wrong frame: %d vs %d\n",
			     entry_state->curframe, cur_func_state->frameno);
		return -EFAULT;
	}

	header_env = find_header_env(scev, insn_idx);
	for (r = 0; r < REGS_NUM; r++) {
		/* If SCEV for r is (linear <reg> <slope>)*/
		if (!is_simple_linear(scev, header_env->reg2scev[r], &base_reg, &slope_imm) ||
		    base_reg != r)
			continue;

		entry_reg = scev_regno_to_reg(env, entry_st, r);
		reg = scev_regno_to_reg(env, cur_func_state, r);
		if (entry_reg->type == NOT_INIT || reg->type == NOT_INIT)
			continue;

		if (!linear_bounds(entry_reg, iters, slope_imm, &bounds)) {
			verifier_bug(env, "scev clamp bounds overflow for r%d", r);
			return -EFAULT;
		}
		bounds.range = cnum64_intersect(reg->r64, bounds.range);
		if (cnum64_is_empty(bounds.range)) {
			verifier_bug(env, "scev clamp produced empty range for r%d", r);
			return -EFAULT;
		}
		if (log->level & BPF_LOG_LEVEL2) {
			bpf_log(log, "loop header at %d, clamping ", insn_idx);
			log_reg(env, r);
			bpf_log(log, " to %lld..%lld step %u\n",
				cnum64_smin(bounds.range), cnum64_smax(bounds.range),
				bounds.step);
		}
		scratch_scalar_id(reg);
		err = bpf_set_reg_range(env, reg, bounds.range, bounds.step);
		if (err)
			return err;
		mark_scev_reg_scratched(env, r);
	}
	return 0;
}
