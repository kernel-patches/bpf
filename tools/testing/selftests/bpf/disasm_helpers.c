// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <bpf/bpf.h>
#include "disasm.h"

struct print_insn_context {
	char *buf;
	size_t sz;
};

static void print_insn_cb(void *private_data, const char *fmt, ...)
{
	struct print_insn_context *ctx = private_data;
	va_list args;

	va_start(args, fmt);
	vsnprintf(ctx->buf, ctx->sz, fmt, args);
	va_end(args);
}

uint32_t disasm_insn(struct bpf_insn *insn, char *buf, size_t buf_sz)
{
	struct print_insn_context ctx = {
		.buf = buf,
		.sz = buf_sz,
	};
	struct bpf_insn_cbs cbs = {
		.cb_print	= print_insn_cb,
		.private_data	= &ctx,
	};
	int pfx_end, sfx_start, len;
	bool double_insn;

	print_bpf_insn(&cbs, insn, true);
	/* We share code with kernel BPF disassembler, it adds '(FF) ' prefix
	 * for each instruction (FF stands for instruction `code` byte).
	 * Remove the prefix inplace, and also simplify call instructions.
	 * E.g.: "(85) call foo#10" -> "call foo".
	 */
	pfx_end = 0;
	sfx_start = max((int)strlen(buf) - 1, 0);
	/* For whatever reason %n is not counted in sscanf return value */
	sscanf(buf, "(%*[^)]) %n", &pfx_end);
	sscanf(buf, "(%*[^)]) call %*[^#]%n", &sfx_start);
	len = sfx_start - pfx_end;
	memmove(buf, buf + pfx_end, len);
	buf[len] = 0;
	double_insn = insn->code == (BPF_LD | BPF_IMM | BPF_DW);
	return double_insn ? 2 : 1;
}
