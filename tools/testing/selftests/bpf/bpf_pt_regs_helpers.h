/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BPF_PT_REGS_HELPERS
#define __BPF_PT_REGS_HELPERS

#include <bpf/bpf_tracing.h>

struct bpf_pt_regs {
	unsigned long long parm[5];
	unsigned long long ret;
	unsigned long long fp;
	unsigned long long rc;
	unsigned long long sp;
	unsigned long long ip;
};

static inline void bpf_copy_pt_regs(struct bpf_pt_regs *dest, struct pt_regs *src)
{
	dest->parm[0]	= PT_REGS_PARM1(src);
	dest->parm[1]	= PT_REGS_PARM2(src);
	dest->parm[2]	= PT_REGS_PARM3(src);
	dest->parm[3]	= PT_REGS_PARM4(src);
	dest->parm[4]	= PT_REGS_PARM5(src);
	dest->ret	= PT_REGS_RET(src);
	dest->fp	= PT_REGS_FP(src);
	dest->rc	= PT_REGS_RC(src);
	dest->sp	= PT_REGS_SP(src);
	dest->ip	= PT_REGS_IP(src);
}

#endif /* __BPF_PT_REGS_HELPERS */
