// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bitfield.h>
#include <linux/compiler.h>
#include <linux/percpu.h>

#include <asm/current.h>
#include <asm/ptrace.h>

/*
 * If the interrupted context had an active per-CPU operation, rewrite its
 * saved offset and address registers for the CPU on which it will resume.
 */
void noinstr riscv_pcpu_regs_fixup(struct pt_regs *regs)
{
	unsigned long pcpu_offset = __my_cpu_offset;
	unsigned long gprs = regs->pcpu_gprs;
	unsigned long pcp;
	unsigned int reg_pcp;
	unsigned int reg_off;
	unsigned int reg_addr;

	reg_pcp = FIELD_GET(PCPU_GPR_PCP, gprs);
	reg_off = FIELD_GET(PCPU_GPR_OFF, gprs);
	reg_addr = FIELD_GET(PCPU_GPR_ADDR, gprs);

	/* pt_regs offset zero represents x0, followed by x1 through x31. */
	pcp = regs_get_register(regs, reg_pcp * sizeof(unsigned long));
	regs_set_register(regs, reg_off * sizeof(unsigned long), pcpu_offset);
	regs_set_register(regs, reg_addr * sizeof(unsigned long),
			  pcp + pcpu_offset);
}
