/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef _RISCV_KERNEL_KPROBES_DECODE_INSN_H
#define _RISCV_KERNEL_KPROBES_DECODE_INSN_H

#include <asm/sections.h>
#include <asm/kprobes.h>

enum probe_insn {
	INSN_REJECTED,
	INSN_GOOD_NO_SLOT,
	INSN_GOOD,
};

enum probe_insn __kprobes
riscv_probe_decode_insn(probe_opcode_t *addr, struct arch_probe_insn *asi);

/* A constrained LR/SC sequence has at most this many instructions between lr and sc */
#define RISCV_LRSC_MAX_BODY	16
/* Bytes from the probed instruction through the farthest possible sc */
#define RISCV_LRSC_SCAN_BYTES	((RISCV_LRSC_MAX_BODY + 1) * 4)

bool __kprobes riscv_probe_in_lrsc_body(const u16 *buf, size_t len);

#endif /* _RISCV_KERNEL_KPROBES_DECODE_INSN_H */
