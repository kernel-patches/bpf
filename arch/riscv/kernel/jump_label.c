// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Emil Renner Berthing
 *
 * Based on arch/arm64/kernel/jump_label.c
 */
#include <linux/jump_label.h>
#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/mutex.h>
#include <asm/bug.h>
#include <asm/insn.h>
#include <asm/patch.h>

void arch_jump_label_transform(struct jump_entry *entry,
			       enum jump_label_type type)
{
	void *addr = (void *)jump_entry_code(entry);
	u32 insn;

	if (type == JUMP_LABEL_JMP) {
		long offset = jump_entry_target(entry) - jump_entry_code(entry);

		if (WARN_ON(offset & 1 || offset < -524288 || offset >= 524288))
			return;

		insn = RVG_OPCODE_JAL;
		riscv_insn_insert_jtype_imm(&insn, (s32)offset);
	} else {
		insn = RVG_OPCODE_NOP;
	}

	mutex_lock(&text_mutex);
	patch_text_nosync(addr, &insn, sizeof(insn));
	mutex_unlock(&text_mutex);
}
