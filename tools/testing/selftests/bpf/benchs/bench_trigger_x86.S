/* SPDX-License-Identifier: GPL-2.0 */

#ifndef ASM_NL
#define ASM_NL  ;
#endif

#define SYM_ENTRY(name)                        \
       .globl name ASM_NL              \
       name:

#define SYM_END(name)                  \
       .type name STT_FUNC ASM_NL      \
       .size name, .-name ASM_NL

.code64
.section .text, "ax"

SYM_ENTRY(uprobe_target_nop)
	nop
	ret
SYM_END(uprobe_target_nop)

SYM_ENTRY(uprobe_target_push)
	push %rax
	pop %rax
	ret
SYM_END(uprobe_target_push)

SYM_ENTRY(uprobe_target_ret)
	ret
SYM_END(uprobe_target_ret)

.section .note.GNU-stack,"",@progbits
