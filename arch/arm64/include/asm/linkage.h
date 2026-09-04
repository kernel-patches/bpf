#ifndef __ASM_LINKAGE_H
#define __ASM_LINKAGE_H

#ifdef __ASSEMBLER__
#include <asm/assembler.h>
#endif

#define __ALIGN		.balign CONFIG_FUNCTION_ALIGNMENT
#define __ALIGN_STR	".balign " #CONFIG_FUNCTION_ALIGNMENT

/*
 * When using in-kernel BTI we need to ensure that PCS-conformant
 * assembly functions have suitable annotations.  Override
 * SYM_FUNC_START to insert a BTI landing pad at the start of
 * everything, the override is done unconditionally so we're more
 * likely to notice any drift from the overridden definitions.
 */
#define SYM_FUNC_START(name)				\
	SYM_START(name, SYM_L_GLOBAL, SYM_A_ALIGN)	\
	bti c ;

#define SYM_FUNC_START_NOALIGN(name)			\
	SYM_START(name, SYM_L_GLOBAL, SYM_A_NONE)	\
	bti c ;

#define SYM_FUNC_START_LOCAL(name)			\
	SYM_START(name, SYM_L_LOCAL, SYM_A_ALIGN)	\
	bti c ;

#define SYM_FUNC_START_LOCAL_NOALIGN(name)		\
	SYM_START(name, SYM_L_LOCAL, SYM_A_NONE)	\
	bti c ;

#define SYM_FUNC_START_WEAK(name)			\
	SYM_START(name, SYM_L_WEAK, SYM_A_ALIGN)	\
	bti c ;

#define SYM_FUNC_START_WEAK_NOALIGN(name)		\
	SYM_START(name, SYM_L_WEAK, SYM_A_NONE)		\
	bti c ;

/*
 * The compiler emits CONFIG_ARM64_FUNCTION_PREFIX_NOPS NOPs between a C
 * function's kCFI type hash and its entry point. Callers check the hash
 * at that offset.
 */
#define __CFI_TYPE(name)				\
	.4byte __kcfi_typeid_##name ASM_NL		\
	.rept CONFIG_ARM64_FUNCTION_PREFIX_NOPS ASM_NL	\
	nop ASM_NL					\
	.endr

#define SYM_TYPED_FUNC_START(name)				\
	SYM_TYPED_START(name, SYM_L_GLOBAL, SYM_A_ALIGN)	\
	bti c ;

#define _THIS_IP_ ({ unsigned long __ip; asm volatile("adr %0, ." : "=r" (__ip)); __ip; })

#define __bss_pgtbl __section(".bss..pgtbl") __aligned(PAGE_SIZE)

#endif
