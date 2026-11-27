/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 Linaro Ltd <ard.biesheuvel@linaro.org>
 */

#ifndef __ASM_ARM_EFI_H
#define __ASM_ARM_EFI_H

#include <asm/cacheflush.h>
#include <asm/cachetype.h>
#include <asm/early_ioremap.h>
#include <asm/fixmap.h>
#include <asm/highmem.h>
#include <asm/mach/map.h>
#include <asm/mmu_context.h>
#include <asm/ptrace.h>
#include <asm/uaccess.h>

#ifdef CONFIG_EFI
void efi_init(void);
void arm_efi_init(void);

int efi_create_mapping(struct mm_struct *mm, efi_memory_desc_t *md);
int efi_set_mapping_permissions(struct mm_struct *mm, efi_memory_desc_t *md, bool);

#define arch_efi_call_virt_setup()	efi_virtmap_load()
#define arch_efi_call_virt_teardown()	efi_virtmap_unload()

#ifdef CONFIG_CPU_TTBR0_PAN
#undef arch_efi_call_virt
#define arch_efi_call_virt(p, f, args...) ({				\
	unsigned int flags = uaccess_save_and_enable();			\
	efi_status_t res = _Generic((p)->f(args),			\
			efi_status_t:	(p)->f(args),			\
			default:	((p)->f(args), EFI_ABORTED));	\
	uaccess_restore(flags);						\
	res;								\
})
#endif

#define ARCH_EFI_IRQ_FLAGS_MASK \
	(PSR_J_BIT | PSR_E_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | \
	 PSR_T_BIT | MODE_MASK)

static inline void efi_set_pgd(struct mm_struct *mm)
{
	check_and_switch_context(mm, NULL);
}

void efi_virtmap_load(void);
void efi_virtmap_unload(void);

#else
#define arm_efi_init()
#endif /* CONFIG_EFI */

/* arch specific definitions used by the stub code */

/*
 * phys-to-virt patching requires that the physical to virtual offset is a
 * multiple of 2 MiB.
 */
#define EFI_PHYS_ALIGN		SZ_2M

/* on ARM, the initrd should be loaded in a lowmem region */
static inline unsigned long efi_get_max_initrd_addr(unsigned long image_addr)
{
	return round_down(image_addr, SZ_4M) + SZ_512M;
}

struct efi_arm_entry_state {
	u32	cpsr_before_ebs;
	u32	sctlr_before_ebs;
	u32	cpsr_after_ebs;
	u32	sctlr_after_ebs;
};

static inline void efi_capsule_flush_cache_range(void *addr, int size)
{
	__cpuc_flush_dcache_area(addr, size);
}

#endif /* _ASM_ARM_EFI_H */
