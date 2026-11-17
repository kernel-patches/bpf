// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2013 Linaro Ltd;  <roy.franz@linaro.org>
 */
#include <linux/efi.h>
#include <asm/efi.h>

#include "efistub.h"

static efi_guid_t cpu_state_guid = LINUX_EFI_ARM_CPU_STATE_TABLE_GUID;

struct efi_arm_entry_state *efi_entry_state;

static void get_cpu_state(u32 *cpsr, u32 *sctlr)
{
	asm("mrs %0, cpsr" : "=r"(*cpsr));
	if ((*cpsr & MODE_MASK) == HYP_MODE)
		asm("mrc p15, 4, %0, c1, c0, 0" : "=r"(*sctlr));
	else
		asm("mrc p15, 0, %0, c1, c0, 0" : "=r"(*sctlr));
}

efi_status_t check_platform_features(void)
{
	efi_status_t status;
	u32 cpsr, sctlr;
	int block;

	get_cpu_state(&cpsr, &sctlr);

	efi_info("Entering in %s mode with MMU %sabled\n",
		 ((cpsr & MODE_MASK) == HYP_MODE) ? "HYP" : "SVC",
		 (sctlr & 1) ? "en" : "dis");

	status = efi_bs_call(allocate_pool, EFI_LOADER_DATA,
			     sizeof(*efi_entry_state),
			     (void **)&efi_entry_state);
	if (status != EFI_SUCCESS) {
		efi_err("allocate_pool() failed\n");
		return status;
	}

	efi_entry_state->cpsr_before_ebs = cpsr;
	efi_entry_state->sctlr_before_ebs = sctlr;

	status = efi_bs_call(install_configuration_table, &cpu_state_guid,
			     efi_entry_state);
	if (status != EFI_SUCCESS) {
		efi_err("install_configuration_table() failed\n");
		goto free_state;
	}

	/* non-LPAE kernels can run anywhere */
	if (!IS_ENABLED(CONFIG_ARM_LPAE))
		return EFI_SUCCESS;

	/* LPAE kernels need compatible hardware */
	block = cpuid_feature_extract(CPUID_EXT_MMFR0, 0);
	if (block < 5) {
		efi_err("This LPAE kernel is not supported by your CPU\n");
		status = EFI_UNSUPPORTED;
		goto drop_table;
	}
	return EFI_SUCCESS;

drop_table:
	efi_bs_call(install_configuration_table, &cpu_state_guid, NULL);
free_state:
	efi_bs_call(free_pool, efi_entry_state);
	return status;
}

void efi_handle_post_ebs_state(void)
{
	get_cpu_state(&efi_entry_state->cpsr_after_ebs,
		      &efi_entry_state->sctlr_after_ebs);
}

/* last unaligned u32 in the image carries the uncompressed size */
extern u32 input_data_end[] __aligned(1);

/* entry #3 in the zimage magic table carries the kernel's BSS size */
extern u32 zimage_magic_table[] asm("_table_start");

struct efi_image_info efistub_image_info = {};

efi_status_t handle_kernel_image(unsigned long *image_addr,
				 unsigned long *image_size,
				 unsigned long *reserve_addr,
				 unsigned long *reserve_size,
				 efi_loaded_image_t *image,
				 efi_handle_t image_handle,
				 const struct efi_image_info **image_info)
{
	unsigned long kernel_memsize = input_data_end[-1] + zimage_magic_table[3];
	const int pgdir_size = (4 + IS_ENABLED(CONFIG_ARM_LPAE)) * PAGE_SIZE;
	int alloc_size = pgdir_size + ALIGN(kernel_memsize, EFI_PAGE_SIZE);
	const int slack = TEXT_OFFSET - pgdir_size;
	const unsigned long margin = max(EFI_PHYS_ALIGN, slack);
	unsigned long alloc_base, kernel_base;
	efi_status_t status;

	/*
	 * Allocate space for the decompressed kernel as low as possible.
	 * The region should be 2 MiB aligned, but the first 'slack' bytes
	 * are not used by Linux, so we allow those to be occupied by the
	 * firmware.
	 */
	status = efi_low_alloc_above(alloc_size + margin, EFI_PAGE_SIZE,
				     &alloc_base, 0x0);
	if (status != EFI_SUCCESS) {
		efi_err("Unable to allocate memory for uncompressed kernel.\n");
		return status;
	}

	if ((alloc_base % EFI_PHYS_ALIGN) > slack) {
		/*
		 * More than 'slack' bytes are already occupied at the base of
		 * the allocation, so we need to advance to the next 2 MiB block.
		 */
		kernel_base = round_up(alloc_base, EFI_PHYS_ALIGN);
		efi_info("Free memory starts at 0x%lx, setting kernel_base to 0x%lx\n",
			 alloc_base, kernel_base);
	} else {
		kernel_base = round_down(alloc_base, EFI_PHYS_ALIGN);
	}

	efistub_image_info._text_offset =
		kernel_base + TEXT_OFFSET - (u32)&efistub_image_info;

	kernel_base += slack;

	/* now free the parts that we will not use */
	efi_free(kernel_base - alloc_base, alloc_base);	/* no-op if 0 */
	efi_free(alloc_base + margin - kernel_base, kernel_base + alloc_size);

	*image_addr = kernel_base;
	*image_size = alloc_size;

	return EFI_SUCCESS;
}
