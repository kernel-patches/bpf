// SPDX-License-Identifier: GPL-2.0-only

#include <linux/efi.h>
#include <linux/sysfb.h>

#include <asm/efi.h>

#include "efistub.h"

extern const struct efi_image_info efistub_image_info;

struct sysfb_display_info *
alloc_primary_display(const struct efi_image_info *image_info)
{
	if (IS_ENABLED(CONFIG_ARM))
		return __alloc_primary_display();

	if (IS_ENABLED(CONFIG_EFI_EARLYCON) ||
	    IS_ENABLED(CONFIG_SYSFB))
		return efistub_sysfb_display_info(image_info);

	return NULL;
}

/*
 * EFI entry point for the generic EFI stub used by ARM, arm64, RISC-V and
 * LoongArch. This is the entrypoint that is described in the PE/COFF header
 * of the core kernel.
 */
efi_status_t __efiapi efi_pe_entry(efi_handle_t handle,
				   efi_system_table_t *systab)
{
	static efi_guid_t loaded_image_proto = LOADED_IMAGE_PROTOCOL_GUID;
	const struct efi_image_info *image_info = &efistub_image_info;
	efi_loaded_image_t *image;
	efi_status_t status;
	unsigned long image_addr;
	unsigned long image_size = 0;
	/* addr/point and size pairs for memory management*/
	unsigned long reserve_addr = 0;
	unsigned long reserve_size = 0;

	WRITE_ONCE(efi_system_table, systab);

	/* Check if we were booted by the EFI firmware */
	if (efi_system_table->hdr.signature != EFI_SYSTEM_TABLE_SIGNATURE)
		return EFI_INVALID_PARAMETER;

	/*
	 * Get a handle to the loaded image protocol.  This is used to get
	 * information about the running image, such as size and the command
	 * line.
	 */
	status = efi_bs_call(handle_protocol, handle, &loaded_image_proto,
			     (void *)&image);
	if (status != EFI_SUCCESS) {
		efi_err("Failed to get loaded image protocol\n");
		return status;
	}

	char *cmdline_ptr __free(efi_pool) = NULL;
	status = efi_handle_cmdline(image, &cmdline_ptr);
	if (status != EFI_SUCCESS)
		return status;

	efi_info("Booting Linux Kernel...\n");

	status = handle_kernel_image(&image_addr, &image_size,
				     &reserve_addr,
				     &reserve_size,
				     image, handle, &image_info);
	if (status != EFI_SUCCESS) {
		efi_err("Failed to relocate kernel\n");
		return status;
	}

	status = efi_stub_common(handle, image, image_info, cmdline_ptr);

	efi_free(image_size, image_addr);
	efi_free(reserve_size, reserve_addr);

	return status;
}
