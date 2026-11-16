// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2013, 2014 Linaro Ltd;  <roy.franz@linaro.org>
 *
 * This file implements the EFI boot stub for the arm64 kernel.
 * Adapted from ARM version by Mark Salter <msalter@redhat.com>
 */


#include <linux/efi.h>
#include <asm/efi.h>
#include <asm/memory.h>

#include "efistub.h"

efi_status_t handle_kernel_image(unsigned long *image_addr,
				 unsigned long *image_size,
				 unsigned long *reserve_addr,
				 unsigned long *reserve_size,
				 efi_loaded_image_t *image,
				 efi_handle_t image_handle,
				 const struct efi_image_info **image_info)
{
	if (image->image_base != _text) {
		efi_err("FIRMWARE BUG: efi_loaded_image_t::image_base has bogus value\n");
		image->image_base = _text;
	}

	if (!IS_ALIGNED((u64)_text, SEGMENT_ALIGN))
		efi_err("FIRMWARE BUG: kernel image not aligned on %dk boundary\n",
			SEGMENT_ALIGN >> 10);

	return efi_kaslr_relocate_kernel(image_addr, image_size, image_info,
					 efi_kaslr_get_phys_seed(image_handle));
}

void efi_icache_sync(unsigned long start, unsigned long end)
{
	caches_clean_inval_pou(start, end);
}
