/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/init.h>

	__INITRODATA

	.p2align	3
	.globl		__efistub_efistub_image_info
__efistub_efistub_image_info:
0:	.long	_text - .
	.long	__inittext_end - 0b
	.long	_edata - 0b
	.long	_end - 0b
	.long	efi_primary_entry - .
#if defined(CONFIG_EFI_EARLYCON) || defined(CONFIG_SYSFB)
	.long	sysfb_primary_display - .
#else
	.long	0
#endif
