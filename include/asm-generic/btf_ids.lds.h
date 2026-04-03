/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#ifndef __ASM_GENERIC_BTF_IDS_LDS_H
#define __ASM_GENERIC_BTF_IDS_LDS_H

/*
 * Linker script helpers for CONFIG_DEBUG_INFO_BTF .BTF_ids subsections.
 * Input section .BTF_ids.##sfx must match __BTF_IDS_SUBSEC(sfx) in btf_ids.h.
 */
#ifdef CONFIG_DEBUG_INFO_BTF

#define BTF_IDS_SUBSEG(sfx)							\
		KEEP(*(.BTF_ids.##sfx))						\
		__BTF_ids_seg_end_##sfx = .;

#define BTF_IDS_VERIFIER_SUBSEGS

#endif /* CONFIG_DEBUG_INFO_BTF */

#endif /* __ASM_GENERIC_BTF_IDS_LDS_H */
