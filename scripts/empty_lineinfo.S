/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 *
 * Empty lineinfo stub for the initial vmlinux link.
 * The real lineinfo is generated from .tmp_vmlinux1 by gen_lineinfo.
 */
	.section .rodata, "a"
	.globl lineinfo_num_entries
	.balign 4
lineinfo_num_entries:
	.long 0
	.globl lineinfo_num_files
	.balign 4
lineinfo_num_files:
	.long 0
	.globl lineinfo_addrs
lineinfo_addrs:
	.globl lineinfo_file_ids
lineinfo_file_ids:
	.globl lineinfo_lines
lineinfo_lines:
	.globl lineinfo_file_offsets
lineinfo_file_offsets:
	.globl lineinfo_filenames_size
	.balign 4
lineinfo_filenames_size:
	.long 0
	.globl lineinfo_filenames
lineinfo_filenames:
