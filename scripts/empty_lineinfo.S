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
	.globl lineinfo_num_blocks
	.balign 4
lineinfo_num_blocks:
	.long 0
	.globl lineinfo_block_addrs
lineinfo_block_addrs:
	.globl lineinfo_block_offsets
lineinfo_block_offsets:
	.globl lineinfo_data_size
	.balign 4
lineinfo_data_size:
	.long 0
	.globl lineinfo_data
lineinfo_data:
	.globl lineinfo_file_offsets
lineinfo_file_offsets:
	.globl lineinfo_filenames_size
	.balign 4
lineinfo_filenames_size:
	.long 0
	.globl lineinfo_filenames
lineinfo_filenames:
