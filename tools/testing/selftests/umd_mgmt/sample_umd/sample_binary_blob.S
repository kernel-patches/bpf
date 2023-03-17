/* SPDX-License-Identifier: GPL-2.0 */
	.section .init.rodata, "a"
	.global sample_umh_start
sample_umh_start:
	.incbin "tools/testing/selftests/umd_mgmt/sample_umd/sample_umh"
	.global sample_umh_end
sample_umh_end:
