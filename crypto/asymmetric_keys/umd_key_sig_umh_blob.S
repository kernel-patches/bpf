/* SPDX-License-Identifier: GPL-2.0 */
	.section .init.rodata, "a"
	.global umd_key_umh_start
umd_key_umh_start:
	.incbin "crypto/asymmetric_keys/umd_key_sig_umh"
	.global umd_key_umh_end
umd_key_umh_end:
