// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2025 Google LLC.
 */

#include <linux/fs.h>
#include <linux/bpf_lsm.h>

/*
 * A strong definition for BPF LSM hook mmap_file(). Differs from its weak
 * definition counterpart only through its of the __nullable suffix on its
 * struct file pointer parameter. Annotating with a __nullable suffix allows the
 * BPF verifier to enforce stricter NULL pointer checking in cases where a BPF
 * program is attempting to access the BPF program context.
 */
int bpf_lsm_mmap_file(struct file *file__nullable, unsigned long reqprot,
		      unsigned long prot, unsigned long flags)
{
	return 0;
}
