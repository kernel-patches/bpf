// SPDX-License-Identifier: GPL-2.0-only

#include <stdbool.h>

#define UNPRIV_SYSCTL "kernel/unprivileged_bpf_disabled"

/*
 * Return true if /proc/sys/kernel/unprivileged_bpf_disabled is non-zero,
 * or if kernel-side CPU vulnerability mitigations are disabled.
 */
int get_unpriv_disabled(void);
