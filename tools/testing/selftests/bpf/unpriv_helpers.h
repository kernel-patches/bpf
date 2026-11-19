// SPDX-License-Identifier: GPL-2.0-only

#include <stdbool.h>

#define UNPRIV_SYSCTL "kernel/unprivileged_bpf_disabled"

bool kernel_config_has(const char *entry);
bool kernel_config_disabled(const char *name);
bool get_unpriv_disabled(void);
bool get_unpriv_sysctl_disabled(void);
bool get_unpriv_mitigations_disabled(void);
bool get_kasan_jit_enabled(void);
bool get_kasan_multi_shot_enabled(void);
