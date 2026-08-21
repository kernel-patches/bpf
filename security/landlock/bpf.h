/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - LSM policy object hooks
 *
 * Copyright © 2026 Justin Suess <utilityemal77@gmail.com>
 */

#ifndef _SECURITY_LANDLOCK_BPF_H
#define _SECURITY_LANDLOCK_BPF_H

#include <linux/init.h>

#ifdef CONFIG_BPF_LSM
__init void landlock_add_bpf_hooks(void);
#else /* CONFIG_BPF_LSM */
static inline void landlock_add_bpf_hooks(void)
{
}
#endif /* CONFIG_BPF_LSM */

#endif /* _SECURITY_LANDLOCK_BPF_H */
