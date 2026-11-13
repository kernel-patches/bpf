/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2013 Paul Burton <paulburton@kernel.org> */
#ifndef __ASM_INGENIC_SMP_H__
#define __ASM_INGENIC_SMP_H__

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kconfig.h>

#if defined(CONFIG_MACH_JZ4780) && defined(CONFIG_SMP)
int __init register_ingenic_smp_ops(void);
void xburst_secondary_cpu_entry(void);
#else
static inline int register_ingenic_smp_ops(void)
{
	return -ENODEV;
}
#endif

#endif /* __ASM_INGENIC_SMP_H__ */
