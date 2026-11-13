/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2000, 2001, 2002, 2003 Broadcom Corporation
 */

#ifndef _ASM_SIBYTE_SB1250_H
#define _ASM_SIBYTE_SB1250_H

/*
 * yymmddpp: year, month, day, patch.
 * should sync with Makefile EXTRAVERSION
 */
#define SIBYTE_RELEASE 0x02111403

#define SB1250_NR_IRQS 64

#define BCM1480_NR_IRQS			128
#define BCM1480_NR_IRQS_HALF		64

#define SB1250_DUART_MINOR_BASE		64

#ifndef __ASSEMBLER__

#include <asm/addrspace.h>

/* For revision/pass information */
#include <asm/sibyte/sb1250_scd.h>
#include <asm/sibyte/bcm1480_scd.h>
extern unsigned int sb1_pass;
extern unsigned int soc_pass;
extern unsigned int soc_type;
extern unsigned int periph_rev;
extern unsigned int zbbus_mhz;

void sb1_cache_error(void);

#ifdef CONFIG_SIBYTE_BUS_WATCHER
void check_bus_watcher(void);
#endif

int sb1250_m3_workaround_needed(void);
void sb1250_setup(void);
void sb1250_clockevent_init(void);
void sb1250_clocksource_init(void);
void sb1250_mailbox_interrupt(void);

extern void sb1250_mask_irq(int cpu, int irq);
extern void sb1250_unmask_irq(int cpu, int irq);

void bcm1480_setup(void);
void sb1480_clockevent_init(void);
void sb1480_clocksource_init(void);
void bcm1480_mailbox_interrupt(void);

extern void bcm1480_time_init(void);
extern void bcm1480_mask_irq(int cpu, int irq);
extern void bcm1480_unmask_irq(int cpu, int irq);

#define AT_spin \
	__asm__ __volatile__ (		\
		".set noat\n"		\
		"li $at, 0\n"		\
		"1: beqz $at, 1b\n"	\
		".set at\n"		\
		)

#endif

#define IOADDR(a) ((void __iomem *)(IO_BASE + (a)))

#endif
