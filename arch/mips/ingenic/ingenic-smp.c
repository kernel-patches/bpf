// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * XBurst SMP support, based on Paul Burton's CI20 implementation and
 * Zhou Yanjie's 2020 JZ4780 SMP series.
 * Copyright (C) 2013 Paul Burton <paulburton@kernel.org>
 */

#include <linux/clk.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/of.h>
#include <linux/of_clk.h>
#include <linux/sched/task_stack.h>
#include <linux/smp.h>

#include <asm/addrspace.h>
#include <asm/irq_cpu.h>
#include <asm/mipsregs.h>
#include <asm/r4kcache.h>
#include <asm/smp-ops.h>

#include <asm/ingenic-smp.h>

#define read_c0_corectrl()	__read_32bit_c0_register($12, 2)
#define write_c0_corectrl(val)	__write_32bit_c0_register($12, 2, val)
#define read_c0_corestatus()	__read_32bit_c0_register($12, 3)
#define write_c0_corestatus(val)	__write_32bit_c0_register($12, 3, val)
#define read_c0_reim()		__read_32bit_c0_register($12, 4)
#define write_c0_reim(val)	__write_32bit_c0_register($12, 4, val)
#define read_c0_mailbox0()	__read_32bit_c0_register($20, 0)
#define write_c0_mailbox0(val)	__write_32bit_c0_register($20, 0, val)
#define read_c0_mailbox1()	__read_32bit_c0_register($20, 1)
#define write_c0_mailbox1(val)	__write_32bit_c0_register($20, 1, val)

#define XBURST_MBOX_IRQ		(MIPS_CPU_IRQ_BASE + 3)
#define CORECTRL_SWRST(cpu)	BIT(cpu)
#define CORECTRL_RPC(cpu)	BIT(8 + (cpu))
#define CORESTATUS_MIRQ(cpu)	BIT(cpu)
#define REIM_ENTRY		GENMASK(31, 16)
#define REIM_MBOXIRQ(cpu)	BIT(cpu)

static struct clk *cpu1_clock;
static DEFINE_RAW_SPINLOCK(smp_lock);

/* Referenced by the uncached secondary CPU reset entry. */
unsigned long xburst_cpu_entry_sp;
unsigned long xburst_cpu_entry_gp;

static irqreturn_t xburst_mbox_interrupt(int irq, void *dev_id)
{
	unsigned int cpu = cpu_logical_map(smp_processor_id());
	u32 action, status;

	raw_spin_lock(&smp_lock);
	if (cpu == 0) {
		action = read_c0_mailbox0();
		write_c0_mailbox0(0);
	} else {
		action = read_c0_mailbox1();
		write_c0_mailbox1(0);
	}

	status = read_c0_corestatus();
	write_c0_corestatus(status & ~CORESTATUS_MIRQ(cpu));
	irq_disable_hazard();
	raw_spin_unlock(&smp_lock);

	if (action & SMP_RESCHEDULE_YOURSELF)
		scheduler_ipi();
	if (action & SMP_CALL_FUNCTION)
		generic_smp_call_function_interrupt();

	return IRQ_HANDLED;
}

static void __init xburst_smp_setup(void)
{
	struct device_node *np;
	u32 entry, reim;
	unsigned int cpu = 0;
	u64 hwid;

	for_each_of_cpu_node(np) {
		hwid = of_get_cpu_hwid(np, 0);
		if (!of_device_is_available(np) ||
		    hwid >= ARRAY_SIZE(__cpu_number_map))
			continue;
		if (cpu >= nr_cpu_ids) {
			of_node_put(np);
			break;
		}
		__cpu_number_map[hwid] = cpu;
		__cpu_logical_map[cpu] = hwid;
		set_cpu_possible(cpu, true);
		set_cpu_present(cpu, true);
		cpu_set_core(&cpu_data[cpu], hwid);
		cpu++;
	}

	/* Program the shared reset vector with mailbox delivery masked. */
	reim = read_c0_reim();
	reim &= ~(REIM_MBOXIRQ(0) | REIM_MBOXIRQ(1));
	write_c0_reim(reim);
	write_c0_mailbox0(0);
	write_c0_mailbox1(0);
	write_c0_corestatus(0);

	entry = CKSEG1ADDR((unsigned long)xburst_secondary_cpu_entry);
	write_c0_reim((reim & ~REIM_ENTRY) | (entry & REIM_ENTRY));
}

static void __init xburst_prepare_cpus(unsigned int max_cpus)
{
	struct device_node *np;
	u32 reim;
	int ret;

	ret = request_irq(XBURST_MBOX_IRQ, xburst_mbox_interrupt,
			  IRQF_PERCPU | IRQF_NO_THREAD, "core mailbox", NULL);
	if (ret) {
		pr_err("XBurst: cannot request mailbox IRQ: %d\n", ret);
		return;
	}

	reim = read_c0_reim();
	write_c0_reim(reim | REIM_MBOXIRQ(0));
	set_c0_status(STATUSF_IP3);
	irq_enable_hazard();

	if (!cpu_possible(1))
		return;

	np = of_get_cpu_node(1, NULL);
	cpu1_clock = of_clk_get(np, 0);
	of_node_put(np);
	if (IS_ERR(cpu1_clock)) {
		pr_err("XBurst: cannot get CPU1 clock: %ld\n",
		       PTR_ERR(cpu1_clock));
		return;
	}

	ret = clk_prepare(cpu1_clock);
	if (ret) {
		clk_put(cpu1_clock);
		cpu1_clock = ERR_PTR(ret);
		pr_err("XBurst: cannot prepare CPU1 clock: %d\n", ret);
	}
}

static int xburst_boot_secondary(int cpu, struct task_struct *idle)
{
	unsigned long flags;
	u32 ctrl;
	int ret;

	if (cpu_logical_map(cpu) != 1 || IS_ERR_OR_NULL(cpu1_clock))
		return -ENODEV;

	raw_spin_lock_irqsave(&smp_lock, flags);
	ctrl = read_c0_corectrl() | CORECTRL_SWRST(1) | CORECTRL_RPC(1);
	write_c0_corectrl(ctrl);
	back_to_back_c0_hazard();
	raw_spin_unlock_irqrestore(&smp_lock, flags);

	ret = clk_enable(cpu1_clock);
	if (ret)
		return ret;

	xburst_cpu_entry_sp = __KSTK_TOS(idle);
	xburst_cpu_entry_gp = (unsigned long)task_thread_info(idle);
	/* Publish bootstrap state before CPU1 starts using its private cache. */
	r4k_blast_dcache();
	/* Complete cache writeback before releasing reset. */
	mb();
	raw_spin_lock_irqsave(&smp_lock, flags);
	ctrl = read_c0_corectrl();
	write_c0_corectrl(ctrl & ~CORECTRL_SWRST(1));
	back_to_back_c0_hazard();
	raw_spin_unlock_irqrestore(&smp_lock, flags);
	return 0;
}

static void xburst_init_secondary(void)
{
	clear_c0_status(ST0_IM);
	irq_disable_hazard();
}

static void xburst_smp_finish(void)
{
	unsigned int cpu = cpu_logical_map(smp_processor_id());
	u32 reim;

	raw_spin_lock(&smp_lock);
	reim = read_c0_reim();
	write_c0_reim(reim | REIM_MBOXIRQ(cpu));
	raw_spin_unlock(&smp_lock);

	change_c0_status(ST0_IM, STATUSF_IP3 | STATUSF_IP2 |
			 STATUSF_IP1 | STATUSF_IP0);
	irq_enable_hazard();
	local_irq_enable();
}

static void xburst_send_ipi_locked(int cpu, unsigned int action)
{
	if (cpu_logical_map(cpu) == 0)
		write_c0_mailbox0(read_c0_mailbox0() | action);
	else
		write_c0_mailbox1(read_c0_mailbox1() | action);
	back_to_back_c0_hazard();
}

static void xburst_send_ipi_single(int cpu, unsigned int action)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&smp_lock, flags);
	xburst_send_ipi_locked(cpu, action);
	raw_spin_unlock_irqrestore(&smp_lock, flags);
}

static void xburst_send_ipi_mask(const struct cpumask *mask, unsigned int action)
{
	unsigned long flags;
	int cpu;

	raw_spin_lock_irqsave(&smp_lock, flags);
	for_each_cpu(cpu, mask)
		xburst_send_ipi_locked(cpu, action);
	raw_spin_unlock_irqrestore(&smp_lock, flags);
}

static int __maybe_unused xburst_cpu_disable(void)
{
	/* CPU teardown and restart are not supported yet. */
	return -EOPNOTSUPP;
}

static const struct plat_smp_ops xburst_smp_ops = {
	.send_ipi_single = xburst_send_ipi_single,
	.send_ipi_mask = xburst_send_ipi_mask,
	.init_secondary = xburst_init_secondary,
	.smp_finish = xburst_smp_finish,
	.boot_secondary = xburst_boot_secondary,
	.smp_setup = xburst_smp_setup,
	.prepare_cpus = xburst_prepare_cpus,
#ifdef CONFIG_HOTPLUG_CPU
	.cpu_disable = xburst_cpu_disable,
#endif
};

int __init register_ingenic_smp_ops(void)
{
	if (!of_machine_is_compatible("ingenic,jz4780"))
		return -ENODEV;

	register_smp_ops(&xburst_smp_ops);
	return 0;
}
