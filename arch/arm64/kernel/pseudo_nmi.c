// SPDX-License-Identifier: GPL-2.0-only
/*
 * Runtime pseudo-NMI enable/disable support.
 *
 * Copyright (C) 2026 Puranjay Mohan <puranjay@kernel.org>
 */

#include <linux/debugfs.h>
#include <linux/irqflags.h>
#include <linux/jump_label.h>
#include <linux/mutex.h>
#include <linux/smp.h>
#include <asm-generic/irq_regs.h>

#include <asm/arch_gicv3.h>
#include <asm/cpufeature.h>
#include <asm/daifflags.h>
#include <asm/smp.h>

static DEFINE_MUTEX(pnmi_lock);
static bool pnmi_enabled;

static atomic_t pnmi_parked_cpus;
static atomic_t pnmi_patch_done;

/*
 * IPI handler for remote CPUs during the masking paradigm switch.
 *
 * Remote CPUs park here with IRQs disabled (IPI context), wait for
 * the master to finish patching, then perform the lock-new/unlock-old
 * transition atomically.
 */
static void pnmi_enable_remote(void *data)
{
	struct pt_regs *regs = get_irq_regs();

	atomic_inc(&pnmi_parked_cpus);

	while (!atomic_read(&pnmi_patch_done))
		cpu_relax();
	/* Pairs with smp_wmb() in pnmi_switch_to_pmr() */
	smp_rmb();
	isb();

	gic_write_pmr(GIC_PRIO_IRQOFF);
	write_sysreg(DAIF_PROCCTX, daif);

	/*
	 * kernel_entry ran before the switch and did not save PMR.
	 * kernel_exit will run after and will try to restore it.
	 * Convert the DAIF-format saved state to the correct PMR value
	 * so kernel_exit writes a valid PMR on return.
	 */
	if (regs) {
		if (regs->pstate & PSR_I_BIT)
			regs->pmr = GIC_PRIO_IRQOFF;
		else
			regs->pmr = GIC_PRIO_IRQON;
	}
}

static void pnmi_disable_remote(void *data)
{
	struct pt_regs *regs = get_irq_regs();

	atomic_inc(&pnmi_parked_cpus);

	while (!atomic_read(&pnmi_patch_done))
		cpu_relax();
	/* Pairs with smp_wmb() in pnmi_switch_to_daif() */
	smp_rmb();
	isb();

	asm volatile("msr daifset, #3" ::: "memory");
	gic_write_pmr(GIC_PRIO_IRQON);

	/*
	 * kernel_entry saved PMR but kernel_exit will skip restoring it.
	 * In pNMI mode DAIF.I was clear when IRQs were "disabled" via PMR.
	 * Convert the PMR-format state to DAIF-format by setting PSR.I in
	 * the saved pstate if PMR indicated IRQs were masked.
	 */
	if (regs && regs->pmr != GIC_PRIO_IRQON)
		regs->pstate |= PSR_I_BIT | PSR_F_BIT;
}

static void pnmi_wait_for_park(void)
{
	int expected = num_online_cpus() - 1;

	while (atomic_read(&pnmi_parked_cpus) < expected)
		cpu_relax();
	/* Pairs with atomic_inc() in pnmi_{enable,disable}_remote() */
	smp_rmb();
}

/*
 * Switch the interrupt masking paradigm between DAIF and PMR.
 *
 * The transition must be atomic across all call sites on all CPUs.
 * Remote CPUs are parked via IPI with interrupts disabled while the
 * master CPU patches all static branch sites under jump_label_lock.
 *
 * The lock-new/unlock-old pattern ensures no CPU ever has both masks
 * active simultaneously: we take the new lock before unlocking the
 * old one on each CPU, and all patching completes before any CPU
 * unlocks.
 */
static void pnmi_switch_to_pmr(void)
{
	atomic_set(&pnmi_parked_cpus, 0);
	atomic_set(&pnmi_patch_done, 0);

	jump_label_lock();

	smp_call_function(pnmi_enable_remote, NULL, 0);
	pnmi_wait_for_park();

	local_irq_disable();

	/* Master: lock-new */
	init_gic_priority_masking_cpu(NULL);
	gic_write_pmr(GIC_PRIO_IRQOFF);

	/* Master: patch all sites */
	atomic_set(&arm64_irq_prio_masking.key.enabled, 1);
	jump_label_update_nosync(&arm64_irq_prio_masking.key);

	/* Ensure text patches are visible before releasing parked CPUs */
	smp_wmb();
	atomic_set(&pnmi_patch_done, 1);

	isb();

	/* Master: unlock-old, enable IRQs through new PMR path */
	trace_hardirqs_on();
	write_sysreg(DAIF_PROCCTX, daif);
	gic_write_pmr(GIC_PRIO_IRQON);
	pmr_sync();

	jump_label_unlock();
}

static void pnmi_switch_to_daif(void)
{
	atomic_set(&pnmi_parked_cpus, 0);
	atomic_set(&pnmi_patch_done, 0);

	jump_label_lock();

	smp_call_function(pnmi_disable_remote, NULL, 0);
	pnmi_wait_for_park();

	/* Master: lock-old (disable via both DAIF and PMR for safety) */
	local_irq_disable();
	asm volatile("msr daifset, #3" ::: "memory");

	/* Master: patch all sites */
	atomic_set(&arm64_irq_prio_masking.key.enabled, 0);
	jump_label_update_nosync(&arm64_irq_prio_masking.key);

	/* Ensure text patches are visible before releasing parked CPUs */
	smp_wmb();
	atomic_set(&pnmi_patch_done, 1);

	isb();

	/* Master: unlock-new, enable IRQs through old DAIF path */
	trace_hardirqs_on();
	gic_write_pmr(GIC_PRIO_IRQON);
	write_sysreg(DAIF_PROCCTX, daif);

	jump_label_unlock();
}

static int pseudo_nmi_enable(void)
{
	int ret;

	if (gic_runtime_nmi_forbidden())
		return -ENODEV;

	cpus_read_lock();

	pnmi_switch_to_pmr();
	gic_runtime_enable_nmi();

	ret = ipi_promote_to_nmi();
	if (ret) {
		gic_runtime_disable_nmi();
		pnmi_switch_to_daif();
		cpus_read_unlock();
		return ret;
	}

	cpus_read_unlock();

	pr_info("Pseudo-NMI enabled at runtime\n");
	return 0;
}

static void pseudo_nmi_disable(void)
{
	cpus_read_lock();

	ipi_demote_from_nmi();
	gic_runtime_disable_nmi();
	pnmi_switch_to_daif();

	cpus_read_unlock();

	pr_info("Pseudo-NMI disabled at runtime\n");
}

static ssize_t pnmi_write(struct file *file, const char __user *ubuf,
			   size_t count, loff_t *ppos)
{
	bool val;
	int ret;

	ret = kstrtobool_from_user(ubuf, count, &val);
	if (ret)
		return ret;

	guard(mutex)(&pnmi_lock);

	if (val == pnmi_enabled)
		return count;

	if (val)
		ret = pseudo_nmi_enable();
	else
		pseudo_nmi_disable();

	if (!ret)
		pnmi_enabled = val;

	return ret ?: count;
}

static ssize_t pnmi_read(struct file *file, char __user *ubuf,
			  size_t count, loff_t *ppos)
{
	char buf[4];
	int len;

	len = scnprintf(buf, sizeof(buf), "%d\n", pnmi_enabled);
	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations pnmi_fops = {
	.write	= pnmi_write,
	.read	= pnmi_read,
};

static int __init pseudo_nmi_debugfs_init(void)
{
	struct dentry *dir;

	dir = debugfs_create_dir("pseudo_nmi", NULL);
	debugfs_create_file("enable", 0600, dir, NULL, &pnmi_fops);

	return 0;
}
late_initcall(pseudo_nmi_debugfs_init);
