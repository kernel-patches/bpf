// SPDX-License-Identifier: GPL-2.0
/*
 * Test module: spin with IRQs disabled on a specific CPU.
 *
 * Usage:
 *   insmod test_irqoff.ko cpu=2 duration_ms=5000
 *
 * A kthread is pinned to the given CPU and spins with IRQs disabled
 * for duration_ms milliseconds. The insmod returns immediately.
 * While spinning, only an NMI can interrupt the CPU.
 * Use sysrq-l from another terminal to test.
 */

#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/timekeeping.h>
#include <linux/nmi.h>

static int cpu = 1;
module_param(cpu, int, 0444);

static int duration_ms = 5000;
module_param(duration_ms, int, 0444);

static noinline void simulated_hard_lockup(ktime_t end)
{
	while (ktime_before(ktime_get(), end))
		cpu_relax();
}

static int irqoff_thread(void *data)
{
	unsigned long flags;
	ktime_t end;

	pr_info("test_irqoff: CPU%d disabling IRQs for %d ms NOW\n",
		smp_processor_id(), duration_ms);

	end = ktime_add_ms(ktime_get(), duration_ms);

	local_irq_save(flags);
	simulated_hard_lockup(end);
	local_irq_restore(flags);

	pr_info("test_irqoff: CPU%d done\n", smp_processor_id());
	return 0;
}

static int __init test_irqoff_init(void)
{
	struct task_struct *t;

	if (cpu >= nr_cpu_ids || !cpu_online(cpu)) {
		pr_err("test_irqoff: CPU%d not online\n", cpu);
		return -EINVAL;
	}

	t = kthread_run_on_cpu(irqoff_thread, NULL, cpu, "irqoff/%d");
	if (IS_ERR(t))
		return PTR_ERR(t);

	return 0;
}

static void __exit test_irqoff_exit(void)
{
}

module_init(test_irqoff_init);
module_exit(test_irqoff_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test IRQ-disabled spin for NMI testing");
