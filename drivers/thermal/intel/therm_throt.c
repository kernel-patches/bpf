// SPDX-License-Identifier: GPL-2.0-only
/*
 * Thermal throttle event support code (such as syslog messaging and rate
 * limiting) that was factored out from x86_64 (mce_intel.c) and i386 (p4.c).
 *
 * This allows consistent reporting of CPU thermal throttle events.
 *
 * Maintains a counter in /sys that keeps track of the number of thermal
 * events, such that the user knows how bad the thermal problem might be
 * (since the logging to syslog is rate limited).
 *
 * Author: Dmitriy Zavin (dmitriyz@google.com)
 *
 * Credits: Adapted from Zwane Mwaikambo's original code in mce_intel.c.
 *          Inspired by Ross Biro's and Al Borchers' counter code.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/sched/isolation.h>
#include <linux/syscore_ops.h>
#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/export.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/sysfs.h>
#include <linux/cpu.h>

#include <asm/processor.h>
#include <asm/thermal.h>
#include <asm/traps.h>
#include <asm/apic.h>
#include <asm/irq.h>
#include <asm/msr.h>

#include "intel_hfi.h"
#include "thermal_interrupt.h"

/* How long to wait between reporting thermal events */
#define CHECK_INTERVAL		(300 * HZ)

#define THERMAL_THROTTLING_EVENT	0
#define POWER_LIMIT_EVENT		1

/**
 * struct _thermal_state - Represent the current thermal event state
 * @next_check:			Stores the next timestamp, when it is allowed
 *				to log the next warning message.
 * @last_interrupt_time:	Stores the timestamp for the last threshold
 *				high event.
 * @therm_work:			Delayed workqueue structure
 * @count:			Stores the current running count for thermal
 *				or power threshold interrupts.
 * @last_count:			Stores the previous running count for thermal
 *				or power threshold interrupts.
 * @max_time_ms:		This shows the maximum amount of time CPU was
 *				in throttled state for a single thermal
 *				threshold high to low state.
 * @total_time_ms:		This is a cumulative time during which CPU was
 *				in the throttled state.
 * @rate_control_active:	Set when a throttling message is logged.
 *				This is used for the purpose of rate-control.
 * @new_event:			Stores the last high/low status of the
 *				THERM_STATUS_PROCHOT or
 *				THERM_STATUS_POWER_LIMIT.
 * @level:			Stores whether this _thermal_state instance is
 *				for a CORE level or for PACKAGE level.
 * @sample_index:		Index for storing the next sample in the buffer
 *				temp_samples[].
 * @sample_count:		Total number of samples collected in the buffer
 *				temp_samples[].
 * @average:			The last moving average of temperature samples
 * @baseline_temp:		Temperature at which thermal threshold high
 *				interrupt was generated.
 * @temp_samples:		Storage for temperature samples to calculate
 *				moving average.
 *
 * This structure is used to represent data related to thermal state for a CPU.
 * There is a separate storage for core and package level for each CPU.
 */
struct _thermal_state {
	u64			next_check;
	u64			last_interrupt_time;
	struct delayed_work	therm_work;
	unsigned long		count;
	unsigned long		last_count;
	unsigned long		max_time_ms;
	unsigned long		total_time_ms;
	bool			rate_control_active;
	bool			new_event;
	u8			level;
	u8			sample_index;
	u8			sample_count;
	u8			average;
	u8			baseline_temp;
	u8			temp_samples[3];
};

struct thermal_state {
	struct _thermal_state core_throttle;
	struct _thermal_state core_power_limit;
	struct _thermal_state package_throttle;
	struct _thermal_state package_power_limit;
	struct _thermal_state core_thresh0;
	struct _thermal_state core_thresh1;
	struct _thermal_state pkg_thresh0;
	struct _thermal_state pkg_thresh1;
};

/* Callback to handle core threshold interrupts */
int (*platform_thermal_notify)(__u64 msr_val);
EXPORT_SYMBOL(platform_thermal_notify);

/* Callback to handle core package threshold_interrupts */
int (*platform_thermal_package_notify)(__u64 msr_val);
EXPORT_SYMBOL_GPL(platform_thermal_package_notify);

/* Callback support of rate control, return true, if
 * callback has rate control */
bool (*platform_thermal_package_rate_control)(void);
EXPORT_SYMBOL_GPL(platform_thermal_package_rate_control);


static DEFINE_PER_CPU(struct thermal_state, thermal_state);

static atomic_t therm_throt_en	= ATOMIC_INIT(0);

static u32 lvtthmr_init __read_mostly;

#ifdef CONFIG_SYSFS
#define define_therm_throt_device_one_ro(_name)				\
	static DEVICE_ATTR(_name, 0444,					\
			   therm_throt_device_show_##_name,		\
				   NULL)				\

#define define_therm_throt_device_show_func(event, name)		\
									\
static ssize_t therm_throt_device_show_##event##_##name(		\
			struct device *dev,				\
			struct device_attribute *attr,			\
			char *buf)					\
{									\
	unsigned int cpu = dev->id;					\
	ssize_t ret;							\
									\
	preempt_disable();	/* CPU hotplug */			\
	if (cpu_online(cpu)) {						\
		ret = sysfs_emit(buf, "%lu\n",				\
			per_cpu(thermal_state, cpu).event.name);	\
	} else								\
		ret = 0;						\
	preempt_enable();						\
									\
	return ret;							\
}

define_therm_throt_device_show_func(core_throttle, count);
define_therm_throt_device_one_ro(core_throttle_count);

define_therm_throt_device_show_func(core_power_limit, count);
define_therm_throt_device_one_ro(core_power_limit_count);

define_therm_throt_device_show_func(package_throttle, count);
define_therm_throt_device_one_ro(package_throttle_count);

define_therm_throt_device_show_func(package_power_limit, count);
define_therm_throt_device_one_ro(package_power_limit_count);

define_therm_throt_device_show_func(core_throttle, max_time_ms);
define_therm_throt_device_one_ro(core_throttle_max_time_ms);

define_therm_throt_device_show_func(package_throttle, max_time_ms);
define_therm_throt_device_one_ro(package_throttle_max_time_ms);

define_therm_throt_device_show_func(core_throttle, total_time_ms);
define_therm_throt_device_one_ro(core_throttle_total_time_ms);

define_therm_throt_device_show_func(package_throttle, total_time_ms);
define_therm_throt_device_one_ro(package_throttle_total_time_ms);

static struct attribute *thermal_throttle_attrs[] = {
	&dev_attr_core_throttle_count.attr,
	&dev_attr_core_throttle_max_time_ms.attr,
	&dev_attr_core_throttle_total_time_ms.attr,
	NULL
};

static const struct attribute_group thermal_attr_group = {
	.attrs	= thermal_throttle_attrs,
	.name	= "thermal_throttle"
};
#endif /* CONFIG_SYSFS */

#define THERM_THROT_POLL_INTERVAL	HZ
#define THERM_STATUS_PROCHOT_LOG	BIT(1)

static u64 therm_intr_core_clear_mask;
static u64 therm_intr_pkg_clear_mask;

static void thermal_intr_init_core_clear_mask(void)
{
	if (therm_intr_core_clear_mask)
		return;

	/*
	 * Reference: Intel SDM  Volume 4
	 * "Table 2-2. IA-32 Architectural MSRs", MSR 0x19C
	 * IA32_THERM_STATUS.
	 */

	/*
	 * Bit 1, 3, 5: CPUID.01H:EDX[22] = 1. This driver will not
	 * enable interrupts, when 0 as it checks for X86_FEATURE_ACPI.
	 */
	therm_intr_core_clear_mask = (BIT(1) | BIT(3) | BIT(5));

	/*
	 * Bit 7 and 9: Thermal Threshold #1 and #2 log
	 * If CPUID.01H:ECX[8] = 1
	 */
	if (boot_cpu_has(X86_FEATURE_TM2))
		therm_intr_core_clear_mask |= (BIT(7) | BIT(9));

	/* Bit 11: Power Limitation log (R/WC0) If CPUID.06H:EAX[4] = 1 */
	if (boot_cpu_has(X86_FEATURE_PLN))
		therm_intr_core_clear_mask |= BIT(11);

	/*
	 * Bit 13: Current Limit log (R/WC0) If CPUID.06H:EAX[7] = 1
	 * Bit 15: Cross Domain Limit log (R/WC0) If CPUID.06H:EAX[7] = 1
	 */
	if (boot_cpu_has(X86_FEATURE_HWP))
		therm_intr_core_clear_mask |= (BIT(13) | BIT(15));
}

static void thermal_intr_init_pkg_clear_mask(void)
{
	if (therm_intr_pkg_clear_mask)
		return;

	/*
	 * Reference: Intel SDM  Volume 4
	 * "Table 2-2. IA-32 Architectural MSRs", MSR 0x1B1
	 * IA32_PACKAGE_THERM_STATUS.
	 */

	/* All bits except BITs 25 and 26 depend on CPUID.06H: EAX[6] = 1 */
	if (boot_cpu_has(X86_FEATURE_PTS))
		therm_intr_pkg_clear_mask = (BIT(1) | BIT(3) | BIT(5) | BIT(7) | BIT(9) | BIT(11));

	/*
	 * Intel SDM Volume 1: Thermal and Power Management Leaf
	 * Bit 26: CPUID.06H: EAX[19] = 1
	 */
	if (boot_cpu_has(X86_FEATURE_HFI))
		therm_intr_pkg_clear_mask |= BIT(26);

	/*
	 * Intel SDM Volume 1: Thermal and Power Management Leaf
	 * Bit 25: CPUID.06H: EAX[24] = 1
	 */
	if (boot_cpu_has(X86_FEATURE_DPTI))
		therm_intr_pkg_clear_mask |= BIT(25);
}

/*
 * Clear the bits in package thermal status register for bit = 1
 * in bitmask
 */
void thermal_clear_package_intr_status(int level, u64 bit_mask)
{
	u64 msr_val;
	int msr;

	if (level == CORE_LEVEL) {
		msr  = MSR_IA32_THERM_STATUS;
		msr_val = therm_intr_core_clear_mask;
	} else {
		msr  = MSR_IA32_PACKAGE_THERM_STATUS;
		msr_val = therm_intr_pkg_clear_mask;
	}

	msr_val &= ~bit_mask;
	wrmsrq(msr, msr_val);
}
EXPORT_SYMBOL_GPL(thermal_clear_package_intr_status);

static void get_therm_status(int level, bool *proc_hot, u8 *temp)
{
	int msr;
	u64 msr_val;

	if (level == CORE_LEVEL)
		msr = MSR_IA32_THERM_STATUS;
	else
		msr = MSR_IA32_PACKAGE_THERM_STATUS;

	rdmsrq(msr, msr_val);
	if (msr_val & THERM_STATUS_PROCHOT_LOG)
		*proc_hot = true;
	else
		*proc_hot = false;

	*temp = (msr_val >> 16) & 0x7F;
}

static void __maybe_unused throttle_active_work(struct work_struct *work)
{
	struct _thermal_state *state = container_of(to_delayed_work(work),
						struct _thermal_state, therm_work);
	unsigned int i, avg, this_cpu = smp_processor_id();
	u64 now = get_jiffies_64();
	bool hot;
	u8 temp;

	get_therm_status(state->level, &hot, &temp);
	/* temperature value is offset from the max so lesser means hotter */
	if (!hot && temp > state->baseline_temp) {
		if (state->rate_control_active)
			pr_info("CPU%d: %s temperature/speed normal (total events = %lu)\n",
				this_cpu,
				state->level == CORE_LEVEL ? "Core" : "Package",
				state->count);

		state->rate_control_active = false;
		return;
	}

	if (time_before64(now, state->next_check) &&
			  state->rate_control_active)
		goto re_arm;

	state->next_check = now + CHECK_INTERVAL;

	if (state->count != state->last_count) {
		/* There was one new thermal interrupt */
		state->last_count = state->count;
		state->average = 0;
		state->sample_count = 0;
		state->sample_index = 0;
	}

	state->temp_samples[state->sample_index] = temp;
	state->sample_count++;
	state->sample_index = (state->sample_index + 1) % ARRAY_SIZE(state->temp_samples);
	if (state->sample_count < ARRAY_SIZE(state->temp_samples))
		goto re_arm;

	avg = 0;
	for (i = 0; i < ARRAY_SIZE(state->temp_samples); ++i)
		avg += state->temp_samples[i];

	avg /= ARRAY_SIZE(state->temp_samples);

	if (state->average > avg) {
		pr_warn("CPU%d: %s temperature is above threshold, cpu clock is throttled (total events = %lu)\n",
			this_cpu,
			state->level == CORE_LEVEL ? "Core" : "Package",
			state->count);
		state->rate_control_active = true;
	}

	state->average = avg;

re_arm:
	thermal_clear_package_intr_status(state->level, THERM_STATUS_PROCHOT_LOG);
	schedule_delayed_work_on(this_cpu, &state->therm_work, THERM_THROT_POLL_INTERVAL);
}

/***
 * therm_throt_process - Process thermal throttling event from interrupt
 * @curr: Whether the condition is current or not (boolean), since the
 *        thermal interrupt normally gets called both when the thermal
 *        event begins and once the event has ended.
 *
 * This function is called by the thermal interrupt after the
 * IRQ has been acknowledged.
 *
 * It will take care of rate limiting and printing messages to the syslog.
 */
static void therm_throt_process(bool new_event, int event, int level)
{
	struct _thermal_state *state;
	unsigned int this_cpu = smp_processor_id();
	bool old_event;
	u64 now;
	struct thermal_state *pstate = &per_cpu(thermal_state, this_cpu);

	now = get_jiffies_64();
	if (level == CORE_LEVEL) {
		if (event == THERMAL_THROTTLING_EVENT)
			state = &pstate->core_throttle;
		else if (event == POWER_LIMIT_EVENT)
			state = &pstate->core_power_limit;
		else
			return;
	} else if (level == PACKAGE_LEVEL) {
		if (event == THERMAL_THROTTLING_EVENT)
			state = &pstate->package_throttle;
		else if (event == POWER_LIMIT_EVENT)
			state = &pstate->package_power_limit;
		else
			return;
	} else
		return;

	old_event = state->new_event;
	state->new_event = new_event;

	if (new_event)
		state->count++;

	if (event != THERMAL_THROTTLING_EVENT)
		return;

	if (new_event && !state->last_interrupt_time) {
		bool hot;
		u8 temp;

		get_therm_status(state->level, &hot, &temp);
		/*
		 * Ignore short temperature spike as the system is not close
		 * to PROCHOT. 10C offset is large enough to ignore. It is
		 * already dropped from the high threshold temperature.
		 */
		if (temp > 10)
			return;

		state->baseline_temp = temp;
		state->last_interrupt_time = now;
		schedule_delayed_work_on(this_cpu, &state->therm_work, THERM_THROT_POLL_INTERVAL);
	} else if (old_event && state->last_interrupt_time) {
		unsigned long throttle_time;

		throttle_time = jiffies_delta_to_msecs(now - state->last_interrupt_time);
		if (throttle_time > state->max_time_ms)
			state->max_time_ms = throttle_time;
		state->total_time_ms += throttle_time;
		state->last_interrupt_time = 0;
	}
}

static int thresh_event_valid(int level, int event)
{
	struct _thermal_state *state;
	unsigned int this_cpu = smp_processor_id();
	struct thermal_state *pstate = &per_cpu(thermal_state, this_cpu);
	u64 now = get_jiffies_64();

	if (level == PACKAGE_LEVEL)
		state = (event == 0) ? &pstate->pkg_thresh0 :
						&pstate->pkg_thresh1;
	else
		state = (event == 0) ? &pstate->core_thresh0 :
						&pstate->core_thresh1;

	if (time_before64(now, state->next_check))
		return 0;

	state->next_check = now + CHECK_INTERVAL;

	return 1;
}

static bool int_pln_enable;
static int __init int_pln_enable_setup(char *s)
{
	int_pln_enable = true;

	return 1;
}
__setup("int_pln_enable", int_pln_enable_setup);

#ifdef CONFIG_SYSFS
static int dpti_wait_for_ack(void)
{
	unsigned int count = 15000;
	u64 msr_val;

	/*
	 * Hardware acknowledges the directed interrupt setup in 10ms or less.
	 * Wait 15ms to be safe.
	 */
	do {
		rdmsrq(MSR_IA32_PACKAGE_THERM_STATUS, msr_val);
		udelay(1);
	} while (!(msr_val & PACKAGE_THERM_STATUS_DPTI_ACK) && --count);

	if (!count)
		return -ETIMEDOUT;

	thermal_clear_package_intr_status(PACKAGE_LEVEL,
					  PACKAGE_THERM_STATUS_DPTI_ACK);

	return 0;
}

static void dpti_config_this_cpu(bool enable)
{
	u64 msr_val;

	rdmsrq(MSR_IA32_THERM_INTERRUPT, msr_val);

	if (enable)
		msr_val |= THERM_INT_DPTI_ENABLE;
	else
		msr_val &= ~THERM_INT_DPTI_ENABLE;

	wrmsrq(MSR_IA32_THERM_INTERRUPT, msr_val);
}

static void dpti_clear_ipi(void *unused)
{
	dpti_config_this_cpu(false);
}

static void dpti_clear_on_cpu(unsigned int cpu)
{
	smp_call_function_single(cpu, dpti_clear_ipi, NULL, true);
}

/* The unused argument matches the smp_call_on_cpu() callback signature. */
static int dpti_program_this_cpu(void *unused)
{
	int ret;

	thermal_clear_package_intr_status(PACKAGE_LEVEL,
					  PACKAGE_THERM_STATUS_DPTI_ACK);

	dpti_config_this_cpu(true);
	ret = dpti_wait_for_ack();
	if (!ret)
		return 0;

	/* Undo the enable on failure, leaving the package as it was before. */
	dpti_config_this_cpu(false);

	return ret;
}

/*
 * MSR_IA32_PACKAGE_THERM_STATUS is package-scoped, so the acknowledgment must
 * be polled on the same package. Run a worker bound to @cpu: it cannot be
 * migrated and may wait for the acknowledgment for as long as 15ms.
 */
static int dpti_program_on_cpu(unsigned int cpu)
{
	lockdep_assert_cpus_held();

	return smp_call_on_cpu(cpu, dpti_program_this_cpu, NULL, false);
}

/**
 * struct dpti_pkg - Per-package DPTI state
 * @owner:	CPU currently programmed to receive the package-level
 *		interrupt, or nr_cpu_ids when the package has no owner.
 * @pin:	CPU the user requested as the owner, or nr_cpu_ids for
 *		automatic selection. A pinned CPU overrides the automatic
 *		selection whenever it is online.
 */
struct dpti_pkg {
	unsigned int owner;
	unsigned int pin;
};

/*
 * Serializes updates to dpti_pkgs[] and dpti_shut_down. To avoid deadlock, a
 * path that needs both this mutex and the CPU hotplug lock always takes the
 * hotplug lock first.
 */
static DEFINE_MUTEX(dpti_mutex);

static struct dpti_pkg *dpti_pkgs;

/*
 * Set under dpti_mutex by the syscore shutdown callback before it disables
 * DPTI, so that no owner update enables it again on the way to kexec.
 */
static bool dpti_shut_down;

/*
 * Cleared once the hotplug callbacks are registered: at least one CPU
 * attempted the setup by then, and the hardware is assumed sane from that
 * point on.
 */
static bool dpti_in_boot __ro_after_init = true;

static bool dpti_supported(void)
{
	if (!boot_cpu_has(X86_FEATURE_DPTI))
		return false;

	if (!dpti_pkgs)
		return false;

	return true;
}

/* @pkg_id may be NULL for a caller that only validates @cpu. */
static int dpti_lookup_pkg_id(unsigned int cpu, u16 *pkg_id)
{
	u16 id;

	if (!dpti_supported())
		return -ENODEV;

	id = topology_logical_package_id(cpu);
	if (id >= topology_max_packages())
		return -ENODEV;

	if (pkg_id)
		*pkg_id = id;

	return 0;
}

/* For callers already past dpti_lookup_pkg_id(). */
static struct dpti_pkg *dpti_pkg_of_cpu_nocheck(unsigned int cpu)
{
	return &dpti_pkgs[topology_logical_package_id(cpu)];
}

/*
 * Reads dpti_pkgs[] without dpti_mutex: the syscore callers run with
 * interrupts disabled on the only online CPU.
 */
static bool dpti_cpu_is_owner(unsigned int cpu)
{
	u16 pkg_id;

	if (dpti_lookup_pkg_id(cpu, &pkg_id))
		return false;

	return dpti_pkgs[pkg_id].owner == cpu;
}

/*
 * Must be called with cpu_hotplug_lock held to prevent CPUs from going offline
 * while iterating through packages and interrupts must be enabled to avoid
 * deadlocks in SMP function calls. The syscore shutdown callback also calls
 * this function, but runs with CPU hotplug disabled (and interrupts enabled).
 */
static void dpti_clear_all(void)
{
	int i;

	if (!dpti_supported())
		return;

	guard(mutex)(&dpti_mutex);

	/*
	 * No need to reset the owners: callers free dpti_pkgs[] or have shut
	 * DPTI down.
	 */
	for (i = 0; i < topology_max_packages(); i++) {
		unsigned int owner = dpti_pkgs[i].owner;

		if (owner == nr_cpu_ids)
			continue;

		dpti_clear_on_cpu(owner);
	}
}

/**
 * enum dpti_rank - How suitable a CPU is as a DPTI owner
 * @DPTI_RANK_NONE:		No eligible CPU.
 * @DPTI_RANK_ISOLATED:		nohz_full-isolated (last resort).
 * @DPTI_RANK_HOUSEKEEPING:	Not isolated (ideal automatic choice).
 * @DPTI_RANK_PINNED:		Explicitly requested by the user; overrides any
 *				automatic choice.
 *
 * Higher is better; the selection picks the highest-ranked online CPU in the
 * package.
 */
enum dpti_rank {
	DPTI_RANK_NONE,
	DPTI_RANK_ISOLATED,
	DPTI_RANK_HOUSEKEEPING,
	DPTI_RANK_PINNED,
};

static enum dpti_rank dpti_cpu_rank(unsigned int cpu)
{
	/*
	 * Prefer a HK_TYPE_KERNEL_NOISE CPU to avoid disturbing nohz_full
	 * isolated CPUs. The mask is boot-static. No locking needed.
	 */
	if (housekeeping_cpu(cpu, HK_TYPE_KERNEL_NOISE))
		return DPTI_RANK_HOUSEKEEPING;

	return DPTI_RANK_ISOLATED;
}

/*
 * Select the owner of the package-level thermal interrupt for @pkg_cpu's
 * package. @skip is excluded from the selection (e.g., if it is going offline).
 * @rank receives the rank of the selected CPU.
 *
 * A user-pinned CPU takes precedence whenever it is online; otherwise the best
 * ranked CPU in the package is chosen.
 */
static unsigned int dpti_select_cpu(unsigned int pkg_cpu, unsigned int skip,
				    enum dpti_rank *rank)
{
	const struct cpumask *pkg_mask = topology_core_cpumask(pkg_cpu);
	enum dpti_rank best_rank = DPTI_RANK_NONE;
	unsigned int cpu, pin, best = nr_cpu_ids;

	lockdep_assert_cpus_held();
	lockdep_assert_held(&dpti_mutex);

	/*
	 * Choose the user-pinned CPU if available: it is online and not going
	 * offline (as indicated by @skip).
	 */
	pin = dpti_pkg_of_cpu_nocheck(pkg_cpu)->pin;
	if (pin < nr_cpu_ids && pin != skip &&
	    cpumask_test_cpu(pin, pkg_mask)) {
		*rank = DPTI_RANK_PINNED;
		return pin;
	}

	for_each_cpu(cpu, pkg_mask) {
		enum dpti_rank cpu_rank;

		if (cpu == skip)
			continue;

		cpu_rank = dpti_cpu_rank(cpu);
		if (cpu_rank > best_rank) {
			best_rank = cpu_rank;
			best = cpu;
			/*
			 * Nothing outranks a housekeeping CPU in automatic
			 * selection.
			 */
			if (best_rank == DPTI_RANK_HOUSEKEEPING)
				break;
		}
	}

	*rank = best_rank;

	return best;
}

static void dpti_warn_if_isolated(unsigned int cpu, enum dpti_rank rank)
{
	if (rank == DPTI_RANK_ISOLATED)
		pr_warn_once("Package %u thermal interrupt directed to nohz_full-isolated CPU%u; no housekeeping CPU available\n",
			     topology_logical_package_id(cpu), cpu);
}

/*
 * Reselect the owner for @cpu's package and migrate to it, but only on a
 * strict rank improvement.
 */
static int dpti_update_owner(unsigned int cpu)
{
	struct dpti_pkg *pkg = dpti_pkg_of_cpu_nocheck(cpu);
	enum dpti_rank new_rank, old_rank;
	unsigned int new_cpu, old_cpu;
	int ret;

	lockdep_assert_held(&dpti_mutex);

	if (dpti_shut_down)
		return 0;

	old_cpu = pkg->owner;
	new_cpu = dpti_select_cpu(cpu, nr_cpu_ids, &new_rank);
	if (new_cpu == old_cpu)
		return 0;

	old_rank = DPTI_RANK_NONE;
	if (old_cpu < nr_cpu_ids)
		old_rank = dpti_cpu_rank(old_cpu);
	if (new_rank <= old_rank)
		return 0;

	ret = dpti_program_on_cpu(new_cpu);
	if (ret) {
		if (old_cpu < nr_cpu_ids)
			pr_warn_once("Failed to redirect package thermal interrupt from CPU%u to CPU%u; keeping CPU%u\n",
				     old_cpu, new_cpu, old_cpu);
		return ret;
	}

	if (old_cpu < nr_cpu_ids)
		dpti_clear_on_cpu(old_cpu);

	pkg->owner = new_cpu;
	dpti_warn_if_isolated(new_cpu, new_rank);

	return 0;
}

static int dpti_online(unsigned int cpu)
{
	int ret;

	if (!dpti_supported())
		return 0;

	/*
	 * Validate @cpu's package id on behalf of dpti_update_owner(), which
	 * indexes dpti_pkgs[] based on @cpu.
	 */
	ret = dpti_lookup_pkg_id(cpu, NULL);
	if (ret)
		return ret;

	guard(mutex)(&dpti_mutex);

	/*
	 * A CPU coming online may be a better owner than the one currently
	 * programmed. If the hardware does not acknowledge it, the current
	 * owner keeps the interrupt: a valid outcome, already reported.
	 */
	ret = dpti_update_owner(cpu);
	if (ret && dpti_pkg_of_cpu_nocheck(cpu)->owner < nr_cpu_ids)
		return 0;

	return ret;
}

static void dpti_offline(unsigned int cpu)
{
	enum dpti_rank new_rank;
	unsigned int new_cpu;
	u16 pkg_id;

	if (dpti_lookup_pkg_id(cpu, &pkg_id))
		return;

	guard(mutex)(&dpti_mutex);

	if (dpti_shut_down)
		return;

	/* Not the owner of the directed interrupt. */
	if (dpti_pkgs[pkg_id].owner != cpu)
		return;

	/*
	 * The package-level interrupt must remain directed after this CPU goes
	 * offline.
	 */
	new_cpu = dpti_select_cpu(cpu, cpu, &new_rank);

	/*
	 * dpti_program_on_cpu() undoes a setup that the hardware does not
	 * acknowledge on @new_cpu. With @cpu cleared below, no CPU is then
	 * configured to receive the package-level interrupt: all CPUs in the
	 * package receive it.
	 */
	if (new_cpu < nr_cpu_ids && dpti_program_on_cpu(new_cpu)) {
		pr_warn_once("Failed to redirect package thermal interrupt from CPU%u to CPU%u; reverting to broadcast\n",
			     cpu, new_cpu);

		new_cpu = nr_cpu_ids;
		new_rank = DPTI_RANK_NONE;
	}

	/*
	 * Clear the directed interrupt on @cpu. Hardware acknowledgment can be
	 * ignored since @cpu is going offline.
	 */
	dpti_config_this_cpu(false);

	dpti_pkgs[pkg_id].owner = new_cpu;
	dpti_warn_if_isolated(new_cpu, new_rank);
}

/*
 * CPU0 may own the directed interrupt, but the CPU hotplug callbacks are not
 * called for CPU0 during suspend and resume.
 */
static void dpti_syscore_resume(void *data)
{
	if (!dpti_cpu_is_owner(0))
		return;

	if (!dpti_program_this_cpu(NULL))
		return;

	/*
	 * Let another CPU take over via CPU hotplug. No lock is needed here:
	 * only CPU0 is online and interrupts are disabled.
	 */
	dpti_pkg_of_cpu_nocheck(0)->owner = nr_cpu_ids;
}

static int dpti_syscore_suspend(void *data)
{
	if (dpti_cpu_is_owner(0))
		dpti_config_this_cpu(false);

	return 0;
}

static void dpti_syscore_shutdown(void *data)
{
	scoped_guard(mutex, &dpti_mutex)
		dpti_shut_down = true;

	dpti_clear_all();
}

static const struct syscore_ops dpti_syscore_ops = {
	.resume = dpti_syscore_resume,
	.suspend = dpti_syscore_suspend,
	.shutdown = dpti_syscore_shutdown,
};

static struct syscore dpti_syscore = {
	.ops = &dpti_syscore_ops,
};

static __init void dpti_init(void)
{
	int i;

	if (!boot_cpu_has(X86_FEATURE_DPTI))
		return;

	dpti_pkgs = kmalloc_objs(*dpti_pkgs, topology_max_packages());
	if (!dpti_pkgs)
		return;

	for (i = 0; i < topology_max_packages(); i++) {
		dpti_pkgs[i].owner = nr_cpu_ids;
		dpti_pkgs[i].pin = nr_cpu_ids;
	}

	register_syscore(&dpti_syscore);
}

static void dpti_cleanup(void)
{
	if (!dpti_supported())
		return;

	unregister_syscore(&dpti_syscore);
	dpti_clear_all();
	kfree(dpti_pkgs);
	dpti_pkgs = NULL;
}

/* Add/Remove thermal_throttle interface for CPU device: */
static int thermal_throttle_add_dev(struct device *dev, unsigned int cpu)
{
	int err;
	struct cpuinfo_x86 *c = &cpu_data(cpu);

	err = sysfs_create_group(&dev->kobj, &thermal_attr_group);
	if (err)
		return err;

	if (cpu_has(c, X86_FEATURE_PLN) && int_pln_enable) {
		err = sysfs_add_file_to_group(&dev->kobj,
					      &dev_attr_core_power_limit_count.attr,
					      thermal_attr_group.name);
		if (err)
			goto del_group;
	}

	if (cpu_has(c, X86_FEATURE_PTS)) {
		err = sysfs_add_file_to_group(&dev->kobj,
					      &dev_attr_package_throttle_count.attr,
					      thermal_attr_group.name);
		if (err)
			goto del_group;

		err = sysfs_add_file_to_group(&dev->kobj,
					      &dev_attr_package_throttle_max_time_ms.attr,
					      thermal_attr_group.name);
		if (err)
			goto del_group;

		err = sysfs_add_file_to_group(&dev->kobj,
					      &dev_attr_package_throttle_total_time_ms.attr,
					      thermal_attr_group.name);
		if (err)
			goto del_group;

		if (cpu_has(c, X86_FEATURE_PLN) && int_pln_enable) {
			err = sysfs_add_file_to_group(&dev->kobj,
					&dev_attr_package_power_limit_count.attr,
					thermal_attr_group.name);
			if (err)
				goto del_group;
		}
	}

	return 0;

del_group:
	sysfs_remove_group(&dev->kobj, &thermal_attr_group);

	return err;
}

static void thermal_throttle_remove_dev(struct device *dev)
{
	sysfs_remove_group(&dev->kobj, &thermal_attr_group);
}

/* Get notified when a cpu comes on/off. Be hotplug friendly. */
static int thermal_throttle_online(unsigned int cpu)
{
	struct thermal_state *state = &per_cpu(thermal_state, cpu);
	struct device *dev = get_cpu_device(cpu);
	int err;
	u32 l;

	err = thermal_throttle_add_dev(dev, cpu);
	if (err)
		return err;

	state->package_throttle.level = PACKAGE_LEVEL;
	state->core_throttle.level = CORE_LEVEL;

	INIT_DELAYED_WORK(&state->package_throttle.therm_work, throttle_active_work);
	INIT_DELAYED_WORK(&state->core_throttle.therm_work, throttle_active_work);

	/*
	 * The first CPU coming online will enable the HFI. Usually this causes
	 * hardware to issue an HFI thermal interrupt. Such interrupt will reach
	 * the CPU once we enable the thermal vector in the local APIC.
	 */
	intel_hfi_online(cpu);

	if (dpti_online(cpu)) {
		pr_warn_once("Failed to direct the thermal interrupt of package %u; reverting to broadcast on %s\n",
			     topology_logical_package_id(cpu),
			     dpti_in_boot ? "all packages" : "this package");

		/*
		 * A failure during boot indicates faulty hardware, so no other
		 * CPU should try.
		 */
		if (dpti_in_boot)
			dpti_cleanup();
	}

	/* Unmask the thermal vector after the above workqueues are initialized. */
	l = apic_read(APIC_LVTTHMR);
	apic_write(APIC_LVTTHMR, l & ~APIC_LVT_MASKED);

	return err;
}

static int thermal_throttle_offline(unsigned int cpu)
{
	struct thermal_state *state = &per_cpu(thermal_state, cpu);
	struct device *dev = get_cpu_device(cpu);
	u32 l;

	/* Mask the thermal vector before draining evtl. pending work */
	l = apic_read(APIC_LVTTHMR);
	apic_write(APIC_LVTTHMR, l | APIC_LVT_MASKED);

	dpti_offline(cpu);

	intel_hfi_offline(cpu);

	cancel_delayed_work_sync(&state->package_throttle.therm_work);
	cancel_delayed_work_sync(&state->core_throttle.therm_work);

	state->package_throttle.rate_control_active = false;
	state->core_throttle.rate_control_active = false;

	thermal_throttle_remove_dev(dev);
	return 0;
}

static __init int thermal_throttle_init_device(void)
{
	int ret;

	if (!atomic_read(&therm_throt_en))
		return 0;

	dpti_init();

	intel_hfi_init();

	/*
	 * A CPU coming online before dpti_in_boot is cleared would treat a DPTI
	 * failure as faulty hardware and tear DPTI down. Hold the CPU hotplug
	 * lock across the registration and the clear, so that the flag changes
	 * only while no CPU can come online.
	 */
	guard(cpus_read_lock)();

	ret = cpuhp_setup_state_cpuslocked(CPUHP_AP_ONLINE_DYN,
					   "x86/therm:online",
					   thermal_throttle_online,
					   thermal_throttle_offline);
	if (ret >= 0) {
		dpti_in_boot = false;
		return 0;
	}

	dpti_cleanup();

	return ret;
}
device_initcall(thermal_throttle_init_device);

#endif /* CONFIG_SYSFS */

static void notify_package_thresholds(__u64 msr_val)
{
	bool notify_thres_0 = false;
	bool notify_thres_1 = false;

	if (!platform_thermal_package_notify)
		return;

	/* lower threshold check */
	if (msr_val & THERM_LOG_THRESHOLD0)
		notify_thres_0 = true;
	/* higher threshold check */
	if (msr_val & THERM_LOG_THRESHOLD1)
		notify_thres_1 = true;

	if (!notify_thres_0 && !notify_thres_1)
		return;

	if (platform_thermal_package_rate_control &&
		platform_thermal_package_rate_control()) {
		/* Rate control is implemented in callback */
		platform_thermal_package_notify(msr_val);
		return;
	}

	/* lower threshold reached */
	if (notify_thres_0 && thresh_event_valid(PACKAGE_LEVEL, 0))
		platform_thermal_package_notify(msr_val);
	/* higher threshold reached */
	if (notify_thres_1 && thresh_event_valid(PACKAGE_LEVEL, 1))
		platform_thermal_package_notify(msr_val);
}

static void notify_thresholds(__u64 msr_val)
{
	/* check whether the interrupt handler is defined;
	 * otherwise simply return
	 */
	if (!platform_thermal_notify)
		return;

	/* lower threshold reached */
	if ((msr_val & THERM_LOG_THRESHOLD0) &&
			thresh_event_valid(CORE_LEVEL, 0))
		platform_thermal_notify(msr_val);
	/* higher threshold reached */
	if ((msr_val & THERM_LOG_THRESHOLD1) &&
			thresh_event_valid(CORE_LEVEL, 1))
		platform_thermal_notify(msr_val);
}

void __weak notify_hwp_interrupt(void)
{
	wrmsrq_safe(MSR_HWP_STATUS, 0);
}

/* Thermal transition interrupt handler */
void intel_thermal_interrupt(void)
{
	__u64 msr_val;

	if (cpu_feature_enabled(X86_FEATURE_HWP))
		notify_hwp_interrupt();

	rdmsrq(MSR_IA32_THERM_STATUS, msr_val);

	/* Check for violation of core thermal thresholds*/
	notify_thresholds(msr_val);

	therm_throt_process(msr_val & THERM_STATUS_PROCHOT,
			    THERMAL_THROTTLING_EVENT,
			    CORE_LEVEL);

	if (this_cpu_has(X86_FEATURE_PLN) && int_pln_enable)
		therm_throt_process(msr_val & THERM_STATUS_POWER_LIMIT,
					POWER_LIMIT_EVENT,
					CORE_LEVEL);

	if (this_cpu_has(X86_FEATURE_PTS)) {
		rdmsrq(MSR_IA32_PACKAGE_THERM_STATUS, msr_val);
		/* check violations of package thermal thresholds */
		notify_package_thresholds(msr_val);
		therm_throt_process(msr_val & PACKAGE_THERM_STATUS_PROCHOT,
					THERMAL_THROTTLING_EVENT,
					PACKAGE_LEVEL);
		if (this_cpu_has(X86_FEATURE_PLN) && int_pln_enable)
			therm_throt_process(msr_val &
					PACKAGE_THERM_STATUS_POWER_LIMIT,
					POWER_LIMIT_EVENT,
					PACKAGE_LEVEL);

		if (this_cpu_has(X86_FEATURE_HFI))
			intel_hfi_process_event(msr_val &
						PACKAGE_THERM_STATUS_HFI_UPDATED);
	}
}

/* Thermal monitoring depends on APIC, ACPI and clock modulation */
static int intel_thermal_supported(struct cpuinfo_x86 *c)
{
	if (!boot_cpu_has(X86_FEATURE_APIC))
		return 0;
	if (!cpu_has(c, X86_FEATURE_ACPI) || !cpu_has(c, X86_FEATURE_ACC))
		return 0;
	return 1;
}

bool x86_thermal_enabled(void)
{
	return atomic_read(&therm_throt_en);
}

void __init therm_lvt_init(void)
{
	/*
	 * This function is only called on boot CPU. Save the init thermal
	 * LVT value on BSP and use that value to restore APs' thermal LVT
	 * entry BIOS programmed later
	 */
	if (intel_thermal_supported(&boot_cpu_data))
		lvtthmr_init = apic_read(APIC_LVTTHMR);
}

void intel_init_thermal(struct cpuinfo_x86 *c)
{
	unsigned int cpu = smp_processor_id();
	struct msr val;
	int tm2 = 0;

	if (!intel_thermal_supported(c))
		return;

	/*
	 * First check if its enabled already, in which case there might
	 * be some SMM goo which handles it, so we can't even put a handler
	 * since it might be delivered via SMI already:
	 */
	rdmsrq(MSR_IA32_MISC_ENABLE, val.q);

	val.h = lvtthmr_init;
	/*
	 * The initial value of thermal LVT entries on all APs always reads
	 * 0x10000 because APs are woken up by BSP issuing INIT-SIPI-SIPI
	 * sequence to them and LVT registers are reset to 0s except for
	 * the mask bits which are set to 1s when APs receive INIT IPI.
	 * If BIOS takes over the thermal interrupt and sets its interrupt
	 * delivery mode to SMI (not fixed), it restores the value that the
	 * BIOS has programmed on AP based on BSP's info we saved since BIOS
	 * is always setting the same value for all threads/cores.
	 */
	if ((val.h & APIC_DM_FIXED_MASK) != APIC_DM_FIXED)
		apic_write(APIC_LVTTHMR, lvtthmr_init);


	if ((val.l & MSR_IA32_MISC_ENABLE_TM1) && (val.h & APIC_DM_SMI)) {
		if (system_state == SYSTEM_BOOTING)
			pr_debug("CPU%d: Thermal monitoring handled by SMI\n", cpu);
		return;
	}

	/* early Pentium M models use different method for enabling TM2 */
	if (cpu_has(c, X86_FEATURE_TM2)) {
		if (c->x86 == 6 && (c->x86_model == 9 || c->x86_model == 13)) {
			rdmsrq(MSR_THERM2_CTL, val.q);
			if (val.l & MSR_THERM2_CTL_TM_SELECT)
				tm2 = 1;
		} else if (val.l & MSR_IA32_MISC_ENABLE_TM2)
			tm2 = 1;
	}

	/* We'll mask the thermal vector in the lapic till we're ready: */
	val.h = THERMAL_APIC_VECTOR | APIC_DM_FIXED | APIC_LVT_MASKED;
	apic_write(APIC_LVTTHMR, val.h);

	thermal_intr_init_core_clear_mask();
	thermal_intr_init_pkg_clear_mask();

	rdmsrq(MSR_IA32_THERM_INTERRUPT, val.q);
	if (cpu_has(c, X86_FEATURE_PLN) && !int_pln_enable) {
		val.l |= THERM_INT_LOW_ENABLE | THERM_INT_HIGH_ENABLE;
		val.l &= ~THERM_INT_PLN_ENABLE;
	} else if (cpu_has(c, X86_FEATURE_PLN) && int_pln_enable)
		val.l |= THERM_INT_LOW_ENABLE | THERM_INT_HIGH_ENABLE |
			 THERM_INT_PLN_ENABLE;
	else
		val.l |= THERM_INT_LOW_ENABLE | THERM_INT_HIGH_ENABLE;
	wrmsrq(MSR_IA32_THERM_INTERRUPT, val.q);

	if (cpu_has(c, X86_FEATURE_PTS)) {
		rdmsrq(MSR_IA32_PACKAGE_THERM_INTERRUPT, val.q);
		if (cpu_has(c, X86_FEATURE_PLN) && !int_pln_enable) {
			val.l |= PACKAGE_THERM_INT_LOW_ENABLE |
				 PACKAGE_THERM_INT_HIGH_ENABLE;
			val.l &= ~PACKAGE_THERM_INT_PLN_ENABLE;
		} else if (cpu_has(c, X86_FEATURE_PLN) && int_pln_enable)
			val.l |= PACKAGE_THERM_INT_LOW_ENABLE |
				 PACKAGE_THERM_INT_HIGH_ENABLE |
				 PACKAGE_THERM_INT_PLN_ENABLE;
		else
			val.l |= PACKAGE_THERM_INT_LOW_ENABLE |
				 PACKAGE_THERM_INT_HIGH_ENABLE;
		wrmsrq(MSR_IA32_PACKAGE_THERM_INTERRUPT, val.q);

		if (cpu_has(c, X86_FEATURE_HFI)) {
			rdmsrq(MSR_IA32_PACKAGE_THERM_INTERRUPT, val.q);
			wrmsrq(MSR_IA32_PACKAGE_THERM_INTERRUPT,
			       val.q | PACKAGE_THERM_INT_HFI_ENABLE);
		}
	}

	rdmsrq(MSR_IA32_MISC_ENABLE, val.q);
	wrmsrq(MSR_IA32_MISC_ENABLE, val.q | MSR_IA32_MISC_ENABLE_TM1);

	pr_info_once("CPU0: Thermal monitoring enabled (%s)\n",
		      tm2 ? "TM2" : "TM1");

	/* enable thermal throttle processing */
	atomic_set(&therm_throt_en, 1);
}
