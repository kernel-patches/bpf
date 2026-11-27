// SPDX-License-Identifier: GPL-2.0-only
/*
 * Watchdog driver for the ARM Cortex-A9/A5 and ARM11 MPCore private
 * (TWD) watchdog
 *
 * Every CPU has its own watchdog, banked at the same address, and any of
 * them resets the system when it expires. The driver uses the watchdog of
 * CPU0 as the system watchdog and leaves the others alone: CPU0 cannot be
 * taken offline, so the registers are always reached through it. Once the
 * watchdog mode bit is set it can only be cleared by writing the disable
 * sequence to the disable register.
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/cleanup.h>
#include <linux/clk.h>
#include <linux/cpu.h>
#include <linux/cpu_pm.h>
#include <linux/cpufreq.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/smp.h>
#include <linux/stringify.h>
#include <linux/wait.h>
#include <linux/watchdog.h>

#define TWD_WDT_LOAD		0x00
#define TWD_WDT_COUNTER		0x04
#define TWD_WDT_CONTROL		0x08
#define TWD_WDT_RESET_STATUS	0x10
#define TWD_WDT_DISABLE		0x14

#define TWD_WDT_CTRL_ENABLE	BIT(0)
#define TWD_WDT_CTRL_WD_MODE	BIT(3)
#define TWD_WDT_CTRL_PRESCALER	GENMASK(15, 8)

#define TWD_WDT_RESET_FLAG	BIT(0)

#define TWD_WDT_DISABLE_KEY1	0x12345678
#define TWD_WDT_DISABLE_KEY2	0x87654321

/* Largest prescaler, the counter clock is the input clock divided by 256 */
#define TWD_WDT_PRESCALE	255
#define TWD_WDT_DEFAULT_TIMEOUT	30

/* The CPU whose watchdog is used */
#define TWD_WDT_CPU		0

static bool nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, bool, 0);
MODULE_PARM_DESC(nowayout, "Watchdog cannot be stopped once started (default="
		 __stringify(WATCHDOG_NOWAYOUT) ")");

static unsigned int timeout;
module_param(timeout, uint, 0);
MODULE_PARM_DESC(timeout, "Watchdog timeout in seconds");

struct twd_wdt {
	struct watchdog_device wdd;
	void __iomem *base;
	struct notifier_block clk_nb;
	struct notifier_block cpufreq_nb;
	/* Fixed calibration reference: avoid rounding drift across transitions. */
	unsigned long reference_rate;
	unsigned long max_rate;
	unsigned int reference_freq;
	atomic_t freq_changes;
	bool freq_changing;
	unsigned long sampled_rate;
	struct notifier_block pm_nb;
	/* Serializes the watchdog operations and the frequency notifiers */
	struct mutex lock;
	/* Also read by the CPU PM notifier, which cannot take the lock */
	unsigned long rate;
	bool armed;
	/* Expiration time in monotonic ns, also read by the CPU PM notifier */
	atomic64_t expires;
	bool resume_armed;
	/* Remaining monotonic ns while the hardware is stopped for system sleep. */
	s64 suspend_left;
	u32 counter;
	bool running;
	bool reset;
};

/*
 * Counter value for the time left until the watchdog has to expire: the
 * watchdog is always loaded with it, so neither a clock rate change nor
 * setting it up again after a CPU power down extends the timeout.
 */
static u32 twd_wdt_ticks(struct twd_wdt *wdt)
{
	s64 left = atomic64_read(&wdt->expires) - ktime_get_ns();
	u64 ticks;

	if (left <= 0)
		return 1;

	ticks = mul_u64_u64_div_u64(READ_ONCE(wdt->rate), left,
				    (u64)NSEC_PER_SEC * (TWD_WDT_PRESCALE + 1));

	return clamp_t(u64, ticks, 1, U32_MAX);
}

/* The following run on TWD_WDT_CPU */
static void twd_wdt_cpu_stop(void *data)
{
	struct twd_wdt *wdt = data;

	writel(TWD_WDT_DISABLE_KEY1, wdt->base + TWD_WDT_DISABLE);
	writel(TWD_WDT_DISABLE_KEY2, wdt->base + TWD_WDT_DISABLE);
	writel(0, wdt->base + TWD_WDT_CONTROL);
}

static void twd_wdt_cpu_start(void *data)
{
	struct twd_wdt *wdt = data;
	u32 ctrl = readl(wdt->base + TWD_WDT_CONTROL);

	/*
	 * In watchdog mode the prescaler cannot be changed, so a watchdog
	 * started by the bootloader with a different one is stopped first.
	 */
	if ((ctrl & TWD_WDT_CTRL_WD_MODE) &&
	    FIELD_GET(TWD_WDT_CTRL_PRESCALER, ctrl) != TWD_WDT_PRESCALE)
		twd_wdt_cpu_stop(wdt);

	/*
	 * Load the counter before enabling, it may still be zero. A watchdog
	 * that is already running is reloaded and keeps running.
	 */
	writel(twd_wdt_ticks(wdt), wdt->base + TWD_WDT_LOAD);
	writel(FIELD_PREP(TWD_WDT_CTRL_PRESCALER, TWD_WDT_PRESCALE) |
	       TWD_WDT_CTRL_WD_MODE | TWD_WDT_CTRL_ENABLE,
	       wdt->base + TWD_WDT_CONTROL);
}

static void twd_wdt_cpu_ping(void *data)
{
	struct twd_wdt *wdt = data;

	/* In watchdog mode a write to the load register reloads the counter */
	writel(twd_wdt_ticks(wdt), wdt->base + TWD_WDT_LOAD);
}

static void twd_wdt_cpu_counter(void *data)
{
	struct twd_wdt *wdt = data;

	wdt->counter = readl(wdt->base + TWD_WDT_COUNTER);
}

static void twd_wdt_cpu_probe(void *data)
{
	struct twd_wdt *wdt = data;
	u32 ctrl = readl(wdt->base + TWD_WDT_CONTROL);

	wdt->running = (ctrl & (TWD_WDT_CTRL_WD_MODE | TWD_WDT_CTRL_ENABLE)) ==
		       (TWD_WDT_CTRL_WD_MODE | TWD_WDT_CTRL_ENABLE);

	if (readl(wdt->base + TWD_WDT_RESET_STATUS) & TWD_WDT_RESET_FLAG) {
		wdt->reset = true;
		/* The flag is cleared by writing one */
		writel(TWD_WDT_RESET_FLAG, wdt->base + TWD_WDT_RESET_STATUS);
	}
}

static void twd_wdt_call(struct twd_wdt *wdt, smp_call_func_t func)
{
	smp_call_function_single(TWD_WDT_CPU, func, wdt, 1);
}

/*
 * Measure PERIPHCLK rather than assuming a particular CPU clock divider.
 * An active watchdog is only observed, never stopped or reloaded here.
 * Otherwise temporarily use timer mode without interrupts, restoring the
 * original registers afterwards. This runs on CPU0 with interrupts disabled.
 */
static void twd_wdt_cpu_calibrate(void *data)
{
	struct twd_wdt *wdt = data;
	u32 ctrl = readl(wdt->base + TWD_WDT_CONTROL);
	u32 load = 0, counter = 0, first, last;
	bool enabled = ctrl & TWD_WDT_CTRL_ENABLE;
	u64 start, elapsed, rate;
	unsigned int divisor = FIELD_GET(TWD_WDT_CTRL_PRESCALER, ctrl) + 1;

	wdt->sampled_rate = 0;
	if (!enabled) {
		load = readl(wdt->base + TWD_WDT_LOAD);
		counter = readl(wdt->base + TWD_WDT_COUNTER);
		twd_wdt_cpu_stop(wdt);
		writel(U32_MAX, wdt->base + TWD_WDT_COUNTER);
		writel(TWD_WDT_CTRL_ENABLE, wdt->base + TWD_WDT_CONTROL);
		divisor = 1;
	}

	start = ktime_get_ns();
	first = readl(wdt->base + TWD_WDT_COUNTER);
	mdelay(2);
	last = readl(wdt->base + TWD_WDT_COUNTER);
	elapsed = ktime_get_ns() - start;

	if (!enabled) {
		twd_wdt_cpu_stop(wdt);
		writel(load, wdt->base + TWD_WDT_LOAD);
		writel(counter, wdt->base + TWD_WDT_COUNTER);
		writel(ctrl, wdt->base + TWD_WDT_CONTROL);
	}

	/* Reject a stopped counter, expiration or wrap during measurement. */
	if (!elapsed || !last || last >= first)
		return;

	rate = mul_u64_u64_div_u64((u64)(first - last) * divisor,
				   NSEC_PER_SEC, elapsed);
	if (rate <= ULONG_MAX)
		wdt->sampled_rate = rate;
}

static void twd_wdt_set_armed(struct twd_wdt *wdt, bool armed)
{
	guard(mutex)(&wdt->lock);

	if (armed)
		atomic64_set(&wdt->expires, ktime_get_ns() +
			     (s64)wdt->wdd.timeout * NSEC_PER_SEC);
	/* Publish the deadline before the CPU PM notifier can see armed. */
	smp_store_release(&wdt->armed, armed);
	twd_wdt_call(wdt, armed ? twd_wdt_cpu_start : twd_wdt_cpu_stop);
}

static int twd_wdt_start(struct watchdog_device *wdd)
{
	twd_wdt_set_armed(watchdog_get_drvdata(wdd), true);

	return 0;
}

static int twd_wdt_stop(struct watchdog_device *wdd)
{
	twd_wdt_set_armed(watchdog_get_drvdata(wdd), false);

	return 0;
}

static int twd_wdt_ping(struct watchdog_device *wdd)
{
	struct twd_wdt *wdt = watchdog_get_drvdata(wdd);

	guard(mutex)(&wdt->lock);

	if (!wdt->armed)
		return 0;

	atomic64_set(&wdt->expires, ktime_get_ns() +
		     (s64)wdd->timeout * NSEC_PER_SEC);
	twd_wdt_call(wdt, twd_wdt_cpu_ping);

	return 0;
}

static int twd_wdt_set_timeout(struct watchdog_device *wdd, unsigned int t)
{
	struct twd_wdt *wdt = watchdog_get_drvdata(wdd);

	guard(mutex)(&wdt->lock);

	wdd->timeout = t;
	if (wdt->armed)
		atomic64_set(&wdt->expires, ktime_get_ns() +
			     (s64)t * NSEC_PER_SEC);

	return 0;
}

static unsigned int twd_wdt_get_timeleft(struct watchdog_device *wdd)
{
	struct twd_wdt *wdt = watchdog_get_drvdata(wdd);
	u64 ticks;

	guard(mutex)(&wdt->lock);

	twd_wdt_call(wdt, twd_wdt_cpu_counter);
	ticks = (u64)wdt->counter * (TWD_WDT_PRESCALE + 1);

	return div_u64(ticks, wdt->rate);
}

/*
 * The TWD runs from the peripheral clock, which follows the CPU clock. While
 * the rate goes up, count with the new rate already: the watchdog then just
 * fires later than asked until the change is done.
 */
static int twd_wdt_clk_notify(struct notifier_block *nb, unsigned long event,
			      void *data)
{
	struct twd_wdt *wdt = container_of(nb, struct twd_wdt, clk_nb);
	struct clk_notifier_data *cnd = data;
	unsigned long rate;

	switch (event) {
	case PRE_RATE_CHANGE:
		if (cnd->new_rate <= cnd->old_rate)
			return NOTIFY_OK;
		rate = cnd->new_rate;
		break;
	case POST_RATE_CHANGE:
		rate = cnd->new_rate;
		break;
	case ABORT_RATE_CHANGE:
		rate = cnd->old_rate;
		break;
	default:
		return NOTIFY_DONE;
	}

	guard(mutex)(&wdt->lock);

	if (!rate || rate == wdt->rate)
		return NOTIFY_OK;

	WRITE_ONCE(wdt->rate, rate);
	if (wdt->armed)
		twd_wdt_call(wdt, twd_wdt_cpu_ping);

	return NOTIFY_OK;
}

/*
 * With no clock provider, assume PERIPHCLK keeps the calibrated CPU clock
 * ratio. Platforms with an independently changing divider need a clock.
 */
static int twd_wdt_cpufreq_notify(struct notifier_block *nb,
				  unsigned long event, void *data)
{
	struct twd_wdt *wdt = container_of(nb, struct twd_wdt, cpufreq_nb);
	struct cpufreq_freqs *freqs = data;
	unsigned long rate;

	if (!cpumask_test_cpu(TWD_WDT_CPU, freqs->policy->cpus) ||
	    (event != CPUFREQ_PRECHANGE && event != CPUFREQ_POSTCHANGE))
		return NOTIFY_DONE;

	/* Also invalidate calibration when this callback is waiting for lock. */
	atomic_inc(&wdt->freq_changes);
	guard(mutex)(&wdt->lock);

	wdt->freq_changing = event == CPUFREQ_PRECHANGE;
	if (!wdt->reference_freq || !freqs->new ||
	    (event == CPUFREQ_PRECHANGE && freqs->new <= freqs->old))
		return NOTIFY_OK;

	/* Failed transitions are reported as a second, reverse transition. */
	rate = mul_u64_u64_div_u64(wdt->reference_rate, freqs->new,
				   wdt->reference_freq);
	if (!rate || rate == wdt->rate)
		return NOTIFY_OK;

	WRITE_ONCE(wdt->rate, rate);
	if (wdt->armed)
		twd_wdt_call(wdt, twd_wdt_cpu_ping);

	return NOTIFY_OK;
}

static void twd_wdt_remove_cpufreq_notifier(void *data)
{
	struct twd_wdt *wdt = data;

	cpufreq_unregister_notifier(&wdt->cpufreq_nb,
				    CPUFREQ_TRANSITION_NOTIFIER);
}

static int twd_wdt_init_cpufreq(struct device *dev, struct twd_wdt *wdt)
{
	struct cpufreq_policy *policy;
	u64 max_rate;
	unsigned long rate;
	unsigned int freq, max_freq;
	int ret, seq, attempt;
	bool retry;

	if (!IS_ENABLED(CONFIG_CPU_FREQ))
		return dev_err_probe(dev, -EOPNOTSUPP,
				     "no clock and CPU frequency support is disabled\n");

	wdt->cpufreq_nb.notifier_call = twd_wdt_cpufreq_notify;
	ret = cpufreq_register_notifier(&wdt->cpufreq_nb,
					CPUFREQ_TRANSITION_NOTIFIER);
	if (ret)
		return dev_err_probe(dev, ret, "failed to register CPU frequency notifier\n");

	ret = devm_add_action_or_reset(dev, twd_wdt_remove_cpufreq_notifier, wdt);
	if (ret)
		return ret;

	/* A transition may have begun before we registered and missed PRE. */
	policy = cpufreq_cpu_get(TWD_WDT_CPU);
	if (!policy)
		return dev_err_probe(dev, -EPROBE_DEFER,
				     "CPU frequency policy is unavailable\n");
	wait_event(policy->transition_wait, !READ_ONCE(policy->transition_ongoing));
	cpufreq_cpu_put(policy);

	max_freq = cpufreq_get_hw_max_freq(TWD_WDT_CPU);
	if (!max_freq)
		return dev_err_probe(dev, -EPROBE_DEFER,
				     "maximum CPU frequency is unavailable\n");

	for (attempt = 0; attempt < 3; attempt++) {
		seq = atomic_read(&wdt->freq_changes);
		/* May notify transitions itself: never call with lock held. */
		freq = cpufreq_get(TWD_WDT_CPU);
		if (!freq)
			return dev_err_probe(dev, -EPROBE_DEFER,
					     "CPU frequency is unavailable\n");
		scoped_guard(mutex, &wdt->lock) {
			retry = wdt->freq_changing || seq != atomic_read(&wdt->freq_changes);
			if (retry)
				break;
			twd_wdt_call(wdt, twd_wdt_cpu_calibrate);
			rate = wdt->sampled_rate;
		}
		if (retry)
			continue;
		if (!rate)
			return dev_err_probe(dev, -EINVAL, "failed to calibrate watchdog clock\n");
		if (cpufreq_get(TWD_WDT_CPU) != freq)
			continue;
		scoped_guard(mutex, &wdt->lock) {
			if (wdt->freq_changing || seq != atomic_read(&wdt->freq_changes))
				break;
			/* Bound the advertised timeout at the highest CPU rate. */
			max_rate = mul_u64_u64_div_u64(rate, max(max_freq, freq), freq);
			if (max_rate >= ULONG_MAX)
				return dev_err_probe(dev, -EINVAL,
						     "watchdog clock rate is too high\n");
			wdt->max_rate = max_rate + 1;
			wdt->reference_freq = freq;
			wdt->reference_rate = rate;
			WRITE_ONCE(wdt->rate, rate);
			return 0;
		}
	}

	return dev_err_probe(dev, -EPROBE_DEFER,
			     "CPU frequency changed during calibration\n");
}

/*
 * A CPU whose power domain was turned off in idle comes back with its
 * watchdog stopped. Only then set it up again: reloading a watchdog that
 * kept running would ping it on every idle exit.
 */
static int twd_wdt_cpu_pm_notify(struct notifier_block *nb,
				 unsigned long action, void *data)
{
	struct twd_wdt *wdt = container_of(nb, struct twd_wdt, pm_nb);

	if (action != CPU_PM_EXIT && action != CPU_PM_ENTER_FAILED)
		return NOTIFY_DONE;

	/* Pairs with the release stores that publish the expiration time. */
	if (smp_processor_id() == TWD_WDT_CPU && smp_load_acquire(&wdt->armed) &&
	    !(readl(wdt->base + TWD_WDT_CONTROL) & TWD_WDT_CTRL_WD_MODE))
		twd_wdt_cpu_start(wdt);

	return NOTIFY_OK;
}

static int twd_wdt_restart(struct watchdog_device *wdd, unsigned long action,
			   void *data)
{
	struct twd_wdt *wdt = watchdog_get_drvdata(wdd);

	/*
	 * Only this CPU is still running, and it may not be TWD_WDT_CPU. The
	 * watchdog of any CPU resets the system: let its own expire right away.
	 */
	writel(1, wdt->base + TWD_WDT_LOAD);
	writel(TWD_WDT_CTRL_WD_MODE | TWD_WDT_CTRL_ENABLE,
	       wdt->base + TWD_WDT_CONTROL);
	mdelay(500);

	return 0;
}

static const struct watchdog_ops twd_wdt_ops = {
	.owner		= THIS_MODULE,
	.start		= twd_wdt_start,
	.stop		= twd_wdt_stop,
	.ping		= twd_wdt_ping,
	.set_timeout	= twd_wdt_set_timeout,
	.get_timeleft	= twd_wdt_get_timeleft,
	.restart	= twd_wdt_restart,
};

static const struct watchdog_info twd_wdt_info = {
	.options	= WDIOF_SETTIMEOUT | WDIOF_KEEPALIVEPING |
			  WDIOF_MAGICCLOSE | WDIOF_CARDRESET,
	.identity	= "ARM TWD watchdog",
};

/* A watchdog left running would not be pinged any more */
static void twd_wdt_disable(void *data)
{
	struct twd_wdt *wdt = data;

	twd_wdt_set_armed(wdt, false);
}

static void twd_wdt_remove_pm_notifier(void *data)
{
	struct twd_wdt *wdt = data;

	cpu_pm_unregister_notifier(&wdt->pm_nb);
}

static int twd_wdt_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct twd_wdt *wdt;
	struct clk *clk;
	int ret;

	if (cpu_is_hotpluggable(TWD_WDT_CPU))
		return dev_err_probe(dev, -EOPNOTSUPP,
				     "CPU%d can be taken offline\n", TWD_WDT_CPU);

	wdt = devm_kzalloc(dev, sizeof(*wdt), GFP_KERNEL);
	if (!wdt)
		return -ENOMEM;

	ret = devm_mutex_init(dev, &wdt->lock);
	if (ret)
		return ret;

	wdt->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(wdt->base))
		return PTR_ERR(wdt->base);

	clk = devm_clk_get_optional_enabled(dev, NULL);
	if (IS_ERR(clk))
		return dev_err_probe(dev, PTR_ERR(clk), "failed to get clock\n");

	if (clk) {
		/* Keep the rate snapshot stable until its notifier is installed. */
		ret = clk_rate_exclusive_get(clk);
		if (ret)
			return dev_err_probe(dev, ret, "failed to protect clock rate\n");

		wdt->rate = clk_get_rate(clk);
		if (!wdt->rate) {
			clk_rate_exclusive_put(clk);
			return dev_err_probe(dev, -EINVAL, "clock rate is zero\n");
		}

		wdt->max_rate = wdt->rate;
		wdt->clk_nb.notifier_call = twd_wdt_clk_notify;
		ret = devm_clk_notifier_register(dev, clk, &wdt->clk_nb);
		clk_rate_exclusive_put(clk);
		if (ret)
			return dev_err_probe(dev, ret, "failed to register clock notifier\n");
	} else {
		ret = twd_wdt_init_cpufreq(dev, wdt);
		if (ret)
			return ret;
	}
	platform_set_drvdata(pdev, wdt);

	wdt->wdd.info = &twd_wdt_info;
	wdt->wdd.ops = &twd_wdt_ops;
	wdt->wdd.parent = dev;
	wdt->wdd.min_timeout = 1;
	wdt->wdd.max_timeout = div_u64((u64)U32_MAX * (TWD_WDT_PRESCALE + 1),
				       wdt->max_rate);
	wdt->wdd.timeout = min_t(unsigned int, TWD_WDT_DEFAULT_TIMEOUT,
				 wdt->wdd.max_timeout);
	watchdog_init_timeout(&wdt->wdd, timeout, dev);
	watchdog_set_nowayout(&wdt->wdd, nowayout);
	watchdog_stop_on_reboot(&wdt->wdd);
	watchdog_stop_on_unregister(&wdt->wdd);
	watchdog_stop_ping_on_suspend(&wdt->wdd);
	watchdog_set_drvdata(&wdt->wdd, wdt);

	twd_wdt_call(wdt, twd_wdt_cpu_probe);
	if (wdt->reset) {
		wdt->wdd.bootstatus = WDIOF_CARDRESET;
		dev_info(dev, "last reset caused by the watchdog\n");
	}

	wdt->pm_nb.notifier_call = twd_wdt_cpu_pm_notify;
	ret = cpu_pm_register_notifier(&wdt->pm_nb);
	if (ret)
		return ret;

	ret = devm_add_action_or_reset(dev, twd_wdt_remove_pm_notifier, wdt);
	if (ret)
		return ret;

	ret = devm_add_action_or_reset(dev, twd_wdt_disable, wdt);
	if (ret)
		return ret;

	if (wdt->running) {
		/* Left running by the bootloader: take it over without a stop */
		dev_info(dev, "running, taking over\n");
		twd_wdt_start(&wdt->wdd);
		set_bit(WDOG_HW_RUNNING, &wdt->wdd.status);
	}

	ret = devm_watchdog_register_device(dev, &wdt->wdd);
	if (ret)
		return ret;

	dev_dbg(dev, "timeout %u s (max %u s), clock %lu Hz\n",
		wdt->wdd.timeout, wdt->wdd.max_timeout, wdt->rate);

	return 0;
}

static const struct of_device_id twd_wdt_of_match[] = {
	{ .compatible = "arm,arm11mp-twd-wdt" },
	{ .compatible = "arm,cortex-a5-twd-wdt" },
	{ .compatible = "arm,cortex-a9-twd-wdt" },
	{ }
};
MODULE_DEVICE_TABLE(of, twd_wdt_of_match);

/*
 * Stop the hardware for system sleep while the core stops its ping worker.
 * Pause the remaining timeout while the hardware is stopped: monotonic time
 * can advance during system sleep and device PM. Core PM keepalives still
 * refresh the timeout before suspend and after resume.
 */
static int twd_wdt_suspend(struct device *dev)
{
	struct twd_wdt *wdt = dev_get_drvdata(dev);

	guard(mutex)(&wdt->lock);

	wdt->resume_armed = wdt->armed;
	/* Keep CPU PM from restoring the watchdog while it is suspended. */
	smp_store_release(&wdt->armed, false);
	if (wdt->resume_armed) {
		wdt->suspend_left = atomic64_read(&wdt->expires) - ktime_get_ns();
		twd_wdt_call(wdt, twd_wdt_cpu_stop);
	}

	return 0;
}

static int twd_wdt_resume(struct device *dev)
{
	struct twd_wdt *wdt = dev_get_drvdata(dev);

	guard(mutex)(&wdt->lock);

	if (wdt->resume_armed) {
		atomic64_set(&wdt->expires, ktime_get_ns() + wdt->suspend_left);
		/* Publish the restored deadline before CPU PM can rearm it. */
		smp_store_release(&wdt->armed, true);
		twd_wdt_call(wdt, twd_wdt_cpu_start);
		wdt->resume_armed = false;
	}

	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(twd_wdt_pm_ops, twd_wdt_suspend, twd_wdt_resume);

static struct platform_driver twd_wdt_driver = {
	.probe = twd_wdt_probe,
	.driver = {
		.name = "arm-twd-wdt",
		.of_match_table = twd_wdt_of_match,
		.pm = pm_sleep_ptr(&twd_wdt_pm_ops),
	},
};
module_platform_driver(twd_wdt_driver);

MODULE_DESCRIPTION("ARM TWD (MPCore private) watchdog driver");
MODULE_LICENSE("GPL");
