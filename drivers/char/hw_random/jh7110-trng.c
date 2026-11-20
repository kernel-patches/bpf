// SPDX-License-Identifier: GPL-2.0
/*
 * TRNG driver for the StarFive JH7110/JHB100 SoCs
 *
 * Copyright (C) 2022 StarFive Technology Co.
 */

#include <linux/bits.h>
#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/container_of.h>
#include <linux/device.h>
#include <linux/devm-helpers.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/hw_random.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/jiffies.h>
#include <linux/lockdep.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/property.h>
#include <linux/reset.h>
#include <linux/types.h>
#include <linux/workqueue.h>

/* trng register offset */
#define STARFIVE_CTRL			0x00
#define STARFIVE_STAT			0x04
#define STARFIVE_MODE			0x08
#define STARFIVE_SMODE			0x0C
#define STARFIVE_IE			0x10
#define STARFIVE_ISTAT			0x14
#define STARFIVE_RAND0			0x20
#define STARFIVE_RAND1			0x24
#define STARFIVE_RAND2			0x28
#define STARFIVE_RAND3			0x2C
#define STARFIVE_RAND4			0x30
#define STARFIVE_RAND5			0x34
#define STARFIVE_RAND6			0x38
#define STARFIVE_RAND7			0x3C
#define STARFIVE_AUTO_RQSTS		0x60
#define STARFIVE_AUTO_AGE		0x64

/* CTRL CMD */
#define STARFIVE_CTRL_EXEC_NOP		0x0
#define STARFIVE_CTRL_GENE_RANDNUM	0x1
#define STARFIVE_CTRL_EXEC_RANDRESEED	0x2

/* STAT */
#define STARFIVE_STAT_NONCE_MODE	BIT(2)
#define STARFIVE_STAT_R256		BIT(3)
#define STARFIVE_STAT_MISSION_MODE	BIT(8)
#define STARFIVE_STAT_SEEDED		BIT(9)
#define STARFIVE_STAT_LAST_RESEED(x)	((x) << 16)
#define STARFIVE_STAT_SRVC_RQST		BIT(27)
#define STARFIVE_STAT_RAND_GENERATING	BIT(30)
#define STARFIVE_STAT_RAND_SEEDING	BIT(31)

/* MODE */
#define STARFIVE_MODE_R256		BIT(3)

/* SMODE */
#define STARFIVE_SMODE_NONCE_MODE	BIT(2)
#define STARFIVE_SMODE_MISSION_MODE	BIT(8)
#define STARFIVE_SMODE_MAX_REJECTS(x)	((x) << 16)

/* IE */
#define STARFIVE_IE_RAND_RDY_EN		BIT(0)
#define STARFIVE_IE_SEED_DONE_EN	BIT(1)
#define STARFIVE_IE_LFSR_LOCKUP_EN	BIT(4)
#define STARFIVE_IE_GLBL_EN		BIT(31)

#define STARFIVE_IE_ALL			(STARFIVE_IE_GLBL_EN | \
					 STARFIVE_IE_RAND_RDY_EN | \
					 STARFIVE_IE_SEED_DONE_EN | \
					 STARFIVE_IE_LFSR_LOCKUP_EN)

/* ISTAT */
#define STARFIVE_ISTAT_RAND_RDY		BIT(0)
#define STARFIVE_ISTAT_SEED_DONE	BIT(1)
#define STARFIVE_ISTAT_LFSR_LOCKUP	BIT(4)

#define STARFIVE_ISTAT_ALL		(STARFIVE_ISTAT_RAND_RDY | \
					 STARFIVE_ISTAT_SEED_DONE | \
					 STARFIVE_ISTAT_LFSR_LOCKUP)

#define STARFIVE_RAND_LEN		sizeof(u32)
#define STARFIVE_RANDRESEED_TIMEOUT_MS	50
#define STARFIVE_RANDGEN_TIMEOUT_MS	20
#define STARFIVE_RANDGEN_NOWAIT_TIMEOUT	1

#define to_trng(p)			container_of(p, struct starfive_trng, rng)

enum starfive_trng_mode {
	PRNG_128BIT,
	PRNG_256BIT,
};

/*
 * Power-down ordering of reset assertion vs. clock gating:
 * SEQ_RST_FIRST - assert reset, then gate the clocks (JH7110).
 * SEQ_CLK_FIRST - gate the clocks, then assert reset (JHB100). Asserting
 *                 reset with the clocks running causes reset-domain-crossing
 *                 glitches that can affect downstream IPs.
 */
enum seq_rst_clk {
	SEQ_RST_FIRST,
	SEQ_CLK_FIRST,
};

struct starfive_trng_data {
	enum seq_rst_clk	seq_rst_clk;
};

struct starfive_trng {
	struct device		*dev;
	void __iomem		*base;
	int			irq;
	struct clk		*hclk;
	struct clk		*ahb;
	struct reset_control	*rst;
	struct hwrng		rng;
	struct completion	random_done;
	struct completion	reseed_done;
	struct work_struct	work;
	const struct starfive_trng_data *data;
	u32			mode;
	u32			mission;
	bool			need_reseed;
	bool			initialized;
	bool			clk_on;
	bool			rst_deassert;
	struct mutex		lock; /* protect trng cmd seq */
};

static inline struct starfive_trng *work_to_trng(struct work_struct *work)
{
	return container_of(work, struct starfive_trng, work);
}

static u16 autoreq;
module_param(autoreq, ushort, 0);
MODULE_PARM_DESC(autoreq, "Auto-reseeding after random number requests by host reaches specified counter:\n"
				" 0 - disable counter\n"
				" other - reload value for internal counter");

static u16 autoage;
module_param(autoage, ushort, 0);
MODULE_PARM_DESC(autoage, "Auto-reseeding after specified timer countdowns to 0:\n"
				" 0 - disable timer\n"
				" other - reload value for internal timer");

static bool starfive_trng_idle(struct starfive_trng *trng, bool wait)
{
	u32 stat, busy = STARFIVE_STAT_RAND_GENERATING | STARFIVE_STAT_RAND_SEEDING;

	if (!wait)
		return !(readl_relaxed(trng->base + STARFIVE_STAT) & busy);

	return !readl_relaxed_poll_timeout(trng->base + STARFIVE_STAT, stat,
					   !(stat & busy),
					   10, 100000);
}

/*
 * Record a pending LFSR lockup and make sure it gets serviced. queue_work()
 * is a no-op while the work is already pending, so this is safe to call
 * from any context that notices the lockup.
 */
static void starfive_trng_request_reseed(struct starfive_trng *trng)
{
	WRITE_ONCE(trng->need_reseed, true);
	queue_work(system_freezable_wq, &trng->work);
}

static void starfive_trng_irq_clear(struct starfive_trng *trng)
{
	u32 istat = readl(trng->base + STARFIVE_ISTAT);

	/* Do not lose an LFSR lockup that has not been serviced yet. */
	if ((istat & STARFIVE_ISTAT_LFSR_LOCKUP) && trng->initialized)
		starfive_trng_request_reseed(trng);

	writel(istat, trng->base + STARFIVE_ISTAT);
}

static int starfive_trng_power_on(struct starfive_trng *trng)
{
	int ret;

	if (!trng->clk_on) {
		ret = clk_prepare_enable(trng->hclk);
		if (ret)
			goto err_hclk;

		ret = clk_prepare_enable(trng->ahb);
		if (ret)
			goto err_ahb;

		trng->clk_on = true;
	}

	if (!trng->rst_deassert) {
		ret = reset_control_deassert(trng->rst);
		if (ret)
			goto err_rst;

		trng->rst_deassert = true;
	}

	return 0;

err_rst:
	clk_disable_unprepare(trng->ahb);
err_ahb:
	clk_disable_unprepare(trng->hclk);
	trng->clk_on = false;
err_hclk:
	return ret;
}

static void starfive_trng_power_off(struct starfive_trng *trng, bool assert_rst)
{
	bool clk_first = trng->data->seq_rst_clk == SEQ_CLK_FIRST;
	bool do_rst = assert_rst && trng->rst_deassert;

	if (do_rst && !clk_first) {
		reset_control_assert(trng->rst);
		trng->rst_deassert = false;
	}

	if (trng->clk_on) {
		clk_disable_unprepare(trng->ahb);
		clk_disable_unprepare(trng->hclk);
		trng->clk_on = false;
	}

	if (do_rst && clk_first) {
		reset_control_assert(trng->rst);
		trng->rst_deassert = false;
	}
}

static void starfive_trng_power_off_action(void *data)
{
	starfive_trng_power_off(data, true);
}

static int starfive_trng_cmd(struct starfive_trng *trng, u32 cmd, unsigned long timeout, bool wait)
{
	struct completion *done;

	lockdep_assert_held(&trng->lock);

	if (!starfive_trng_idle(trng, wait))
		return wait ? -ETIMEDOUT : -EBUSY;

	switch (cmd) {
	case STARFIVE_CTRL_GENE_RANDNUM:
		done = &trng->random_done;
		break;
	case STARFIVE_CTRL_EXEC_RANDRESEED:
		done = &trng->reseed_done;
		break;
	default:
		return -EINVAL;
	}

	/*
	 * A command that timed out earlier may still have its completion
	 * interrupt in flight. Ack the status bits and flush the handler so
	 * a late RAND_RDY/SEED_DONE cannot complete this command.
	 */
	writel(STARFIVE_ISTAT_RAND_RDY | STARFIVE_ISTAT_SEED_DONE,
	       trng->base + STARFIVE_ISTAT);
	synchronize_irq(trng->irq);

	reinit_completion(done);
	writel(cmd, trng->base + STARFIVE_CTRL);
	if (!wait_for_completion_timeout(done, timeout)) {
		synchronize_irq(trng->irq);
		if (!try_wait_for_completion(done))
			return -ETIMEDOUT;
	}

	return 0;
}

static int starfive_trng_reseed(struct starfive_trng *trng)
{
	int ret;

	lockdep_assert_held(&trng->lock);

	WRITE_ONCE(trng->need_reseed, false);
	ret = starfive_trng_cmd(trng, STARFIVE_CTRL_EXEC_RANDRESEED,
				msecs_to_jiffies(STARFIVE_RANDRESEED_TIMEOUT_MS), true);
	if (ret)
		WRITE_ONCE(trng->need_reseed, true);

	return ret;
}

static void starfive_trng_hw_setup(struct starfive_trng *trng)
{
	u32 mode;

	/* setup Auto Request/Age register */
	writel(autoage, trng->base + STARFIVE_AUTO_AGE);
	writel(autoreq, trng->base + STARFIVE_AUTO_RQSTS);

	mode = readl(trng->base + STARFIVE_MODE);
	if (trng->mode == PRNG_128BIT)
		mode &= ~STARFIVE_MODE_R256;
	else
		mode |= STARFIVE_MODE_R256;
	writel(mode, trng->base + STARFIVE_MODE);
}

static int starfive_trng_init(struct hwrng *rng)
{
	struct starfive_trng *trng = to_trng(rng);
	int ret;

	ret = pm_runtime_resume_and_get(trng->dev);
	if (ret < 0) {
		dev_err(trng->dev, "Failed to wake device for init: %d\n", ret);
		return ret;
	}

	mutex_lock(&trng->lock);

	/*
	 * The hwrng core can call init again without an intervening
	 * cleanup: deselecting and quickly reselecting the device makes
	 * cleanup_rng_work() skip ->cleanup() once the refcount is back up.
	 * Only bring up the interrupt line once in that case.
	 */
	if (!trng->initialized) {
		starfive_trng_irq_clear(trng);
		starfive_trng_hw_setup(trng);

		enable_irq(trng->irq);
		writel(STARFIVE_IE_ALL, trng->base + STARFIVE_IE);
		trng->initialized = true;
	}

	ret = starfive_trng_reseed(trng);
	if (ret) {
		trng->initialized = false;
		writel(0, trng->base + STARFIVE_IE);
		starfive_trng_irq_clear(trng);
		disable_irq(trng->irq);
	}

	mutex_unlock(&trng->lock);

	pm_runtime_put_autosuspend(trng->dev);

	return ret;
}

static void starfive_trng_reseed_work(struct work_struct *work)
{
	struct starfive_trng *trng = work_to_trng(work);
	int ret;

	ret = pm_runtime_resume_and_get(trng->dev);
	if (ret < 0) {
		dev_err(trng->dev, "Failed to wake device for reseed: %d\n", ret);
		return;
	}

	mutex_lock(&trng->lock);

	if (!READ_ONCE(trng->need_reseed) || !trng->initialized)
		goto unlock;

	ret = starfive_trng_reseed(trng);
	if (ret)
		dev_err(trng->dev, "Reseed after LFSR lockup failed: %d\n", ret);

unlock:
	mutex_unlock(&trng->lock);

	pm_runtime_put_autosuspend(trng->dev);
}

static irqreturn_t starfive_trng_irq(int irq, void *priv)
{
	u32 status;
	struct starfive_trng *trng = priv;

	status = readl(trng->base + STARFIVE_ISTAT) & STARFIVE_ISTAT_ALL;
	if (!status)
		return IRQ_NONE;

	writel(status, trng->base + STARFIVE_ISTAT);

	/* SEU occurred, reseeding required */
	if (status & STARFIVE_ISTAT_LFSR_LOCKUP)
		starfive_trng_request_reseed(trng);

	if (status & STARFIVE_ISTAT_RAND_RDY)
		complete(&trng->random_done);

	if (status & STARFIVE_ISTAT_SEED_DONE)
		complete(&trng->reseed_done);

	return IRQ_HANDLED;
}

static void starfive_trng_cleanup(struct hwrng *rng)
{
	struct starfive_trng *trng = to_trng(rng);
	bool initialized;
	int ret;

	ret = pm_runtime_resume_and_get(trng->dev);
	if (ret < 0)
		dev_err(trng->dev, "Failed to wake device for cleanup: %d\n", ret);

	mutex_lock(&trng->lock);
	initialized = trng->initialized;
	trng->initialized = false;
	if (ret >= 0 && initialized) {
		writel(0, trng->base + STARFIVE_IE);
		starfive_trng_irq_clear(trng);
	}
	mutex_unlock(&trng->lock);

	/*
	 * cleanup also runs after a failed init, which has already undone
	 * its enable_irq(). Only disable the line if init left it enabled.
	 */
	if (initialized)
		disable_irq(trng->irq);
	cancel_work_sync(&trng->work);

	if (ret < 0)
		return;

	mutex_lock(&trng->lock);
	writel(STARFIVE_CTRL_EXEC_NOP, trng->base + STARFIVE_CTRL);
	mutex_unlock(&trng->lock);

	pm_runtime_put_sync_suspend(trng->dev);
}

static int starfive_trng_read(struct hwrng *rng, void *buf, size_t max, bool wait)
{
	struct starfive_trng *trng = to_trng(rng);
	unsigned long timeout;
	int ret, retry = 1;

	ret = pm_runtime_resume_and_get(trng->dev);
	if (ret < 0) {
		dev_warn_ratelimited(trng->dev, "Failed to wake device for read: %d\n", ret);
		return ret;
	}

	if (wait) {
		mutex_lock(&trng->lock);
		timeout = msecs_to_jiffies(STARFIVE_RANDGEN_TIMEOUT_MS);
	} else {
		/* allow up to 1 jiffy for wait == 0 */
		if (!mutex_trylock(&trng->lock)) {
			ret = 0;
			goto out_put;
		}
		timeout = STARFIVE_RANDGEN_NOWAIT_TIMEOUT;
	}

	for (;;) {
		/*
		 * A pending LFSR lockup taints the next sample. Blocking
		 * callers reseed here; non-blocking callers return no data
		 * and leave it to the reseed work. Re-queue it explicitly:
		 * the lockup may have been seen by starfive_trng_irq_clear()
		 * or a previous reseed attempt may have failed.
		 */
		if (READ_ONCE(trng->need_reseed)) {
			if (!wait) {
				starfive_trng_request_reseed(trng);
				ret = 0;
				goto out_unlock;
			}
			ret = starfive_trng_reseed(trng);
			if (ret)
				goto out_unlock;
		}

		ret = starfive_trng_cmd(trng, STARFIVE_CTRL_GENE_RANDNUM, timeout, wait);
		if (ret) {
			if (!wait && (ret == -EBUSY || ret == -ETIMEDOUT))
				ret = 0;
			goto out_unlock;
		}

		/* Lockup reported together with RAND_RDY: reseed and retry once */
		if (!READ_ONCE(trng->need_reseed))
			break;

		if (!wait || !retry--) {
			ret = 0;
			goto out_unlock;
		}
	}

	if (trng->mode == PRNG_256BIT)
		max = min(max, STARFIVE_RAND_LEN * 8);
	else
		max = min(max, STARFIVE_RAND_LEN * 4);

	memcpy_fromio(buf, trng->base + STARFIVE_RAND0, max);

	ret = max;

out_unlock:
	mutex_unlock(&trng->lock);

out_put:
	pm_runtime_put_autosuspend(trng->dev);

	return ret;
}

static int starfive_trng_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct starfive_trng *trng;
	int ret;

	trng = devm_kzalloc_obj(dev, *trng);
	if (!trng)
		return -ENOMEM;

	platform_set_drvdata(pdev, trng);

	trng->dev = dev;
	trng->data = device_get_match_data(dev);
	if (!trng->data)
		return dev_err_probe(dev, -ENODEV, "No match data\n");

	trng->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(trng->base))
		return dev_err_probe(dev, PTR_ERR(trng->base),
				     "Error remapping memory for platform device\n");

	trng->irq = platform_get_irq(pdev, 0);
	if (trng->irq < 0)
		return trng->irq;

	init_completion(&trng->random_done);
	init_completion(&trng->reseed_done);

	ret = devm_mutex_init(dev, &trng->lock);
	if (ret)
		return ret;

	trng->hclk = devm_clk_get(dev, "hclk");
	if (IS_ERR(trng->hclk))
		return dev_err_probe(dev, PTR_ERR(trng->hclk),
				     "Error getting hardware reference clock\n");

	trng->ahb = devm_clk_get(dev, "ahb");
	if (IS_ERR(trng->ahb))
		return dev_err_probe(dev, PTR_ERR(trng->ahb),
				     "Error getting ahb reference clock\n");

	trng->rst = devm_reset_control_get_shared(dev, NULL);
	if (IS_ERR(trng->rst))
		return dev_err_probe(dev, PTR_ERR(trng->rst),
				     "Error getting hardware reset line\n");

	ret = starfive_trng_power_on(trng);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to power on\n");

	ret = devm_add_action_or_reset(dev, starfive_trng_power_off_action, trng);
	if (ret)
		return ret;

	trng->rng.name = dev_driver_string(dev);
	trng->rng.init = starfive_trng_init;
	trng->rng.cleanup = starfive_trng_cleanup;
	trng->rng.read = starfive_trng_read;

	trng->mode = PRNG_256BIT;
	trng->mission = 1;

	pm_runtime_use_autosuspend(dev);
	pm_runtime_set_autosuspend_delay(dev, 100);

	ret = devm_pm_runtime_set_active_enabled(dev);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to enable runtime PM\n");

	ret = devm_work_autocancel(dev, &trng->work, starfive_trng_reseed_work);
	if (ret)
		return ret;

	ret = devm_request_irq(dev, trng->irq, starfive_trng_irq, IRQF_NO_AUTOEN,
			       dev_name(dev), trng);
	if (ret)
		return ret;

	ret = devm_hwrng_register(dev, &trng->rng);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to register hwrng\n");

	pm_runtime_idle(dev);

	return 0;
}

static int starfive_trng_suspend(struct device *dev)
{
	struct starfive_trng *trng = dev_get_drvdata(dev);
	bool assert_rst;

	mutex_lock(&trng->lock);
	assert_rst = !trng->initialized;
	writel(0, trng->base + STARFIVE_IE);
	starfive_trng_irq_clear(trng);
	mutex_unlock(&trng->lock);

	synchronize_irq(trng->irq);
	starfive_trng_power_off(trng, assert_rst);

	return 0;
}

static int starfive_trng_resume(struct device *dev)
{
	struct starfive_trng *trng = dev_get_drvdata(dev);
	int ret;

	ret = starfive_trng_power_on(trng);
	if (ret) {
		dev_err(dev, "Failed to power on: %d\n", ret);
		return ret;
	}

	if (trng->initialized) {
		starfive_trng_irq_clear(trng);
		writel(STARFIVE_IE_ALL, trng->base + STARFIVE_IE);
	}

	return 0;
}

static const struct starfive_trng_data jh7110_data = {
	.seq_rst_clk = SEQ_RST_FIRST,
};

static const struct starfive_trng_data jhb100_data = {
	.seq_rst_clk = SEQ_CLK_FIRST,
};

static const struct of_device_id trng_dt_ids[] = {
	{ .compatible = "starfive,jh7110-trng", .data = &jh7110_data },
	{ .compatible = "starfive,jhb100-trng", .data = &jhb100_data },
	{ }
};
MODULE_DEVICE_TABLE(of, trng_dt_ids);

static DEFINE_RUNTIME_DEV_PM_OPS(starfive_trng_pm_ops,
				 starfive_trng_suspend, starfive_trng_resume, NULL);

static struct platform_driver starfive_trng_driver = {
	.probe	= starfive_trng_probe,
	.driver	= {
		.name		= "jh7110-trng",
		.pm		= pm_ptr(&starfive_trng_pm_ops),
		.of_match_table	= trng_dt_ids,
	},
};

module_platform_driver(starfive_trng_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("StarFive True Random Number Generator");
