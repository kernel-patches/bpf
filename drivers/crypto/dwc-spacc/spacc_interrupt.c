// SPDX-License-Identifier: GPL-2.0

#include <linux/interrupt.h>
#include <linux/minmax.h>
#include <crypto/scatterwalk.h>
#include <linux/platform_device.h>
#include "spacc_core.h"

static inline u32 _spacc_get_stat_cnt(struct spacc_device *spacc)
{
	u32 fifo;

	if (spacc->config.is_qos)
		fifo = SPACC_FIFO_STAT_STAT_CNT_GET_QOS(readl(spacc->regmap +
					SPACC_REG_FIFO_STAT));
	else
		fifo = SPACC_FIFO_STAT_STAT_CNT_GET(readl(spacc->regmap +
					SPACC_REG_FIFO_STAT));
	return fifo;
}

/* Map a SPAcc hardware status code to the errno reported for the job. */
static int spacc_status_to_err(struct spacc_device *spacc, u32 spacc_errcode)
{
	switch (spacc_errcode) {
	case SPACC_OK:
		return 0;
	case SPACC_ICVFAIL:
		return -EBADMSG;
	case SPACC_MEMERR:
	case SPACC_BLOCKERR:
		return -EINVAL;
	case SPACC_SECERR:
		return -EIO;
	default:
		dev_err(spacc->dptr, "Invalid SPAcc Error\n");
		return -EIO;
	}
}

/*
 * Pop one entry from the STATUS FIFO and dispatch its completion.
 *
 * Called with spacc->lock held. When the completed job has a callback,
 * the lock is dropped across that callback and re-acquired before return,
 * so the caller must re-sample any hardware state afterwards. Returns true
 * and stores the job status in *job_ret when a live job was dispatched;
 * false for a dropped/stale FIFO entry that maps to no live job (the FIFO
 * slot is still consumed either way).
 */
static bool spacc_pop_one_job(struct spacc_device *spacc,
			      unsigned long *lock_flag, int *job_ret)
{
	struct spacc_job *job;
	u32 cmdstat, swid;
	int ret;

	/* write the pop register to get the next job */
	writel(1, spacc->regmap + SPACC_REG_STAT_POP);
	cmdstat = readl(spacc->regmap + SPACC_REG_STATUS);

	swid = SPACC_STATUS_SW_ID_GET(cmdstat);

	if (swid >= SPACC_MAX_JOBS) {
		dev_warn(spacc->dptr, "out-of-range swid %u dropped\n", swid);
		return false;
	}
	if (spacc->job_lookup[swid] == SPACC_JOB_IDX_UNUSED) {
		dev_warn(spacc->dptr, "stale swid %u dropped\n", swid);
		return false;
	}

	job = &spacc->job[spacc->job_lookup[swid]];

	/*
	 * Release the swid before running the callback so a duplicate/stale
	 * STATUS entry for this swid is dropped on the next pass. A
	 * HW-completed job is dispatched here exactly once; buffered jobs that
	 * never reached HW are dispatched only by spacc_process_jb(). The two
	 * sets are disjoint, so each job's cb runs once.
	 */
	spacc->job_lookup[swid] = SPACC_JOB_IDX_UNUSED;

	ret = spacc_status_to_err(spacc, SPACC_GET_STATUS_RET_CODE(cmdstat));
	job->job_err = ret;

	if (spacc->autodetect) {
		/* Pairs with smp_load_acquire() in the sync waiters. */
		smp_store_release(&job->job_done, 1);
		wake_up(&job->waitq);
	}

	if (job->cb) {
		spacc_callback cb = job->cb;
		void *cbdata = job->cbdata;

		/*
		 * Done touching the SPAcc hw: drop the lock across the job
		 * callback and re-acquire it before returning to the caller.
		 */
		spin_unlock_irqrestore(&spacc->lock, *lock_flag);
		cb(spacc, cbdata);
		spin_lock_irqsave(&spacc->lock, *lock_flag);
	} else if (!spacc->autodetect) {
		/*
		 * Pairs with smp_load_acquire() in the synchronous waiters
		 * (autodetect, xcbc key computation).
		 */
		smp_store_release(&job->job_done, 1);
		wake_up(&job->waitq);
	}

	*job_ret = ret;
	return true;
}

static int spacc_pop_packets_ex(struct spacc_device *spacc, int *num_popped,
				unsigned long *lock_flag)
{
	int jobs;
	int ret = -EINPROGRESS;

	*num_popped = 0;

	/*
	 * Re-sample the STATUS FIFO count on each outer pass: jobs can
	 * complete while we process a batch (spacc_pop_one_job() drops the
	 * lock across each callback), so keep draining until the FIFO reports
	 * empty instead of servicing only the count seen on entry.
	 */
	while ((jobs = _spacc_get_stat_cnt(spacc))) {
		while (jobs-- > 0) {
			if (spacc_pop_one_job(spacc, lock_flag, &ret))
				(*num_popped)++;
		}
	}

	if (!*num_popped)
		dev_dbg(spacc->dptr, "Failed to pop a single job\n");

	spacc_process_jb(spacc, lock_flag);

	/* reset the WD timer to the original value */
	if (spacc->op_mode == SPACC_OP_MODE_WD) {
		spacc->config.wd_timer = spacc->config.timer;
		spacc_set_wd_count(spacc, spacc->config.wd_timer);
	}

	if (*num_popped && spacc->spacc_notify_jobs)
		spacc->spacc_notify_jobs(spacc);

	return ret;
}

int spacc_pop_packets(struct spacc_device *spacc, int *num_popped)
{
	int err = 0;
	unsigned long lock_flag;

	spin_lock_irqsave(&spacc->lock, lock_flag);
	err = spacc_pop_packets_ex(spacc, num_popped, &lock_flag);
	spin_unlock_irqrestore(&spacc->lock, lock_flag);

	return err;
}

u32 spacc_process_irq(struct spacc_device *spacc)
{
	u32 irq_status;
	u32 handled = 0;
	int x, cmd_max;
	unsigned long lock_flag;

	spin_lock_irqsave(&spacc->lock, lock_flag);

	/* Only look at sources that are actually enabled. */
	irq_status = readl(spacc->regmap + SPACC_REG_IRQ_STAT) &
		     readl(spacc->regmap + SPACC_REG_IRQ_EN);

	/* clear interrupt pin and run registered callback */
	if (irq_status & SPACC_IRQ_STAT_STAT) {
		handled |= SPACC_IRQ_STAT_STAT;
		SPACC_IRQ_STAT_CLEAR_STAT(spacc);
		if (spacc->op_mode == SPACC_OP_MODE_IRQ &&
				spacc->wd_cnt_limit) {
			spacc_irq_cmdx_disable(spacc, 0);
			spacc_irq_stat_enable(spacc,
					spacc->config.ideal_stat_level);
			spacc_irq_stat_wd_enable(spacc);
			spacc->wdcnt = 0;
			spacc->op_mode = SPACC_OP_MODE_WD;
			spacc->wd_cnt_limit = false;
		} else if (spacc->op_mode == SPACC_OP_MODE_IRQ) {
			spacc->config.fifo_cnt <<= 2;
			spacc->config.fifo_cnt = min(spacc->config.fifo_cnt,
					spacc->config.stat_fifo_depth);

			/* update fifo count to allow more stats to pile up */
			spacc_irq_stat_enable(spacc, spacc->config.fifo_cnt);

			/*
			 * Re-arm CMD0: cmdx_cnt == 0 selects the "command FIFO
			 * empty" level. Per the IRQ_CTRL spec the interrupt is
			 * generated when the FIFO *reaches* that level (edge),
			 * not held while at it, so re-arming while empty cannot
			 * self-retrigger.
			 */
			spacc_irq_cmdx_enable(spacc, 0, 0);
		}
		if (spacc->irq_cb_stat)
			spacc->irq_cb_stat(spacc);
	}

	/* watchdog IRQ */
	if (spacc->op_mode == SPACC_OP_MODE_WD &&
			irq_status & SPACC_IRQ_STAT_STAT_WD) {
		handled |= SPACC_IRQ_STAT_STAT_WD;
		if (++spacc->wdcnt == SPACC_WD_LIMIT) {
			/*
			 * This happens when you get too many IRQs that
			 * go unanswered
			 */
			spacc_irq_stat_wd_disable(spacc);

			/*
			 * We set the STAT CNT to 1 so that every job
			 * generates an IRQ now
			 */
			spacc_irq_stat_enable(spacc, 1);
			spacc->op_mode = SPACC_OP_MODE_IRQ;
			spacc->wd_cnt_limit = true;
		} else if (spacc->config.wd_timer < (0xFFFFFFUL >> 4)) {
			/*
			 * If the timer isn't too high lets bump it up
			 * a bit so as to give the IRQ a chance to
			 * reply
			 */
			spacc->config.wd_timer <<= 4;
			spacc_set_wd_count(spacc, spacc->config.wd_timer);
		}

		SPACC_IRQ_STAT_CLEAR_STAT_WD(spacc);
		if (spacc->irq_cb_stat_wd)
			spacc->irq_cb_stat_wd(spacc);
	}

	if (spacc->op_mode == SPACC_OP_MODE_IRQ) {
		cmd_max = (spacc->config.is_qos ? SPACC_CMDX_MAX_QOS :
				SPACC_CMDX_MAX);
		for (x = 0; x < cmd_max; x++) {
			if (irq_status & SPACC_IRQ_STAT_CMDX(x)) {
				handled |= SPACC_IRQ_STAT_CMDX(x);
				spacc->config.fifo_cnt = 1;

				/* disable CMD0 interrupt since STAT=1 */
				spacc_irq_cmdx_disable(spacc, x);
				spacc_irq_stat_enable(spacc,
						spacc->config.fifo_cnt);

				SPACC_IRQ_STAT_CLEAR_CMDX(spacc, x);

				/* run registered callback */
				if (spacc->irq_cb_cmdx)
					spacc->irq_cb_cmdx(spacc, x);
			}
		}
	}

	spin_unlock_irqrestore(&spacc->lock, lock_flag);

	return handled;
}

void spacc_set_wd_count(struct spacc_device *spacc, u32 val)
{
	writel(val, spacc->regmap + SPACC_REG_STAT_WD_CTRL);
}

/*
 * cmdx and cmdx_cnt depend on HW config
 * cmdx can be 0, 1 or 2
 * cmdx_cnt must be 2^6 or less
 */
void spacc_irq_cmdx_enable(struct spacc_device *spacc, int cmdx, int cmdx_cnt)
{
	u32 reg_val;

	/* read the reg, clear the bit range and set the new value */
	reg_val = readl(spacc->regmap + SPACC_REG_IRQ_CTRL) &
		(~SPACC_IRQ_CTRL_CMDX_CNT_MASK(cmdx));
	reg_val |= SPACC_IRQ_CTRL_CMDX_CNT_SET(cmdx, cmdx_cnt);

	writel(reg_val | SPACC_IRQ_CTRL_CMDX_CNT_SET(cmdx, cmdx_cnt),
	       spacc->regmap + SPACC_REG_IRQ_CTRL);

	writel(readl(spacc->regmap + SPACC_REG_IRQ_EN) | SPACC_IRQ_EN_CMD(cmdx),
	       spacc->regmap + SPACC_REG_IRQ_EN);
}

void spacc_irq_cmdx_disable(struct spacc_device *spacc, int cmdx)
{
	writel(readl(spacc->regmap + SPACC_REG_IRQ_EN) &
	       (~SPACC_IRQ_EN_CMD(cmdx)), spacc->regmap + SPACC_REG_IRQ_EN);
}

void spacc_irq_stat_enable(struct spacc_device *spacc, int stat_cnt)
{
	u32 reg_val;

	reg_val = readl(spacc->regmap + SPACC_REG_IRQ_CTRL);
	if (spacc->config.is_qos) {
		reg_val &= (~SPACC_IRQ_CTRL_STAT_CNT_MASK_QOS);
		reg_val |= SPACC_IRQ_CTRL_STAT_CNT_SET_QOS(stat_cnt);
	} else {
		reg_val &= (~SPACC_IRQ_CTRL_STAT_CNT_MASK);
		reg_val |= SPACC_IRQ_CTRL_STAT_CNT_SET(stat_cnt);
	}

	writel(reg_val, spacc->regmap + SPACC_REG_IRQ_CTRL);
	writel(readl(spacc->regmap + SPACC_REG_IRQ_EN) | SPACC_IRQ_EN_STAT,
	       spacc->regmap + SPACC_REG_IRQ_EN);
}

void spacc_irq_stat_disable(struct spacc_device *spacc)
{
	writel(readl(spacc->regmap + SPACC_REG_IRQ_EN) & (~SPACC_IRQ_EN_STAT),
	       spacc->regmap + SPACC_REG_IRQ_EN);
}

void spacc_irq_stat_wd_enable(struct spacc_device *spacc)
{
	writel(readl(spacc->regmap + SPACC_REG_IRQ_EN) | SPACC_IRQ_EN_STAT_WD,
	       spacc->regmap + SPACC_REG_IRQ_EN);
}

void spacc_irq_stat_wd_disable(struct spacc_device *spacc)
{
	writel(readl(spacc->regmap + SPACC_REG_IRQ_EN) &
	       (~SPACC_IRQ_EN_STAT_WD), spacc->regmap + SPACC_REG_IRQ_EN);
}

void spacc_irq_glbl_enable(struct spacc_device *spacc)
{
	writel(readl(spacc->regmap + SPACC_REG_IRQ_EN) | SPACC_IRQ_EN_GLBL,
	       spacc->regmap + SPACC_REG_IRQ_EN);
}

void spacc_irq_glbl_disable(struct spacc_device *spacc)
{
	writel(readl(spacc->regmap + SPACC_REG_IRQ_EN) & (~SPACC_IRQ_EN_GLBL),
	       spacc->regmap + SPACC_REG_IRQ_EN);
}

/* Function to run callbacks in the IRQ handler */
irqreturn_t spacc_irq_handler(int irq, void *dev)
{
	struct spacc_priv *priv = platform_get_drvdata(to_platform_device(dev));
	struct spacc_device *spacc = &priv->spacc;

	/* check irq flags and process as required */
	if (!spacc_process_irq(spacc))
		return IRQ_NONE;

	return IRQ_HANDLED;
}
