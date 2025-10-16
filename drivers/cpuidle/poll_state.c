// SPDX-License-Identifier: GPL-2.0-only
/*
 * poll_state.c - Polling idle state
 */

#include <linux/cpuidle.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/sched/idle.h>

static int __cpuidle poll_idle(struct cpuidle_device *dev,
			       struct cpuidle_driver *drv, int index)
{
	u64 time_end;
	u32 flags = 0;

	dev->poll_time_limit = false;

	time_end = local_clock_noinstr() + cpuidle_poll_time(drv, dev);

	raw_local_irq_enable();
	if (!current_set_polling_and_test())
		flags = smp_cond_load_relaxed_timeout(&current_thread_info()->flags,
						      (VAL & _TIF_NEED_RESCHED),
						      (local_clock_noinstr() >= time_end));
	dev->poll_time_limit = !(flags & _TIF_NEED_RESCHED);

	raw_local_irq_disable();

	current_clr_polling();

	return index;
}

void cpuidle_poll_state_init(struct cpuidle_driver *drv)
{
	struct cpuidle_state *state = &drv->states[0];

	snprintf(state->name, CPUIDLE_NAME_LEN, "POLL");
	snprintf(state->desc, CPUIDLE_DESC_LEN, "CPUIDLE CORE POLL IDLE");
	state->exit_latency = 0;
	state->target_residency = 0;
	state->exit_latency_ns = 0;
	state->target_residency_ns = 0;
	state->power_usage = -1;
	state->enter = poll_idle;
	state->flags = CPUIDLE_FLAG_POLLING;
}
EXPORT_SYMBOL_GPL(cpuidle_poll_state_init);
