// SPDX-License-Identifier: MIT
/*
 * Copyright © 2026 Intel Corporation
 */

#include <linux/delay.h>

#include <drm/drm_print.h>

#include "intel_de.h"
#include "intel_display_regs.h"
#include "intel_display_rpm.h"
#include "intel_uncore.h"
#include "intel_uncore_trace.h"

static inline struct intel_uncore *__to_uncore(struct intel_display *display)
{
	return display->mmio.uncore;
}

static int intel_de_wait_for_register(struct intel_display *display,
				      intel_reg_t reg, u32 mask, u32 value,
				      unsigned int timeout_us,
				      u32 (*read)(struct intel_display *display, intel_reg_t reg),
				      u32 *out_val, bool is_atomic)
{
	const ktime_t end = ktime_add_us(ktime_get_raw(), timeout_us);
	int wait_max = 1000;
	int wait = 10;
	u32 reg_value;
	int ret;

	might_sleep_if(!is_atomic);

	if (timeout_us <= 10) {
		is_atomic = true;
		wait = 1;
	}

	for (;;) {
		bool expired = ktime_after(ktime_get_raw(), end);

		/* guarantee the condition is evaluated after timeout expired */
		barrier();

		reg_value = read(display, reg);
		if ((reg_value & mask) == value) {
			ret = 0;
			break;
		}

		if (expired) {
			ret = -ETIMEDOUT;
			break;
		}

		if (is_atomic)
			udelay(wait);
		else
			usleep_range(wait, wait << 1);

		if (wait < wait_max)
			wait <<= 1;
	}

	if (out_val)
		*out_val = reg_value;

	return ret;
}

int intel_de_wait_us(struct intel_display *display, intel_reg_t reg,
		     u32 mask, u32 value, unsigned int timeout_us,
		     u32 *out_value)
{
	int ret;

	intel_dmc_wl_get(display, reg);

	ret = intel_de_wait_for_register(display, reg, mask, value,
					 timeout_us,
					 intel_de_read,
					 out_value, false);

	intel_dmc_wl_put(display, reg);

	return ret;
}

int intel_de_wait_ms(struct intel_display *display, intel_reg_t reg,
		     u32 mask, u32 value, unsigned int timeout_ms,
		     u32 *out_value)
{
	int ret;

	intel_dmc_wl_get(display, reg);

	ret = intel_de_wait_for_register(display, reg, mask, value,
					 timeout_ms * 1000,
					 intel_de_read,
					 out_value, false);

	intel_dmc_wl_put(display, reg);

	return ret;
}

int intel_de_wait_fw_ms(struct intel_display *display, intel_reg_t reg,
			u32 mask, u32 value, unsigned int timeout_ms,
			u32 *out_value)
{
	return intel_de_wait_for_register(display, reg, mask, value,
					  timeout_ms * 1000,
					  intel_de_read_fw,
					  out_value, false);
}

int intel_de_wait_fw_us_atomic(struct intel_display *display, intel_reg_t reg,
			       u32 mask, u32 value, unsigned int timeout_us,
			       u32 *out_value)
{
	return intel_de_wait_for_register(display, reg, mask, value,
					  timeout_us,
					  intel_de_read_fw,
					  out_value, true);
}

int intel_de_wait_for_set_us(struct intel_display *display, intel_reg_t reg,
			     u32 mask, unsigned int timeout_us)
{
	return intel_de_wait_us(display, reg, mask, mask, timeout_us, NULL);
}

int intel_de_wait_for_clear_us(struct intel_display *display, intel_reg_t reg,
			       u32 mask, unsigned int timeout_us)
{
	return intel_de_wait_us(display, reg, mask, 0, timeout_us, NULL);
}

int intel_de_wait_for_set_ms(struct intel_display *display, intel_reg_t reg,
			     u32 mask, unsigned int timeout_ms)
{
	return intel_de_wait_ms(display, reg, mask, mask, timeout_ms, NULL);
}

int intel_de_wait_for_clear_ms(struct intel_display *display, intel_reg_t reg,
			       u32 mask, unsigned int timeout_ms)
{
	return intel_de_wait_ms(display, reg, mask, 0, timeout_ms, NULL);
}

u8 intel_de_read8(struct intel_display *display, intel_reg_t reg)
{
	/* this is only used on VGA registers (possible on pre-g4x) */
	drm_WARN_ON(display->drm, DISPLAY_VER(display) >= 5 || display->platform.g4x);

	return intel_uncore_read8(__to_uncore(display), reg);
}

void intel_de_write8(struct intel_display *display, intel_reg_t reg, u8 val)
{
	drm_WARN_ON(display->drm, DISPLAY_VER(display) >= 5 || display->platform.g4x);

	intel_uncore_write8(__to_uncore(display), reg, val);
}

u16 intel_de_read16(struct intel_display *display, intel_reg_t reg)
{
	/* this is only used on MCHBAR registers on pre-SNB */
	drm_WARN_ON(display->drm, DISPLAY_VER(display) >= 6);

	return intel_uncore_read16(__to_uncore(display), reg);
}

static __always_inline u32
__intel_de_read_fw(struct intel_display *display, intel_reg_t reg)
{
	u32 val;

	val = intel_uncore_read_fw(__to_uncore(display), reg);
	trace_i915_reg_rw(false, reg, val, sizeof(val), true);

	return val;
}

static __always_inline void
__intel_de_write_fw(struct intel_display *display, intel_reg_t reg, u32 val)
{
	trace_i915_reg_rw(true, reg, val, sizeof(val), true);
	intel_uncore_write_fw(__to_uncore(display), reg, val);
}

u32 intel_de_read_fw(struct intel_display *display, intel_reg_t reg)
{
	return __intel_de_read_fw(display, reg);
}

void intel_de_write_fw(struct intel_display *display, intel_reg_t reg, u32 val)
{
	__intel_de_write_fw(display, reg, val);
}

static bool hsw_check_for_unclaimed_mmio(struct intel_display *display)
{
	u32 dbg;

	dbg = __intel_de_read_fw(display, FPGA_DBG);
	if (likely(!(dbg & FPGA_DBG_RM_NOCLAIM)))
		return false;

	/*
	 * Bugs in PCI programming (or failing hardware) can occasionally cause
	 * us to lose access to the MMIO BAR.  When this happens, register
	 * reads will come back with 0xFFFFFFFF for every register and things
	 * go bad very quickly.  Let's try to detect that special case and at
	 * least try to print a more informative message about what has
	 * happened.
	 *
	 * During normal operation the FPGA_DBG register has several unused
	 * bits that will always read back as 0's so we can use them as canaries
	 * to recognize when MMIO accesses are just busted.
	 */
	if (unlikely(dbg == ~0))
		drm_err(display->drm,
			"Lost access to MMIO BAR; all registers now read back as 0xFFFFFFFF!\n");

	__intel_de_write_fw(display, FPGA_DBG, FPGA_DBG_RM_NOCLAIM);

	return true;
}

static bool vlv_check_for_unclaimed_mmio(struct intel_display *display)
{
	u32 cer;

	cer = __intel_de_read_fw(display, CLAIM_ER);
	if (likely(!(cer & (CLAIM_ER_OVERFLOW | CLAIM_ER_CTR_MASK))))
		return false;

	__intel_de_write_fw(display, CLAIM_ER, CLAIM_ER_CLR);

	return true;
}

static void check_unclaimed_mmio_pre(struct intel_display *display,
				     intel_reg_t reg, bool write)
{
	if (!display->mmio.funcs->check_for_unclaimed_mmio(display))
		return;

	drm_dbg_kms(display->drm,
		    "Unclaimed access detected before %s register 0x%x\n",
		    write ? "write to" : "read from",
		    intel_reg_offset(reg));
}

static void check_unclaimed_mmio_post(struct intel_display *display,
				      intel_reg_t reg, bool write)
{
	if (!display->mmio.funcs->check_for_unclaimed_mmio(display))
		return;

	drm_WARN(display->drm, true,
		 "Unclaimed %s register 0x%x\n",
		 write ? "write to" : "read from",
		 intel_reg_offset(reg));

	WRITE_ONCE(display->mmio.mmio_debug_oneshot, false);
}

bool intel_de_unclaimed_mmio_detected(struct intel_display *display)
{
	bool ret;

	if (!display->mmio.funcs->check_for_unclaimed_mmio)
		return false;

	if (display->mmio.funcs->check_for_unclaimed_mmio_needs_lock) {
		spin_lock_irq(&display->mmio.lock);
		ret = display->mmio.funcs->check_for_unclaimed_mmio(display);
		spin_unlock_irq(&display->mmio.lock);
	} else {
		ret = display->mmio.funcs->check_for_unclaimed_mmio(display);
	}

	return ret;
}

bool intel_de_arm_unclaimed_mmio_detection(struct intel_display *display)
{
	if (!READ_ONCE(display->mmio.unclaimed_mmio_check))
		return false;

	if (!intel_de_unclaimed_mmio_detected(display))
		return false;

	if (!READ_ONCE(display->params.mmio_debug)) {
		drm_dbg_kms(display->drm,
			    "Unclaimed register detected, "
			    "enabling oneshot unclaimed register reporting. "
			    "Please use i915.mmio_debug=1 for more information.\n");
		WRITE_ONCE(display->mmio.mmio_debug_oneshot, true);
	}

	WRITE_ONCE(display->mmio.unclaimed_mmio_check, false);

	return true;
}

#define __MMIO_WAKELOCK		BIT(0)
#define __MMIO_LOCK		BIT(1)
#define __MMIO_UNCLAIMED	BIT(2)

static __always_inline void
__mmio_wakelock_pre(struct intel_display *display, intel_reg_t reg,
		    const unsigned int mmio_flags)
{
	if (mmio_flags & __MMIO_WAKELOCK)
		intel_dmc_wl_get(display, reg);
}

static __always_inline void
__mmio_wakelock_post(struct intel_display *display, intel_reg_t reg,
		     const unsigned int mmio_flags)
{
	if (mmio_flags & __MMIO_WAKELOCK)
		intel_dmc_wl_put(display, reg);
}

static __always_inline void
__mmio_lock_pre(struct intel_display *display, unsigned long *irqflags,
		const unsigned int mmio_flags)
{
	if (mmio_flags & __MMIO_LOCK)
		spin_lock_irqsave(&display->mmio.lock, *irqflags);
}

static __always_inline void
__mmio_lock_post(struct intel_display *display, unsigned long irqflags,
		 const unsigned int mmio_flags)
{
	if (mmio_flags & __MMIO_LOCK)
		spin_unlock_irqrestore(&display->mmio.lock, irqflags);
}

static __always_inline bool
__mmio_debug_is_enabled(struct intel_display *display)
{
	/* with || gcc emits two branches for this */
	return unlikely(!!READ_ONCE(display->params.mmio_debug) |
			READ_ONCE(display->mmio.mmio_debug_oneshot));
}

static __always_inline void
__mmio_unclaimed_pre(struct intel_display *display, intel_reg_t reg,
		     const bool write, const bool mmio_debug_is_enabled,
		     const unsigned int mmio_flags)
{
	if (mmio_flags & __MMIO_UNCLAIMED && mmio_debug_is_enabled)
		check_unclaimed_mmio_pre(display, reg, write);
}

static __always_inline void
__mmio_unclaimed_post(struct intel_display *display, intel_reg_t reg,
		      const bool write, const bool mmio_debug_is_enabled,
		      const unsigned int mmio_flags)
{
	if (mmio_flags & __MMIO_UNCLAIMED && mmio_debug_is_enabled)
		check_unclaimed_mmio_post(display, reg, write);
}

static __always_inline u32
__intel_de_read(struct intel_display *display, intel_reg_t reg,
		const unsigned int mmio_flags)
{
	const bool mmio_debug_is_enabled = __mmio_debug_is_enabled(display);
	unsigned long irqflags;
	u32 val;

	assert_display_rpm_held(display);

	__mmio_wakelock_pre(display, reg, mmio_flags);
	__mmio_lock_pre(display, &irqflags, mmio_flags);
	__mmio_unclaimed_pre(display, reg, false,
			     mmio_debug_is_enabled, mmio_flags);

	val = __intel_de_read_fw(display, reg);

	__mmio_unclaimed_post(display, reg, false,
			      mmio_debug_is_enabled, mmio_flags);
	__mmio_lock_post(display, irqflags, mmio_flags);
	__mmio_wakelock_post(display, reg, mmio_flags);

	return val;
}

static __always_inline void
__intel_de_write(struct intel_display *display, intel_reg_t reg, u32 val,
		 const unsigned int mmio_flags)
{
	const bool mmio_debug_is_enabled = __mmio_debug_is_enabled(display);
	unsigned long irqflags;

	assert_display_rpm_held(display);

	__mmio_wakelock_pre(display, reg, mmio_flags);
	__mmio_lock_pre(display, &irqflags, mmio_flags);
	__mmio_unclaimed_pre(display, reg, true,
			     mmio_debug_is_enabled, mmio_flags);

	__intel_de_write_fw(display, reg, val);

	__mmio_unclaimed_post(display, reg, true,
			      mmio_debug_is_enabled, mmio_flags);
	__mmio_lock_post(display, irqflags, mmio_flags);
	__mmio_wakelock_post(display, reg, mmio_flags);
}

#define I9XX_MMIO_FLAGS 0

static u32 i9xx_mmio_read(struct intel_display *display, intel_reg_t reg)
{
	return __intel_de_read(display, reg, I9XX_MMIO_FLAGS);
}

static void i9xx_mmio_write(struct intel_display *display, intel_reg_t reg, u32 val)
{
	__intel_de_write(display, reg, val, I9XX_MMIO_FLAGS);
}

#undef I9XX_MMIO_FLAGS

static const struct intel_mmio_funcs i9xx_mmio_funcs = {
	.read = i9xx_mmio_read,
	.write = i9xx_mmio_write,
};

#define SNB_MMIO_FLAGS __MMIO_LOCK

static u32 snb_mmio_read(struct intel_display *display, intel_reg_t reg)
{
	return __intel_de_read(display, reg, SNB_MMIO_FLAGS);
}

static void snb_mmio_write(struct intel_display *display, intel_reg_t reg, u32 val)
{
	__intel_de_write(display, reg, val, SNB_MMIO_FLAGS);
}

#undef SNB_MMIO_FLAGS

static const struct intel_mmio_funcs snb_mmio_funcs = {
	.read = snb_mmio_read,
	.write = snb_mmio_write,
};

#define HSW_MMIO_FLAGS (__MMIO_LOCK | __MMIO_UNCLAIMED)

static u32 hsw_mmio_read(struct intel_display *display, intel_reg_t reg)
{
	return __intel_de_read(display, reg, HSW_MMIO_FLAGS);
}

static void hsw_mmio_write(struct intel_display *display, intel_reg_t reg, u32 val)
{
	__intel_de_write(display, reg, val, HSW_MMIO_FLAGS);
}

#undef HSW_MMIO_FLAGS

static const struct intel_mmio_funcs hsw_mmio_funcs = {
	.read = hsw_mmio_read,
	.write = hsw_mmio_write,
	.check_for_unclaimed_mmio = hsw_check_for_unclaimed_mmio,
	.check_for_unclaimed_mmio_needs_lock = true,
};

static const struct intel_mmio_funcs vlv_mmio_funcs = {
	.read = hsw_mmio_read,
	.write = hsw_mmio_write,
	.check_for_unclaimed_mmio = vlv_check_for_unclaimed_mmio,
	.check_for_unclaimed_mmio_needs_lock = true,
};

#define LNL_MMIO_FLAGS __MMIO_WAKELOCK

static u32 lnl_mmio_read(struct intel_display *display, intel_reg_t reg)
{
	return __intel_de_read(display, reg, LNL_MMIO_FLAGS);
}

static void lnl_mmio_write(struct intel_display *display, intel_reg_t reg, u32 val)
{
	__intel_de_write(display, reg, val, LNL_MMIO_FLAGS);
}

#undef LNL_MMIO_FLAGS

static const struct intel_mmio_funcs lnl_mmio_funcs = {
	.read = lnl_mmio_read,
	.write = lnl_mmio_write,
};

static bool driver_is_i915(void)
{
#ifdef I915
	return true;
#else
	return false;
#endif
}

void intel_de_init(struct intel_display *display)
{
	display->mmio.uncore = to_intel_uncore(display->drm);

	spin_lock_init(&display->mmio.lock);

	/*
	 * TODO: enable unclaimed register detection
	 * (ideally without the lock) for xe and get
	 * rid of driver_is_i915().
	 */
	if (driver_is_i915()) {
		if (DISPLAY_VER(display) >= 9 ||
		    display->platform.broadwell || display->platform.haswell)
			display->mmio.funcs = &hsw_mmio_funcs;
		else if (display->platform.valleyview || display->platform.cherryview)
			display->mmio.funcs = &vlv_mmio_funcs;
		else if (DISPLAY_VER(display) >= 6)
			display->mmio.funcs = &snb_mmio_funcs;
		else
			display->mmio.funcs = &i9xx_mmio_funcs;
	} else {
		if (DISPLAY_VER(display) >= 20)
			display->mmio.funcs = &lnl_mmio_funcs;
		else
			display->mmio.funcs = &i9xx_mmio_funcs;
	}

	if (display->mmio.funcs->check_for_unclaimed_mmio)
		WRITE_ONCE(display->mmio.unclaimed_mmio_check, true);

	/* clear out unclaimed reg detection bit someone else left behind */
	if (intel_de_unclaimed_mmio_detected(display))
		drm_dbg_kms(display->drm, "unclaimed mmio detected on init, clearing\n");
}
