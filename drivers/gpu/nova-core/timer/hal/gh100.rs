// SPDX-License-Identifier: GPL-2.0

use super::TimerHal;

use kernel::{
    device,
    io::Io,
    prelude::*,
    time::*, //
};

use crate::{
    driver::Bar0,
    fsp::Fsp,
    timer::regs::gh100::*, //
};

/// Timer HAL for Hopper and Blackwell.
struct Gh100;

fn sec_timer_read(bar: Bar0<'_>) -> u64 {
    let mut hi2 = bar.read(NV_PGC6_SCI_SEC_TIMER_TIME_1);
    loop {
        let lo = bar.read(NV_PGC6_SCI_SEC_TIMER_TIME_0);
        let hi = bar.read(NV_PGC6_SCI_SEC_TIMER_TIME_1);
        if hi == hi2 {
            return u64::from(u32::from(hi)) << 32 | u64::from(u32::from(lo));
        }
        hi2 = bar.read(NV_PGC6_SCI_SEC_TIMER_TIME_1);
    }
}

fn set_sys_timer_offset(bar: Bar0<'_>, fsp: &Fsp<'_>, time_ns: u64) -> u64 {
    let sec_timer_ns = sec_timer_read(bar);

    // if we wrap after an underflow the SEC_TIMER + OFFSET value
    // modulo 61 bits will match the system clock.
    let sys_timer_offset_ns = time_ns.wrapping_sub(sec_timer_ns);

    // Don't set the timer offset registers on buggy firmware
    if !fsp.is_bug_3957833_affected(bar) {
        bar.write_reg(NV_PGC6_SCI_SYS_TIMER_OFFSET_1::from_nsec(
            sys_timer_offset_ns,
        ));
        bar.write_reg(
            NV_PGC6_SCI_SYS_TIMER_OFFSET_0::from_nsec(sys_timer_offset_ns).with_update(true),
        );
    }
    sys_timer_offset_ns
}

impl TimerHal for Gh100 {
    fn setup(
        &self,
        _dev: &device::Device<device::Bound>,
        bar: Bar0<'_>,
        fsp: Option<&Fsp<'_>>,
    ) -> Result<u64> {
        // The OpenRM driver uses wall clock time here not monotonic
        let sys_time_ns = Instant::<RealTime>::now().as_nanos();

        // fsp is required on gh100 - return error if not available.
        let fsp = fsp.ok_or(EINVAL)?;

        // CAST: realtime system time can't be negative.
        Ok(set_sys_timer_offset(bar, fsp, sys_time_ns as u64))
    }
}

const GH100: Gh100 = Gh100;
pub(super) const GH100_HAL: &dyn TimerHal = &GH100;
