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
    timer::regs::*, //
};

/// Timer HAL for Turing, Ampere, Ada
struct Tu102;

fn set_time(bar: Bar0<'_>, time_ns: u64) -> Result {
    if !bar.read(NV_PTIMER_TIME_PRIV_LEVEL_MASK).level0() {
        return Err(EINVAL);
    }
    bar.write_reg(NV_PTIMER_TIME_1::from_nsec(time_ns));
    bar.write_reg(NV_PTIMER_TIME_0::from_nsec(time_ns));
    Ok(())
}

impl TimerHal for Tu102 {
    fn setup(
        &self,
        dev: &device::Device<device::Bound>,
        bar: Bar0<'_>,
        _fsp: Option<&Fsp<'_>>,
    ) -> Result<u64> {
        // The OpenRM driver uses wall clock time here not monotonic
        let sys_time_ns = Instant::<RealTime>::now().as_nanos();

        // CAST: realtime system time can't be negative.
        // not setting the timer isn't fatal, just log.
        let _ = set_time(bar, sys_time_ns as u64)
            .inspect_err(|e| dev_err!(dev, "timer block failed to initialise: {:?}\n", e));
        Ok(0_u64)
    }
}

const TU102: Tu102 = Tu102;
pub(super) const TU102_HAL: &dyn TimerHal = &TU102;
