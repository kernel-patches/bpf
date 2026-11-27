// SPDX-License-Identifier: GPL-2.0

mod hal;
mod regs;

use kernel::{
    device,
    prelude::*, //
};

use crate::{
    driver::Bar0,
    fsp::Fsp,
    gpu::Chipset, //
};

pub(crate) struct Timer;

/// Struct that holds the sys timer offset value
/// after initialising the GPU timer block.
pub(crate) struct TimerState {
    /// This value is to be passed to GspInit SYS_TIMER_OFFSET_NS
    /// It is considered an opaque value, passed from timer hal to GSP.
    #[expect(dead_code)]
    pub(crate) sys_timer_offset_ns: u64,
}

impl Timer {
    /// Setup the GPU timer hardware
    pub(crate) fn setup(
        dev: &device::Device<device::Bound>,
        bar: Bar0<'_>,
        chipset: Chipset,
        fsp: Option<&Fsp<'_>>,
    ) -> Result<TimerState> {
        Ok(TimerState {
            sys_timer_offset_ns: hal::timer_hal(chipset).setup(dev, bar, fsp)?,
        })
    }
}
