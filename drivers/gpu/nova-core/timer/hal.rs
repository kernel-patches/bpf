// SPDX-License-Identifier: GPL-2.0

use kernel::{
    device,
    prelude::*, //
};

use crate::{
    driver::Bar0,
    fsp::Fsp,
    gpu::{
        Architecture,
        Chipset, //
    },
};

mod gh100;
mod tu102;

pub(super) trait TimerHal {
    /// Setup the GPU's system timer.
    ///
    /// Returns the value to program into GspInitRequest.
    fn setup(
        &self,
        dev: &device::Device<device::Bound>,
        bar: Bar0<'_>,
        fsp: Option<&Fsp<'_>>,
    ) -> Result<u64>;
}

pub(super) fn timer_hal(chipset: Chipset) -> &'static dyn TimerHal {
    match chipset.arch() {
        Architecture::Turing | Architecture::Ampere | Architecture::Ada => tu102::TU102_HAL,
        Architecture::Hopper | Architecture::BlackwellGB10x | Architecture::BlackwellGB20x => {
            gh100::GH100_HAL
        }
    }
}
