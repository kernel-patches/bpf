// SPDX-License-Identifier: GPL-2.0

//! Debugfs data shared by all GPUs of the driver.

use kernel::{
    debugfs,
    prelude::*, //
};

/// Debugfs data the module shares with every GPU it drives.
#[pin_data]
pub(crate) struct DebugfsData {
    /// Root directory of the driver in debugfs.
    root: debugfs::Dir,
}

impl DebugfsData {
    /// Creates the debugfs data of the module.
    pub(crate) fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            root: debugfs::Dir::new(c"nova-core"),
        })
    }

    /// Returns the root directory of the driver.
    pub(crate) fn root(&self) -> &debugfs::Dir {
        &self.root
    }
}
