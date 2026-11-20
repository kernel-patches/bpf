// SPDX-License-Identifier: GPL-2.0

//! Debugfs data shared by all GPUs of the driver.

use kernel::{
    debugfs,
    new_mutex,
    prelude::*,
    sync::Mutex, //
};

use crate::gsp::RetainedLogs;

/// Debugfs data the module shares with every GPU it drives.
#[pin_data]
pub(crate) struct DebugfsData {
    /// Copies of the GSP-RM log buffers of GPUs that are no longer bound.
    ///
    /// Declared before `root`, as the copies live below it.
    #[pin]
    retained_logs: Mutex<RetainedLogs>,
    /// Root directory of the driver in debugfs.
    root: debugfs::Dir,
}

impl DebugfsData {
    /// Creates the debugfs data of the module.
    pub(crate) fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            retained_logs <- new_mutex!(RetainedLogs::new()),
            root: debugfs::Dir::new(c"nova-core"),
        })
    }

    /// Returns the root directory of the driver.
    pub(crate) fn root(&self) -> &debugfs::Dir {
        &self.root
    }

    /// Returns the copies of the GSP-RM log buffers of GPUs that are no longer bound.
    #[inline]
    pub(crate) fn retained_logs(&self) -> &Mutex<RetainedLogs> {
        &self.retained_logs
    }
}
