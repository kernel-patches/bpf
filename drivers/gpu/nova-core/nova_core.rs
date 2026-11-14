// SPDX-License-Identifier: GPL-2.0

//! Nova Core GPU Driver

use kernel::{
    device,
    driver::Registration,
    pci,
    prelude::*,
    InPlaceModule, //
};

pub mod api;
mod debugfs;
mod driver;
mod falcon;
mod fb;
mod firmware;
mod fsp;
mod gpu;
mod gsp;
mod irq;
mod mctp;
mod mm;
#[macro_use]
mod num;
mod regs;
mod sbuffer;
#[cfg(CONFIG_NOVA_CORE_SELFTESTS)]
mod selftest;
mod timer;
mod vbios;
mod vgpu;

use debugfs::DebugfsData;

pub(crate) const MODULE_NAME: &core::ffi::CStr = <LocalModule as kernel::ModuleMetadata>::NAME;

/// Pointer to the [`DebugfsData`] of the module.
///
/// A device currently has no way to reach the data of its module, so it goes through here.
///
/// # Invariants
///
/// - Only written once before the driver is registered.
/// - Points to a valid [`DebugfsData`] for as long as the driver is registered.
// TODO: Drop this once devices can reach the data of their module.
static mut DEBUGFS_DATA: *const DebugfsData = core::ptr::null();

#[pin_data]
struct NovaCoreModule {
    // Fields are dropped in declaration order. `_driver` must be dropped before `_debugfs` to
    // uphold the invariant of `DEBUGFS_DATA` that it remains valid for as long as the driver is
    // registered.
    #[pin]
    _driver: Registration<pci::Adapter<driver::NovaCoreDriver>>,
    #[pin]
    _debugfs: DebugfsData,
}

impl NovaCoreModule {
    /// Returns the debugfs data of the module.
    pub(crate) fn debugfs_data<'a>(_dev: &'a device::Device<device::Bound>) -> &'a DebugfsData {
        // SAFETY: `_dev` is bound, so the driver is registered. Per the invariants of
        // `DEBUGFS_DATA`, the pointer is thus valid and not being written to. The `'a` lifetime
        // ensures that the returned reference cannot outlive the bound device.
        unsafe { &*DEBUGFS_DATA }
    }
}

impl InPlaceModule for NovaCoreModule {
    fn init(module: &'static kernel::ThisModule) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            _debugfs <- DebugfsData::new(),
            _: {
                // SAFETY: The driver is not registered yet, meaning that no device can be probed
                // and thus nothing can access `DEBUGFS_DATA` concurrently.
                //
                // INVARIANT: `DEBUGFS_DATA` is written before the driver is registered below and
                // points to `_debugfs`, which is pinned and dropped after `_driver`.
                unsafe { DEBUGFS_DATA = &*_debugfs };
            },
            _driver <- Registration::new(MODULE_NAME, module),
        })
    }
}

module! {
    type: NovaCoreModule,
    name: "nova-core",
    authors: ["Danilo Krummrich"],
    description: "Nova Core GPU driver",
    license: "GPL v2",
    firmware: [],
    params: {
        gsp_keep_logs: bool {
            default: false,
            description: "Keep the GSP-RM log buffers in debugfs after their GPU is unbound",
        },
    },
}

kernel::module_firmware!(firmware::ModInfoBuilder);
