// SPDX-License-Identifier: GPL-2.0

//! Abstractions for PCI Single Root I/O Virtualization (SR-IOV) drivers.

use super::Device;

use crate::{
    bindings,
    device,
    error::to_result,
    prelude::*, //
};

impl Device<device::CoreInternal<'_>> {
    /// Enable the Single Root I/O Virtualization (SR-IOV) capability for this device,
    /// where `nr_virtfn` is number of Virtual Functions (VF) to enable.
    #[inline]
    #[expect(dead_code)]
    pub(crate) fn enable_sriov(&self, nr_virtfn: u16) -> Result {
        // SAFETY:
        // - `self.as_raw` returns a valid pointer to a `struct pci_dev`.
        //
        // - `pci_enable_sriov()` checks that the enable operation is valid:
        //   - the device is a Physical Function (PF),
        //   - SR-IOV is currently disabled, and
        //   - `nr_virtfn` does not exceed the total number of supported VFs.
        //
        // - The `CoreInternal` device context inherits from the `Bound` device context,
        //   which guarantees that the PF device is bound to a driver.
        to_result(unsafe { bindings::pci_enable_sriov(self.as_raw(), nr_virtfn.into()) })
    }

    /// Disable the Single Root I/O Virtualization (SR-IOV) capability for this device.
    #[inline]
    #[expect(dead_code)]
    pub(crate) fn disable_sriov(&self) {
        // SAFETY:
        // - `self.as_raw` returns a valid pointer to a `struct pci_dev`.
        //
        // - `pci_disable_sriov()` checks that the disable operation is valid:
        //   - the device is a Physical Function (PF), and
        //   - SR-IOV is currently enabled.
        //
        // - The `CoreInternal` device context inherits from the `Bound` device context,
        //   which guarantees that the PF device is bound to a driver.
        unsafe { bindings::pci_disable_sriov(self.as_raw()) };
    }
}
