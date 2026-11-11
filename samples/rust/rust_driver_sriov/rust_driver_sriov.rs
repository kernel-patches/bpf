// SPDX-License-Identifier: GPL-2.0

//! Rust SR-IOV driver sample based on QEMU's 82576 ([igb]) emulation.
//!
//! To make these drivers probe, QEMU must be run with `-device igb`.
//!
//! Further, enable [vIOMMU] with interrupt remapping using, e.g.,
//!
//! `-M q35,accel=kvm,kernel-irqchip=split -device intel-iommu,intremap=on,caching-mode=on`
//!
//! and append `intel_iommu=on` to the guest kernel arguments.
//!
//! This module registers both the PF driver and the VF driver.
//!
//! [igb]: https://www.qemu.org/docs/master/system/devices/igb.html
//! [vIOMMU]: https://wiki.qemu.org/Features/VT-d

use kernel::{
    driver,
    pci,
    prelude::*,
    InPlaceModule, //
};

mod pf;
mod vf;

#[pin_data]
struct SampleModule {
    #[pin]
    _pf_driver: driver::Registration<pci::Adapter<pf::SamplePfDriver>>,
    #[pin]
    _vf_driver: driver::Registration<pci::Adapter<vf::SampleVfDriver>>,
}

impl InPlaceModule for SampleModule {
    fn init(module: &'static kernel::ThisModule) -> impl PinInit<Self, Error> {
        // Both drivers are on the PCI bus, so they need distinct driver names.
        try_pin_init!(Self {
            _pf_driver <- driver::Registration::new(c"rust_driver_sriov_pf", module),
            _vf_driver <- driver::Registration::new(c"rust_driver_sriov_vf", module),
        })
    }
}

module! {
    type: SampleModule,
    name: "rust_driver_sriov",
    authors: ["Peter Colberg"],
    description: "Rust SR-IOV PF and VF driver sample",
    license: "GPL v2",
}
