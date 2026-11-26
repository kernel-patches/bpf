// SPDX-License-Identifier: GPL-2.0

//! Virtual Function driver for the Rust SR-IOV sample.

use kernel::{
    device::Core,
    pci,
    prelude::*, //
};

use super::pf::PfApi;

pub(crate) struct SampleVfDriver;

kernel::pci_device_table!(
    VF_TABLE,
    <SampleVfDriver as pci::Driver>::IdInfo,
    [(
        // E1000_DEV_ID_82576_VF
        pci::DeviceId::from_id(pci::Vendor::INTEL, 0x10ca),
        ()
    )]
);

#[vtable]
impl pci::Driver for SampleVfDriver {
    type IdInfo = ();
    type Data<'bound> = Self;

    const ID_TABLE: pci::IdTable<Self::IdInfo> = &VF_TABLE;

    fn probe<'bound>(
        pdev: &'bound pci::Device<Core<'_>>,
        _info: Option<&'bound Self::IdInfo>,
    ) -> impl PinInit<Self, Error> + 'bound {
        dev_info!(
            pdev,
            "Probe Rust SR-IOV VF sample (PCI ID: {}, 0x{:x}).\n",
            pdev.vendor_id(),
            pdev.device_id()
        );

        let request = PfApi::submit(pdev)?;
        dev_info!(pdev, "Submitted request {} through PF data.\n", request);

        pdev.enable_device_mem()?;
        pdev.set_master();

        Ok(Self)
    }
}
