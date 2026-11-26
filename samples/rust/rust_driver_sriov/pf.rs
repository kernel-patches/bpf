// SPDX-License-Identifier: GPL-2.0

//! Physical Function driver for the Rust SR-IOV sample.

use kernel::{
    device::{
        Bound,
        Core, //
    },
    pci,
    prelude::*,
    sync::atomic::{
        Atomic,
        Relaxed, //
    },
    types::CovariantForLt, //
};

pub(crate) struct SamplePfDriver;

#[pin_data]
pub(crate) struct PfApi<'bound> {
    pdev: &'bound pci::Device<Bound>,
    next_request: Atomic<u64>,
}

type PfApiForLt = CovariantForLt!(PfApi<'_>);

impl PfApi<'_> {
    /// Submits a request to the PF associated with a bound VF.
    pub(crate) fn submit(vf: &pci::Device<Bound>) -> Result<u64> {
        let pf = vf.vf_registration_data::<PfApiForLt>()?;
        let request = pf.next_request.fetch_add(1, Relaxed);

        dev_info!(
            pf.pdev,
            "Handle PF request {} from VF devfn {:#x}.\n",
            request,
            vf.dev_id()
        );

        Ok(request)
    }
}

#[pin_data]
pub(crate) struct PfDriverData<'bound> {
    #[pin]
    _registration: pci::VfRegistration<'bound, PfApiForLt>,
    pdev: &'bound pci::Device<Bound>,
}

kernel::pci_device_table!(
    PF_TABLE,
    <SamplePfDriver as pci::Driver>::IdInfo,
    [(
        // E1000_DEV_ID_82576
        pci::DeviceId::from_id(pci::Vendor::INTEL, 0x10c9),
        ()
    )]
);

#[vtable]
impl pci::Driver for SamplePfDriver {
    type IdInfo = ();
    type Data<'bound> = PfDriverData<'bound>;

    const ID_TABLE: pci::IdTable<Self::IdInfo> = &PF_TABLE;

    fn probe<'bound>(
        pdev: &'bound pci::Device<Core<'_>>,
        _info: Option<&'bound Self::IdInfo>,
    ) -> impl PinInit<Self::Data<'bound>, Error> + 'bound {
        try_pin_init!(PfDriverData {
            _: {
                dev_info!(
                    pdev,
                    "Probe Rust SR-IOV PF sample (PCI ID: {}, 0x{:x}).\n",
                    pdev.vendor_id(),
                    pdev.device_id()
                );
            },
            // SAFETY: The registration is embedded in the PF driver's private data.
            _registration <- unsafe {
                pci::VfRegistration::new(
                    pdev,
                    try_pin_init!(PfApi {
                        pdev,
                        next_request: Atomic::new(1),
                    }),
                )
            },
            _: {
                pdev.enable_device_mem()?;
                pdev.set_master();
            },
            pdev,
        })
    }

    fn sriov_enable<'a>(
        _dev: &'a pci::Device<Core<'_>>,
        data: Pin<&Self::Data<'a>>,
        token: pci::SriovEnable<'a>,
    ) -> Result<pci::SriovEnabled<'a>> {
        dev_info!(
            data.pdev,
            "Enable SR-IOV (PCI ID: {}, 0x{:x}).\n",
            data.pdev.vendor_id(),
            data.pdev.device_id()
        );

        token.enable_all()
    }

    fn sriov_disable<'a>(
        _dev: &'a pci::Device<Core<'_>>,
        data: Pin<&Self::Data<'a>>,
        token: pci::SriovDisable<'a>,
    ) -> Result {
        dev_info!(
            data.pdev,
            "Disable SR-IOV (PCI ID: {}, 0x{:x}).\n",
            data.pdev.vendor_id(),
            data.pdev.device_id()
        );

        token.disable();
        Ok(())
    }
}
