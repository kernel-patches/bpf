// SPDX-License-Identifier: GPL-2.0

//! Bootloader support for the FWSEC firmware.
//!
//! On Turing, the FWSEC firmware is not loaded directly, but is instead loaded through a small
//! bootloader program that performs the required DMA operations. This bootloader itself needs to
//! be loaded using PIO.

use kernel::{
    device::{
        self,
        Device, //
    },
    dma::Coherent,
    prelude::*, //
};

use crate::{
    falcon::{
        gsp::Gsp,
        Falcon,
        FalconDmaLoadable,
        FalconFbifTarget, //
    },
    firmware::{
        fwsec::FwsecFirmware,
        gen_bootloader::{
            BootloaderDmemDescV2,
            GenericBootloader, //
        },
    },
    gpu::Chipset,
    num::FromSafeCast, //
};

/// Wrapper for [`FwsecFirmware`] that includes the bootloader performing the actual load
/// operation.
pub(crate) struct FwsecFirmwareWithBl<'a> {
    /// DMA object the bootloader will copy the firmware from.
    _firmware_dma: Coherent<'a, [u8]>,
    /// The bootloader that copies the firmware.
    bootloader: GenericBootloader,
    /// Descriptor to be loaded into DMEM for the bootloader to read.
    dmem_desc: BootloaderDmemDescV2,
}

impl<'a> FwsecFirmwareWithBl<'a> {
    /// Loads the bootloader firmware for `dev` and `chipset`, and wrap `firmware` so it can be
    /// loaded using it.
    pub(crate) fn new(
        firmware: FwsecFirmware,
        dev: &'a Device<device::Bound>,
        chipset: Chipset,
    ) -> Result<Self> {
        let bootloader = GenericBootloader::new(dev, chipset)?;

        // `BootloaderDmemDescV2` expects the source to be a mirror image of the destination and
        // uses the same offset parameter for both.
        //
        // Thus, the start of the source object needs to be padded with the difference between the
        // destination and source offsets.
        //
        // In practice, this is expected to always be zero but is required for code correctness.
        let (align_padding, firmware_dma) = {
            let align_padding = {
                let imem_sec = firmware.imem_sec_load_params();

                imem_sec
                    .dst_start
                    .checked_sub(imem_sec.src_start)
                    .map(usize::from_safe_cast)
                    .ok_or(EOVERFLOW)?
            };

            let mut firmware_obj = KVVec::zeroed(align_padding, GFP_KERNEL)?;
            firmware_obj.extend_from_slice(firmware.ucode.0.as_slice(), GFP_KERNEL)?;

            (
                align_padding,
                Coherent::from_slice(dev, firmware_obj.as_slice(), GFP_KERNEL)?,
            )
        };

        let dmem_desc = {
            let imem_sec = firmware.imem_sec_load_params();
            let imem_ns = firmware.imem_ns_load_params().ok_or(EINVAL)?;
            let dmem = firmware.dmem_load_params();

            // The bootloader does not have a data destination offset field and copies the data at
            // the start of DMEM, so it can only be used if the destination offset of the firmware
            // is 0.
            if dmem.dst_start != 0 {
                return Err(EINVAL);
            }

            // Start of data section is the added padding + the DMEM `src_start` field.
            let data_dma_base = firmware_dma
                .dma_address()
                .checked_add(u64::from_safe_cast(align_padding))
                .and_then(|offset| offset.checked_add(dmem.src_start.into()))
                .ok_or(EOVERFLOW)?;

            BootloaderDmemDescV2::new(
                &imem_ns,
                &imem_sec,
                &dmem,
                firmware_dma.dma_address(),
                data_dma_base,
            )
        };

        Ok(Self {
            _firmware_dma: firmware_dma,
            bootloader,
            dmem_desc,
        })
    }

    /// Loads the bootloader into `falcon` and execute it.
    ///
    /// The bootloader will load the FWSEC firmware and then execute it. This function returns
    /// after FWSEC has reached completion.
    pub(crate) fn run(&self, dev: &Device<device::Bound>, falcon: &Falcon<'_, Gsp>) -> Result<()> {
        falcon
            .reset()
            .inspect_err(|e| dev_err!(dev, "Failed to reset GSP falcon: {:?}\n", e))?;

        // Run the bootloader, which loads the FWSEC firmware and runs it.
        let (mbox0, _) = self
            .bootloader
            .run(falcon, &self.dmem_desc, FalconFbifTarget::CoherentSysmem, 0)
            .inspect_err(|e| dev_err!(dev, "Failed to boot FWSEC firmware: {:?}\n", e))?;
        if mbox0 != 0 {
            dev_err!(dev, "FWSEC firmware returned error {}\n", mbox0);
            Err(EIO)
        } else {
            Ok(())
        }
    }
}
