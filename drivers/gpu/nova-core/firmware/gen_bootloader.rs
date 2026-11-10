// SPDX-License-Identifier: GPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

//! The generic falcon bootloader: a small program that the driver loads into a falcon's IMEM by
//! PIO. It reads a descriptor that the driver writes at DMEM offset 0, and loads the image that
//! the descriptor names into IMEM and DMEM by DMA.

use kernel::{
    device,
    num::{
        Bounded,
        TryIntoBounded, //
    },
    prelude::*,
    ptr::Alignable,
    sizes, //
};

use crate::{
    falcon::{
        self,
        FalconPioImemLoadTarget, //
    },
    firmware::tlv::{
        request_tlv, //
        Tlv,
    },
    gpu::Chipset,
    num::FromSafeCast, //
};

/// The generic falcon bootloader image and its IMEM load parameters.
pub(crate) struct GenericBootloader {
    /// Bootloader code, zero-padded to a whole number of falcon memory blocks.
    ucode: KVec<u8>,
    /// Byte offset in IMEM at which the code is loaded.
    imem_dst_start: Bounded<u32, 24>,
    /// Tag under which the first code block is loaded.
    start_tag: u16,
}

impl GenericBootloader {
    /// Loads the generic bootloader image for `chipset`, placed right below the first 64 KiB of
    /// IMEM.
    ///
    /// # Errors
    ///
    /// - `EINVAL` if a required TLV field is absent.
    /// - `EOVERFLOW` if the image does not fit below 64 KiB.
    /// - `ENOMEM` if the padded copy of the code cannot be allocated.
    pub(crate) fn new(dev: &device::Device, chipset: Chipset) -> Result<Self> {
        let fw = request_tlv(dev, chipset, "gen_bootloader")?;
        let tlv = Tlv::new(fw.data())?;
        dev_dbg!(
            dev,
            "loaded generic bootloader firmware v{}\n",
            tlv.get_string(b"VERS")?
        );

        let ucode = {
            let blob = tlv.get_bytes(b"BLOB")?;
            let code_size = usize::from_safe_cast(tlv.get_u32(b"CDSZ")?);
            let code = blob.get(..code_size).ok_or(EINVAL)?;
            let aligned_code_size = code_size
                .align_up(cv!(falcon::MEM_BLOCK_ALIGNMENT))
                .ok_or(EINVAL)?;

            let mut ucode = KVec::with_capacity(aligned_code_size, GFP_KERNEL)?;
            ucode.extend_from_slice(code, GFP_KERNEL)?;
            ucode.resize(aligned_code_size, 0, GFP_KERNEL)?;

            ucode
        };

        // The bootloader's code must be loaded in the area right below the first 64K of IMEM.
        const BOOTLOADER_LOAD_CEILING: usize = sizes::SZ_64K;
        let imem_dst_start = BOOTLOADER_LOAD_CEILING
            .checked_sub(ucode.len())
            .ok_or(EOVERFLOW)?;

        Ok(Self {
            ucode,
            imem_dst_start: imem_dst_start.try_into_bounded().ok_or(EINVAL)?,
            start_tag: u16::try_from(tlv.get_u32(b"STRT")?)?,
        })
    }

    /// Returns the address at which the falcon starts executing the bootloader: the IMEM virtual
    /// address of its first code block.
    pub(crate) fn boot_addr(&self) -> u32 {
        u32::from(self.start_tag) << 8
    }

    /// Returns the PIO parameters that place this bootloader in non-secure IMEM.
    pub(crate) fn imem_load_params(&self) -> FalconPioImemLoadTarget<'_> {
        FalconPioImemLoadTarget {
            data: self.ucode.as_ref(),
            dst_start: self.imem_dst_start,
            secure: false,
            start_tag: self.start_tag,
        }
    }
}
