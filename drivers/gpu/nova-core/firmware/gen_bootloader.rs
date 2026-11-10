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
    sizes,
    transmute::AsBytes, //
};

use crate::{
    falcon::{
        self,
        FalconDmaLoadTarget,
        FalconPioImemLoadTarget, //
    },
    firmware::tlv::{
        request_tlv, //
        Tlv,
    },
    gpu::Chipset,
    num::FromSafeCast, //
};

/// Structure used by the boot-loader to load the rest of the code.
///
/// This has to be filled by the GPU driver and copied into DMEM at offset
/// [`BootloaderDesc.dmem_load_off`].
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub(crate) struct BootloaderDmemDescV2 {
    /// Reserved, should always be first element.
    reserved: [u32; 4],
    /// 16B signature for secure code, 0s if no secure code.
    signature: [u32; 4],
    /// DMA context used by the bootloader while loading code/data.
    ctx_dma: u32,
    /// 256B-aligned physical FB address where code is located.
    code_dma_base: u64,
    /// Offset from `code_dma_base` where the non-secure code is located.
    ///
    /// Also used as destination IMEM offset of non-secure code as the DMA firmware object is
    /// expected to be a mirror image of its loaded state.
    ///
    /// Must be multiple of 256.
    non_sec_code_off: u32,
    /// Size of the non-secure code part.
    non_sec_code_size: u32,
    /// Offset from `code_dma_base` where the secure code is located (must be multiple of 256).
    ///
    /// Also used as destination IMEM offset of secure code as the DMA firmware object is expected
    /// to be a mirror image of its loaded state.
    ///
    /// Must be multiple of 256.
    sec_code_off: u32,
    /// Size of the secure code part.
    sec_code_size: u32,
    /// Code entry point invoked by the bootloader after code is loaded.
    code_entry_point: u32,
    /// 256B-aligned physical FB address where data is located.
    data_dma_base: u64,
    /// Size of data block (should be multiple of 256B).
    data_size: u32,
    /// Number of arguments to be passed to the target firmware being loaded.
    argc: u32,
    /// Arguments to be passed to the target firmware being loaded.
    argv: u32,
}

impl BootloaderDmemDescV2 {
    /// Context DMA slot through which the bootloader reads the image: physical, non-coherent
    /// system memory.
    const FALCON_DMAIDX_PHYS_SYS_NCOH: u32 = 4;

    /// Creates the descriptor of an image whose code is at `code_dma_base` and whose data is at
    /// `data_dma_base`.
    ///
    /// `imem_ns` and `imem_sec` locate the non-secure and secure code in the image, and `dmem`
    /// gives the size of its data. The code DMA object must be a mirror image of the target IMEM
    /// layout, because the bootloader uses the destination offset of each code segment as its
    /// source offset too.
    pub(crate) fn new(
        imem_ns: &FalconDmaLoadTarget,
        imem_sec: &FalconDmaLoadTarget,
        dmem: &FalconDmaLoadTarget,
        code_dma_base: u64,
        data_dma_base: u64,
    ) -> Self {
        Self {
            reserved: [0; 4],
            signature: [0; 4],
            ctx_dma: Self::FALCON_DMAIDX_PHYS_SYS_NCOH,
            code_dma_base,
            non_sec_code_off: imem_ns.dst_start,
            non_sec_code_size: imem_ns.len,
            sec_code_off: imem_sec.dst_start,
            sec_code_size: imem_sec.len,
            code_entry_point: 0,
            data_dma_base,
            data_size: dmem.len,
            argc: 0,
            argv: 0,
        }
    }

    /// Returns the context DMA slot through which the bootloader reads the image.
    pub(crate) fn ctx_dma(&self) -> u32 {
        self.ctx_dma
    }
}

// SAFETY: This struct doesn't contain uninitialized bytes and doesn't have interior mutability.
unsafe impl AsBytes for BootloaderDmemDescV2 {}

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
