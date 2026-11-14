// SPDX-License-Identifier: GPL-2.0

//! GSP-RM log buffers.

use kernel::{
    device,
    dma::Coherent,
    io::{
        io_project,
        Io, //
    },
    prelude::*, //
};

use crate::gsp::{
    PteArray,
    GSP_PAGE_SIZE, //
};

/// Number of GSP pages to use in a RM log buffer.
const RM_LOG_BUFFER_NUM_PAGES: usize = 0x10;
const LOG_BUFFER_SIZE: usize = RM_LOG_BUFFER_NUM_PAGES * GSP_PAGE_SIZE;

/// The logging buffers are byte queues that contain encoded printf-like
/// messages from GSP-RM.  They need to be decoded by a special application
/// that can parse the buffers.
///
/// The 'loginit' buffer contains logs from early GSP-RM init and
/// exception dumps.  The 'logrm' buffer contains the subsequent logs. Both are
/// written to directly by GSP-RM and can be any multiple of GSP_PAGE_SIZE.
///
/// The physical address map for the log buffer is stored in the buffer
/// itself, starting with offset 1. Offset 0 contains the "put" pointer (pp).
/// Initially, pp is equal to 0. If the buffer has valid logging data in it,
/// then pp points to index into the buffer where the next logging entry will
/// be written. Therefore, the logging data is valid if:
///   1 <= pp < sizeof(buffer)/sizeof(u64)
pub(super) struct LogBuffer<'a>(pub(super) Coherent<'a, [u8; LOG_BUFFER_SIZE]>);

impl<'a> LogBuffer<'a> {
    /// Creates a new `LogBuffer` mapped on `dev`.
    pub(super) fn new(dev: &'a device::Device<device::Bound>) -> Result<Self> {
        let obj = Self(Coherent::zeroed(dev, GFP_KERNEL)?);

        let start_addr = obj.0.dma_address();

        let pte_view = io_project!(
            obj.0,
            [build: size_of::<u64>()..][build: ..RM_LOG_BUFFER_NUM_PAGES * size_of::<u64>()]
        )
        .try_cast::<PteArray<RM_LOG_BUFFER_NUM_PAGES>>()?;
        PteArray::init(pte_view, start_addr)?;

        Ok(obj)
    }
}

pub(super) struct LogBuffers<'a> {
    /// Init log buffer.
    pub(super) loginit: LogBuffer<'a>,
    /// Interrupts log buffer.
    pub(super) logintr: LogBuffer<'a>,
    /// RM log buffer.
    pub(super) logrm: LogBuffer<'a>,
}
