// SPDX-License-Identifier: GPL-2.0

//! GSP-RM log buffers.

use kernel::{
    debugfs,
    device,
    dma::Coherent,
    io::{
        io_project,
        Io, //
    },
    prelude::*,
    str::CString,
    sync::barrier::{
        dma_mb,
        Read, //
    }, //
};

use crate::{
    gsp::{
        PteArray,
        GSP_PAGE_SIZE, //
    },
    NovaCoreModule, //
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
    fn new(dev: &'a device::Device<device::Bound>) -> Result<Self> {
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

    /// Copies the buffer, or returns an empty vector if the GSP never wrote to it.
    fn snapshot(&self) -> Result<VVec<u8>> {
        let put = io_project!(self.0, [build: ..size_of::<u64>()])
            .try_cast::<u64>()?
            .read_val();
        if put == 0 {
            return Ok(VVec::new());
        }

        // ORDERING: LOAD->LOAD ordering needed to order the "put" read before the data read, as a
        // GSP that failed to boot may still be writing.
        dma_mb(Read);

        let mut snapshot = VVec::zeroed(LOG_BUFFER_SIZE, GFP_KERNEL)?;
        io_project!(self.0, [build: ..]).copy_to_slice(&mut snapshot);

        // The copy reads "put" again, unordered against the data, so keep the value read above.
        snapshot[..size_of::<u64>()].copy_from_slice(&put.to_ne_bytes());

        Ok(snapshot)
    }
}

pub(super) struct LogBuffers<'a> {
    /// Device the buffers belong to.
    dev: &'a device::Device<device::Bound>,
    /// Init log buffer.
    pub(super) loginit: LogBuffer<'a>,
    /// Interrupts log buffer.
    pub(super) logintr: LogBuffer<'a>,
    /// RM log buffer.
    pub(super) logrm: LogBuffer<'a>,
}

impl<'a> LogBuffers<'a> {
    /// Allocates the log buffers of `dev`.
    pub(super) fn new(dev: &'a device::Device<device::Bound>) -> Result<Self> {
        Ok(Self {
            dev,
            loginit: LogBuffer::new(dev)?,
            logintr: LogBuffer::new(dev)?,
            logrm: LogBuffer::new(dev)?,
        })
    }

    /// Exposes the buffers in debugfs, in a directory named after their device.
    pub(super) fn into_debugfs_scope(self) -> impl PinInit<debugfs::Scope<Self>> + 'a {
        let dev = self.dev;
        let data = NovaCoreModule::debugfs_data(dev);

        // Retained copies of an earlier run use the same directory.
        data.retained_logs().lock().remove(dev.name());

        data.root().scope(self, dev.name(), |logs, dir| {
            dir.read_binary_file(c"loginit", &logs.loginit.0);
            dir.read_binary_file(c"logintr", &logs.logintr.0);
            dir.read_binary_file(c"logrm", &logs.logrm.0);
        })
    }

    /// Exposes copies of the buffers in their place, if `gsp_keep_logs` is set.
    fn retain(&self) -> Result {
        if !crate::module_parameters::gsp_keep_logs.value() {
            return Ok(());
        }

        let logs = RetainedLogBuffers {
            name: CString::try_from_fmt(fmt!("{}", self.dev.name()))?,
            loginit: self.loginit.snapshot()?,
            logintr: self.logintr.snapshot()?,
            logrm: self.logrm.snapshot()?,
        };

        if logs.loginit.is_empty() && logs.logintr.is_empty() && logs.logrm.is_empty() {
            return Ok(());
        }

        let scope = KBox::<debugfs::Scope<RetainedLogBuffers>>::new_uninit(GFP_KERNEL)?;
        let data = NovaCoreModule::debugfs_data(self.dev);
        let root = data.root();
        let mut retained = data.retained_logs().lock();
        retained.remove(self.dev.name());

        let scope = scope.write_pin_init(root.scope(logs, self.dev.name(), |logs, dir| {
            if !logs.loginit.is_empty() {
                dir.read_binary_file(c"loginit", &logs.loginit);
            }
            if !logs.logintr.is_empty() {
                dir.read_binary_file(c"logintr", &logs.logintr);
            }
            if !logs.logrm.is_empty() {
                dir.read_binary_file(c"logrm", &logs.logrm);
            }
        }))?;

        retained.push(scope)
    }
}

impl Drop for LogBuffers<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.retain() {
            dev_warn!(self.dev, "failed to retain GSP-RM log buffers: {:?}\n", e);
        }
    }
}

/// Copies of the log buffers of a GPU that is no longer bound.
struct RetainedLogBuffers {
    /// Name of the device, which also names the debugfs directory.
    name: CString,
    /// Init log buffer, empty if never written to.
    loginit: VVec<u8>,
    /// Interrupts log buffer, empty if never written to.
    logintr: VVec<u8>,
    /// RM log buffer, empty if never written to.
    logrm: VVec<u8>,
}

/// Copies of the log buffers of all GPUs that are no longer bound.
pub(crate) struct RetainedLogs(KVec<Pin<KBox<debugfs::Scope<RetainedLogBuffers>>>>);

impl RetainedLogs {
    pub(crate) const fn new() -> Self {
        Self(KVec::new())
    }

    /// Drops the copies of the device named `name`, if any.
    fn remove(&mut self, name: &CStr) {
        self.0.retain(|gpu| *gpu.name != *name);
    }

    /// Adds the copies of a device.
    fn push(&mut self, gpu: Pin<KBox<debugfs::Scope<RetainedLogBuffers>>>) -> Result {
        self.0.push(gpu, GFP_KERNEL)?;
        Ok(())
    }
}
