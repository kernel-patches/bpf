// SPDX-License-Identifier: GPL-2.0

//! Abstractions for PCI Single Root I/O Virtualization (SR-IOV) drivers.

use super::{
    Adapter,
    Device,
    Driver, //
};

use crate::{
    bindings,
    device,
    error::{
        from_result,
        to_result, //
    },
    prelude::*,
    types::{
        CovariantForLt,
        ForLt, //
    }, //
};
use core::{
    any::TypeId,
    marker::PhantomPinned,
    mem::ManuallyDrop,
    num::NonZero, //
};

/// Returns the PF's registration pointer, or null when `CONFIG_PCI_IOV` is disabled.
///
/// # Safety
///
/// `pdev` must point to a live PCI device. The caller must exclude concurrent changes to its
/// registration pointer.
unsafe fn vf_registration_data_ptr(pdev: *mut bindings::pci_dev) -> *mut c_void {
    #[cfg(CONFIG_PCI_IOV)]
    {
        // SAFETY: The caller guarantees the device's validity and excludes concurrent changes.
        unsafe { (*pdev).vf_registration_data_rust }
    }
    #[cfg(not(CONFIG_PCI_IOV))]
    {
        let _ = pdev;
        core::ptr::null_mut()
    }
}

/// Updates the PF's registration pointer, doing nothing when `CONFIG_PCI_IOV` is disabled.
///
/// # Safety
///
/// `pdev` must point to a live PCI device. The caller must exclude concurrent access to its
/// registration pointer and uphold the invariants of any published registration data.
unsafe fn set_vf_registration_data_ptr(pdev: *mut bindings::pci_dev, data: *mut c_void) {
    #[cfg(CONFIG_PCI_IOV)]
    // SAFETY: The caller guarantees the device's validity and exclusive access to its slot.
    unsafe {
        (*pdev).vf_registration_data_rust = data
    };

    #[cfg(not(CONFIG_PCI_IOV))]
    let _ = (pdev, data);
}

impl Device<device::Core<'_>> {
    /// Returns the number of Virtual Functions (VF) enabled for a Physical Function (PF).
    ///
    /// Returns zero when `CONFIG_PCI_IOV` is disabled.
    #[inline]
    pub fn num_vf(&self) -> u16 {
        // SAFETY: `self.as_raw()` is valid and this call runs in the PCI core callback context.
        unsafe { bindings::pci_num_vf(self.as_raw()) }
            .try_into()
            .expect("pdev->sriov->num_VFs is u16")
    }
}

impl Device<device::CoreInternal<'_>> {
    /// Enable the Single Root I/O Virtualization (SR-IOV) capability for this device,
    /// where `nr_virtfn` is number of Virtual Functions (VF) to enable.
    #[inline]
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

/// Permission to enable VFs during a driver's [`Driver::sriov_enable()`] callback.
///
/// The PCI adapter creates this token for the PF being configured. It cannot be cloned or sent
/// to another thread, and its lifetime is restricted to the callback. Enabling VFs consumes it.
///
/// The callback lifetime cannot be extended:
///
/// ```ignore,compile_fail
/// use kernel::pci::SriovEnable;
///
/// fn escape(token: SriovEnable<'_>) -> SriovEnable<'static> {
///     token
/// }
/// ```
pub struct SriovEnable<'a> {
    pdev: &'a Device<device::CoreInternal<'a>>,
    num_vfs: NonZero<u16>,
}

impl<'a> SriovEnable<'a> {
    /// Returns the number of VFs requested for this callback.
    #[inline]
    pub fn num_vfs(&self) -> NonZero<u16> {
        self.num_vfs
    }

    /// Enables between one and the requested number of VFs.
    ///
    /// VF drivers can probe before this method returns, so the PF resources they access must
    /// already be initialized. The returned guard disables the VFs if subsequent setup fails.
    /// Return it from [`Driver::sriov_enable()`] to leave the VFs enabled on callback success.
    ///
    /// # Errors
    ///
    /// - [`EINVAL`]: `num_vfs` is greater than [`Self::num_vfs()`].
    /// - [`ENODEV`]: the PF driver has not registered a [`VfRegistration`].
    /// - Any error returned by `pci_enable_sriov()`.
    pub fn enable(self, num_vfs: NonZero<u16>) -> Result<SriovEnabled<'a>> {
        if num_vfs > self.num_vfs {
            return Err(EINVAL);
        }
        let num_vfs = num_vfs.get();

        // SAFETY: The PF's driver data and registration remain installed throughout this callback.
        // The registration owns final VF teardown after the enable guard is disarmed.
        if unsafe { vf_registration_data_ptr(self.pdev.as_raw()) }.is_null() {
            return Err(ENODEV);
        }

        self.pdev.enable_sriov(num_vfs)?;
        Ok(SriovEnabled {
            pdev: self.pdev,
            num_vfs,
        })
    }

    /// Enables all VFs requested for this callback.
    ///
    /// This is equivalent to calling [`Self::enable()`] with [`Self::num_vfs()`].
    ///
    /// # Errors
    ///
    /// - [`ENODEV`]: the PF driver has not registered a [`VfRegistration`].
    /// - Any error returned by `pci_enable_sriov()`.
    #[inline]
    pub fn enable_all(self) -> Result<SriovEnabled<'a>> {
        let num_vfs = self.num_vfs;
        self.enable(num_vfs)
    }
}

/// Enabled VFs awaiting successful completion of [`Driver::sriov_enable()`].
pub struct SriovEnabled<'a> {
    pdev: &'a Device<device::CoreInternal<'a>>,
    num_vfs: u16,
}

impl SriovEnabled<'_> {
    #[inline]
    fn disarm(self) -> u16 {
        ManuallyDrop::new(self).num_vfs
    }
}

impl Drop for SriovEnabled<'_> {
    fn drop(&mut self) {
        self.pdev.disable_sriov();
    }
}

/// Permission to disable VFs during a driver's [`Driver::sriov_disable()`] callback.
///
/// The PCI adapter creates this token for the PF being configured. It cannot be cloned or sent
/// to another thread, and its lifetime is restricted to the callback. Dropping the token does
/// not disable VFs, allowing the callback to reject a disable request.
pub struct SriovDisable<'a> {
    pdev: &'a Device<device::CoreInternal<'a>>,
}

impl SriovDisable<'_> {
    /// Disables all VFs and waits for their drivers to unbind.
    ///
    /// The PF resources used by VF drivers must remain available until this method returns.
    #[inline]
    pub fn disable(self) {
        self.pdev.disable_sriov();
    }
}

impl<T: Driver> Adapter<T> {
    pub(super) extern "C" fn sriov_configure_callback(
        pdev: *mut bindings::pci_dev,
        nr_virtfn: c_int,
    ) -> c_int {
        // SAFETY: The PCI core calls this through the PF-only `sriov_numvfs` sysfs attribute,
        // with a valid `struct pci_dev` and while holding the device lock.
        //
        // INVARIANT: `pdev` is valid for the duration of `sriov_configure_callback()`.
        let pdev = unsafe { &*pdev.cast::<Device<device::CoreInternal<'_>>>() };

        // SAFETY: `sriov_configure` is called only after a successful probe and before unbind, so
        // the stored pointer has type `T::Data<'_>` and remains valid throughout this callback.
        let data = unsafe { pdev.as_ref().drvdata_borrow::<T::Data<'_>>() };

        from_result(|| {
            if nr_virtfn == 0 {
                T::sriov_disable(pdev, data, SriovDisable { pdev })?;
                // The driver may return `Ok` without calling `SriovDisable::disable()`, since
                // dropping the token does not disable the VFs. Do not report success while VFs
                // remain enabled.
                if pdev.num_vf() != 0 {
                    return Err(EBUSY);
                }
                Ok(0)
            } else {
                let num_vfs =
                    NonZero::new(u16::try_from(nr_virtfn).map_err(|_| EINVAL)?).ok_or(EINVAL)?;
                let enabled = T::sriov_enable(pdev, data, SriovEnable { pdev, num_vfs })?;
                Ok(enabled.disarm().into())
            }
        })
    }
}

/// Wrapper for VF registration data stored inside a [`VfRegistration`].
///
/// Stores a [`TypeId`] header (derived from `F`) followed by the pinned data,
/// so that [`Device::vf_registration_data_with()`] can verify the type at
/// runtime.
#[repr(C)]
#[pin_data]
struct VfRegistrationData<'a, F: ForLt + 'static> {
    type_id: TypeId,
    #[pin]
    data: F::Of<'a>,
}

static_assert!(
    core::mem::offset_of!(VfRegistrationData<'static, CovariantForLt!(())>, type_id) == 0
);

impl<'a, F: ForLt + 'static> VfRegistrationData<'a, F> {
    /// Pin-initializer for the registration data.
    #[inline]
    fn new<E>(data: impl PinInit<F::Of<'a>, E>) -> impl PinInit<Self, E> {
        try_pin_init!(Self {
            type_id: TypeId::of::<F>(),
            data <- data,
        }? E)
    }
}

/// SR-IOV VF registration on a PF device.
///
/// Owns the registration data that VF drivers access via
/// [`Device::vf_registration_data_with()`] and [`Device::vf_registration_data()`].
///
/// Drop disables SR-IOV before clearing the registration pointer and releasing the data.
///
/// When `CONFIG_PCI_IOV` is disabled, the registration still initializes, pins and owns its data,
/// but does not publish it to VF drivers.
#[pin_data(PinnedDrop)]
pub struct VfRegistration<'a, F: ForLt + 'static> {
    pdev: &'a Device<device::Bound>,
    #[pin]
    inner: VfRegistrationData<'a, F>,
    #[pin]
    _pin: PhantomPinned,
}

impl<'a, F: ForLt + 'static> VfRegistration<'a, F>
where
    for<'b> F::Of<'b>: Send + Sync,
{
    /// Create a new VF registration.
    ///
    /// Returns a pin-initializer so the registration can be embedded directly
    /// in the PF driver's bus device private data.
    ///
    /// # Safety
    ///
    /// The returned registration must be embedded in the driver's bus device private data.
    pub unsafe fn new<'core, E, I>(
        pdev: &'a Device<device::Core<'core>>,
        data: I,
    ) -> impl PinInit<Self, Error> + use<'a, 'core, E, F, I>
    where
        I: PinInit<F::Of<'a>, E>,
        Error: From<E>,
    {
        try_pin_init!(Self {
            _: {
                if pdev.is_virtfn() {
                    return Err(ENODEV);
                }
                if pdev.num_vf() != 0 {
                    return Err(EBUSY);
                }
                // SAFETY: The core callback serializes changes to this device's registration.
                if !unsafe { vf_registration_data_ptr(pdev.as_raw()) }.is_null() {
                    return Err(EBUSY);
                }
            },
            pdev,
            inner <- VfRegistrationData::new(data),
            _pin: PhantomPinned,
            _: {
                // The data initializer may have registered another object on this device.
                // SAFETY: The captured core context still serializes registration changes.
                if !unsafe { vf_registration_data_ptr(pdev.as_raw()) }.is_null() {
                    return Err(EBUSY);
                }

                // SAFETY: The data is initialized and pinned, the slot is unoccupied, and
                // no VF can access it yet. No fallible work follows publication.
                unsafe {
                    set_vf_registration_data_ptr(
                        pdev.as_raw(),
                        core::ptr::from_ref(inner.as_ref().get_ref()).cast_mut().cast(),
                    );
                }
            },
        })
    }
}

#[pinned_drop]
impl<F: ForLt + 'static> PinnedDrop for VfRegistration<'_, F> {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: `pci_disable_sriov()` is safe to call on any `pci_dev`; it
        // is a no-op if the device has no VFs enabled. When VFs are enabled,
        // this blocks until all VF `remove()` callbacks complete.
        unsafe { bindings::pci_disable_sriov(self.pdev.as_raw()) };

        // SAFETY: The device is valid and all VF remove callbacks have completed, so no VF
        // can access the registration pointer. The data remains alive until this returns.
        unsafe { set_vf_registration_data_ptr(self.pdev.as_raw(), core::ptr::null_mut()) };
    }
}

// SAFETY: The inner data is `Send` (enforced by the bound), and `&Device` is `Send + Sync`.
unsafe impl<F: ForLt> Send for VfRegistration<'_, F> where for<'a> F::Of<'a>: Send {}

// SAFETY: The inner data is `Send + Sync`. `VfRegistration` doesn't expose mutable access;
// VF drivers only read the data through an immutable pinned reference.
unsafe impl<F: ForLt> Sync for VfRegistration<'_, F> where for<'a> F::Of<'a>: Send + Sync {}

impl Device<device::Bound> {
    /// Return the zero-based VF index within its PF, or an error for a non-VF device.
    ///
    /// Returns [`ENOSYS`] when `CONFIG_PCI_IOV` is disabled.
    #[inline]
    pub fn vf_id(&self) -> Result<u16> {
        // SAFETY: `self.as_raw()` points to a live PCI device; the helper checks VF membership.
        let id = unsafe { bindings::pci_iov_vf_id(self.as_raw()) };
        to_result(id)?;
        Ok(id.try_into()?)
    }

    /// Internal helper: reads the `vf_registration_data_rust` pointer from the
    /// PF, checks the `TypeId`, and returns a pinned reference.
    ///
    /// # Safety
    ///
    /// The data lifetime must be hidden behind a higher-ranked closure independently of the
    /// reference lifetime, or `F` must be covariant in its encoded lifetime.
    #[cfg(CONFIG_PCI_IOV)]
    unsafe fn vf_registration_data_pinned<F: ForLt + 'static>(&self) -> Result<Pin<&F::Of<'_>>> {
        if !self.is_virtfn() {
            return Err(ENODEV);
        }

        // SAFETY: This bound VF uses the `physfn` union field. PCI retains its PF until
        // VF removal completes, and the PF keeps the registration installed until then.
        let ptr = unsafe {
            let pf = (*self.as_raw()).__bindgen_anon_1.physfn;
            vf_registration_data_ptr(pf)
        };

        if ptr.is_null() {
            return Err(ENODEV);
        }

        // SAFETY: The registration keeps its data installed until VF removal completes,
        // including when probe initialization rolls back.
        // `ptr` points to a `VfRegistrationData` whose first field is a `TypeId`.
        let type_id = unsafe { ptr.cast::<TypeId>().read() };
        if type_id != TypeId::of::<F>() {
            return Err(EINVAL);
        }

        // SAFETY: TypeId check confirms the stored type matches `F`. The data
        // is pinned inside the PF's driver data struct. Lifetime shortening
        // from the PF's binding scope to `'_` is layout-compatible.
        let data_ptr = unsafe {
            let vfrd = ptr.cast::<VfRegistrationData<'_, F>>();
            &raw const (*vfrd).data
        };

        // SAFETY: `data` is structurally pinned inside `VfRegistrationData`.
        Ok(unsafe { Pin::new_unchecked(&*data_ptr) })
    }

    /// Returns [`ENODEV`] because no VF registration can be published.
    ///
    /// # Safety
    ///
    /// The data lifetime must be hidden behind a higher-ranked closure independently of the
    /// reference lifetime, or `F` must be covariant in its encoded lifetime.
    #[cfg(not(CONFIG_PCI_IOV))]
    unsafe fn vf_registration_data_pinned<F: ForLt + 'static>(&self) -> Result<Pin<&F::Of<'_>>> {
        Err(ENODEV)
    }

    /// Access the VF registration data through a closure with an HRTB lifetime.
    ///
    /// `F` is the [`ForLt`](trait@ForLt) encoding of the data type. Returns
    /// [`ENODEV`] if this is not a VF or no data was registered,
    /// or [`EINVAL`] if `F` does not match the type registered by the PF.
    /// Returns [`ENODEV`] when `CONFIG_PCI_IOV` is disabled.
    ///
    /// The reference is borrowed from this VF, while the registration data's lifetime remains
    /// abstract so the closure cannot store shorter-lived references in invariant data.
    #[inline]
    pub fn vf_registration_data_with<'this, F: ForLt + 'static, R>(
        &'this self,
        f: impl for<'a> FnOnce(Pin<&'this F::Of<'a>>) -> R,
    ) -> Result<R> {
        // SAFETY: The closure is higher-ranked over the data lifetime, independently of `'this`.
        // It cannot insert shorter-lived references, and the outer borrow cannot outlive this VF.
        let pinned = unsafe { self.vf_registration_data_pinned::<F>()? };
        Ok(f(pinned))
    }

    /// Returns a pinned reference to the VF registration data.
    ///
    /// Available only when `F` implements [`CovariantForLt`](trait@crate::types::CovariantForLt),
    /// guaranteeing that shortening the PF data lifetime is sound.
    ///
    /// For non-covariant types, use [`Self::vf_registration_data_with()`].
    ///
    /// It returns the same errors as [`Self::vf_registration_data_with()`].
    #[inline]
    pub fn vf_registration_data<F: CovariantForLt + 'static>(&self) -> Result<Pin<&F::Of<'_>>> {
        // SAFETY: `CovariantForLt` permits shortening the encoded lifetime to this borrow.
        unsafe { self.vf_registration_data_pinned::<F>() }
    }
}
