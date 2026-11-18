// SPDX-License-Identifier: GPL-2.0 OR MIT

//! DRM File objects.
//!
//! C header: [`include/drm/drm_file.h`](srctree/include/drm/drm_file.h)

use crate::{
    bindings,
    drm,
    prelude::*,
    sync::atomic::{
        Relaxed,
        Release, //
    },
    types::Opaque, //
};
use core::marker::PhantomData;

/// Trait that must be implemented by DRM drivers to represent a DRM File (a client instance).
///
/// The lifetime `'a` allows the file data to borrow from
/// [`RegistrationData`](drm::Driver::RegistrationData).
pub trait DriverFile<'a>: Sized + Send + Sync {
    /// The parent `Driver` implementation for this `DriverFile`.
    type Driver: drm::Driver;

    /// Open a new DRM file, creating the per-file driver data.
    ///
    /// Called when a client opens the DRM device. The returned initializer may borrow from
    /// `reg_data` with lifetime `'a`.
    fn open(
        device: &drm::Device<Self::Driver, drm::Registered>,
        reg_data: &'a <Self::Driver as drm::Driver>::RegistrationData<'a>,
    ) -> impl PinInit<Self, Error>;
}

/// File-private allocation, with a link for dropping detached data outside `filelist_mutex`.
#[pin_data]
pub(super) struct FileData<T> {
    /// Pinned per-file driver data, which may borrow from registration data.
    #[pin]
    data: T,
    /// Next detached allocation to drop during registration teardown; otherwise `None`.
    pub(super) next: Option<Pin<KBox<Self>>>,
}

/// An open DRM File.
///
/// # Invariants
///
/// - `self.0` is a valid instance of a `struct drm_file` opened on a device of driver `D`.
/// - A [`drm::RegistrationGuard`] for that device is held for the duration of any `&File<D>`
///   reference.
#[repr(transparent)]
pub struct File<D: drm::Driver>(Opaque<bindings::drm_file>, PhantomData<D>);

impl<D: drm::Driver> File<D> {
    #[doc(hidden)]
    /// Not intended to be called externally, except via declare_drm_ioctls!()
    ///
    /// # Safety
    ///
    /// - `ptr` must point to an open `struct drm_file` on a device of driver `D` and remain valid
    ///   for `'a`.
    /// - A [`drm::RegistrationGuard`] for that device must be held for all of `'a`.
    #[inline]
    pub unsafe fn from_raw<'a>(ptr: *mut bindings::drm_file) -> &'a File<D> {
        // SAFETY:
        // - The caller guarantees that `ptr` is valid for `'a`.
        // - The caller guarantees that the type invariants hold.
        unsafe { &*ptr.cast() }
    }

    pub(super) fn as_raw(&self) -> *mut bindings::drm_file {
        self.0.get()
    }

    /// Returns the registered DRM device this file was opened on.
    #[inline]
    pub fn device(&self) -> &drm::Device<D, drm::Registered> {
        // SAFETY:
        // - The open file keeps its minor and device alive.
        // - By the type invariants, the device uses driver `D`.
        // - The type invariants require a `RegistrationGuard` for the device throughout this
        //   borrow, satisfying the `Registered` context.
        unsafe { drm::Device::from_raw((*(*self.as_raw()).minor).dev) }
    }

    /// Access the driver file data through a closure.
    ///
    /// The closure receives a pinned reference to the file data.
    ///
    /// The outer reference carries the `&self` lifetime while the inner type carries the HRTB
    /// lifetime `'a`, implying `'a` outlives `&self`. This allows the closure to coerce covariant
    /// sub-fields (e.g. `&'a T` to the caller's lifetime) and return them directly in `R`.
    #[inline]
    pub fn inner_with<'this, R, F>(&'this self, f: F) -> R
    where
        F: for<'a> FnOnce(Pin<&'this D::File<'a>>) -> R,
    {
        // SAFETY: By the type invariants, `self.as_raw()` points to a valid `drm_file`.
        let ptr: *const FileData<_> = unsafe { (*self.as_raw()).driver_priv.cast_const().cast() };

        // SAFETY:
        // - The type invariants keep this file's pinned `FileData` allocation valid for `'this`.
        // - The `data` field is structurally pinned.
        // - The HRTB `for<'a>` prevents the caller from choosing a concrete lifetime, so shortening
        //   is sound regardless of variance.
        let data: Pin<&'this D::File<'this>> = unsafe { Pin::new_unchecked(&(*ptr).data) };
        f(data)
    }

    /// The open callback of a `struct drm_file`.
    ///
    /// Called from `drm_open()`, which is itself called from `fops_open()`. The latter holds a
    /// `RegistrationGuard`, so the device is guaranteed to be registered for the duration of this
    /// callback.
    pub(crate) extern "C" fn open_callback(
        raw_dev: *mut bindings::drm_device,
        raw_file: *mut bindings::drm_file,
    ) -> core::ffi::c_int {
        // SAFETY:
        // - The DRM core guarantees that `raw_dev` is valid.
        // - `fops_open()` holds a `RegistrationGuard`, satisfying the `Registered` context.
        let dev: &drm::device::Device<D, drm::Registered> =
            unsafe { drm::device::Device::from_raw(raw_dev) };

        dev.registration_data_with(|reg_data| {
            let init = try_pin_init!(FileData {
                next: None,
                data <- <D::File<'_> as DriverFile<'_>>::open(dev, reg_data),
            });
            let inner = match KBox::try_pin_init(init, GFP_KERNEL) {
                Err(e) => return e.to_errno(),
                Ok(i) => i,
            };

            // SAFETY: The allocation stays pinned until `postclose_callback()` or
            // `Registration::drop_file_data()` drops it in place.
            let driver_priv = KBox::into_raw(unsafe { Pin::into_inner_unchecked(inner) });

            dev.open_count.fetch_add(1, Relaxed);

            // SAFETY: `raw_file` is a valid pointer to a `struct drm_file`.
            unsafe { (*raw_file).driver_priv = driver_priv.cast() };

            0
        })
    }

    /// The postclose callback of a `struct drm_file`.
    pub(crate) extern "C" fn postclose_callback(
        raw_dev: *mut bindings::drm_device,
        raw_file: *mut bindings::drm_file,
    ) {
        // Registration cleanup may have taken ownership and cleared `driver_priv`. For files
        // that reached the filelist, `drm_close_helper()` removes them under `filelist_mutex`
        // before this callback, synchronizing with `Registration::drop_file_data()`.

        // SAFETY: `raw_file` is a valid pointer to a `struct drm_file`.
        let driver_priv = unsafe { (*raw_file).driver_priv };

        if driver_priv.is_null() {
            return;
        }

        // SAFETY:
        // - `driver_priv` comes from `KBox::into_raw()` in `open_callback()`.
        // - The file is not on the filelist, and the NULL check rules out ownership having been
        //   transferred to `Registration::drop_file_data()`.
        // - The pinned data is dropped in place while registration data is still alive, since
        //   registration cleanup waits for `open_count` to reach zero.
        drop(unsafe { KBox::from_raw(driver_priv.cast::<FileData<D::File<'static>>>()) });

        // SAFETY: `raw_dev` is valid for the lifetime of the `struct drm_file`.
        let dev: &drm::device::Device<D> = unsafe { drm::device::Device::from_raw(raw_dev) };
        if dev.open_count.fetch_sub(1, Release) == 1 {
            dev.open_count_wq.wake_up();
        }
    }
}

impl<D: drm::Driver> super::private::Sealed for File<D> {}
