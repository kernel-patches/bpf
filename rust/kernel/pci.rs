// SPDX-License-Identifier: GPL-2.0

//! Abstractions for the PCI bus.
//!
//! C header: [`include/linux/pci.h`](srctree/include/linux/pci.h)

use crate::{
    bindings,
    device,
    device_id::{
        RawDeviceId,
        RawDeviceIdIndex, //
    },
    driver,
    error::{
        from_result,
        to_result, //
    },
    io::resource,
    prelude::*,
    str::CStr,
    types::Opaque,
    ThisModule, //
};
use core::{
    marker::PhantomData,
    mem::offset_of,
    num::NonZero,
    ptr::{
        addr_of_mut,
        NonNull, //
    },
};

mod cap;
mod id;
mod io;
mod iov;
mod irq;

pub use self::cap::{
    ExtCapId,
    ExtCapability,
    ExtSriovCapability,
    ExtSriovRegs,
    ExtSriovVfBar, //
};
pub use self::id::{
    Class,
    ClassMask,
    Vendor, //
};
pub use self::io::{
    Bar,
    ConfigSpace,
    ConfigSpaceSize,
    DevresBar,
    Extended,
    Normal, //
};
pub use self::iov::{
    SriovDisable,
    SriovEnable,
    SriovEnabled,
    VfRegistration, //
};
pub use self::irq::{
    IrqType,
    IrqTypes,
    IrqVector,
    IrqVectorRegistration, //
};

/// An adapter for the registration of PCI drivers.
pub struct Adapter<T: Driver>(T);

// SAFETY:
// - `bindings::pci_driver` is a C type declared as `repr(C)`.
// - `T::Data` is the type of the driver's device private data.
// - `struct pci_driver` embeds a `struct device_driver`.
// - `DEVICE_DRIVER_OFFSET` is the correct byte offset to the embedded `struct device_driver`.
unsafe impl<T: Driver> driver::DriverLayout for Adapter<T> {
    type DriverType = bindings::pci_driver;
    type DriverData<'bound> = T::Data<'bound>;
    const DEVICE_DRIVER_OFFSET: usize = core::mem::offset_of!(Self::DriverType, driver);
}

// SAFETY: A call to `unregister` for a given instance of `DriverType` is guaranteed to be valid if
// a preceding call to `register` has been successful.
unsafe impl<T: Driver> driver::RegistrationOps for Adapter<T> {
    unsafe fn register(
        pdrv: &Opaque<Self::DriverType>,
        name: &'static CStr,
        module: &'static ThisModule,
    ) -> Result {
        const_assert!(
            T::HAS_SRIOV_ENABLE == T::HAS_SRIOV_DISABLE,
            "PCI drivers must implement both sriov_enable and sriov_disable"
        );

        // SAFETY: It's safe to set the fields of `struct pci_driver` on initialization.
        unsafe {
            (*pdrv.get()).name = name.as_char_ptr();
            (*pdrv.get()).probe = Some(Self::probe_callback);
            (*pdrv.get()).remove = Some(Self::remove_callback);
            (*pdrv.get()).id_table = T::ID_TABLE.as_ptr();
            (*pdrv.get()).driver_managed_dma = T::DRIVER_MANAGED_DMA.is_some();
            if T::HAS_ERROR_DETECTED || T::HAS_RESET_PREPARE || T::HAS_RESET_DONE {
                (*pdrv.get()).err_handler = &Self::ERROR_HANDLERS;
            }
            if T::HAS_SRIOV_ENABLE {
                (*pdrv.get()).sriov_configure = Some(Self::sriov_configure_callback);
            }
        }

        // SAFETY: `pdrv` is guaranteed to be a valid `DriverType`.
        to_result(unsafe {
            bindings::__pci_register_driver(pdrv.get(), module.as_ptr(), name.as_char_ptr())
        })
    }

    unsafe fn unregister(pdrv: &Opaque<Self::DriverType>) {
        // SAFETY: `pdrv` is guaranteed to be a valid `DriverType`.
        unsafe { bindings::pci_unregister_driver(pdrv.get()) }
    }
}

impl<T: Driver> Adapter<T> {
    extern "C" fn probe_callback(
        pdev: *mut bindings::pci_dev,
        id: *const bindings::pci_device_id,
    ) -> c_int {
        // SAFETY: The PCI bus only ever calls the probe callback with a valid pointer to a
        // `struct pci_dev`.
        //
        // INVARIANT: `pdev` is valid for the duration of `probe_callback()`.
        let pdev = unsafe { &*pdev.cast::<Device<device::CoreInternal<'_>>>() };

        // SAFETY: `DeviceId` is a `#[repr(transparent)]` wrapper of `struct pci_device_id` and
        // does not add additional invariants, so it's safe to transmute.
        let id = unsafe { &*id.cast::<DeviceId>() };

        // SAFETY: `id` comes from `T::ID_TABLE` which is of type `IdArray<_, T::IdInfo>` or
        // `pci_device_id_any` which has 0 as driver_data. It can also come from dynamic IDs, which
        // will ensure that `driver_data` exists in `T::ID_TABLE`.
        let info = unsafe { id.info_unchecked_opt::<T::IdInfo>() };

        from_result(|| {
            let data = T::probe(pdev, info);

            pdev.as_ref().set_drvdata(data)?;
            Ok(0)
        })
    }

    extern "C" fn remove_callback(pdev: *mut bindings::pci_dev) {
        // SAFETY: The PCI bus only ever calls the remove callback with a valid pointer to a
        // `struct pci_dev`.
        //
        // INVARIANT: `pdev` is valid for the duration of `remove_callback()`.
        let pdev = unsafe { &*pdev.cast::<Device<device::CoreInternal<'_>>>() };

        // SAFETY: `remove_callback` is only ever called after a successful call to
        // `probe_callback`, hence it's guaranteed that `Device::set_drvdata()` has been called
        // and stored a `Pin<KBox<T::Data<'_>>>`.
        let data = unsafe { pdev.as_ref().drvdata_borrow::<T::Data<'_>>() };

        T::unbind(pdev, data);

        // SAFETY: The driver's unbind callback has returned, and no callbacks retain a borrow.
        let data = unsafe { pdev.as_ref().drvdata_obtain::<T::Data<'_>>() };

        // Drop the private data here, ahead of `driver::Registration::post_unbind_callback()`,
        // which would otherwise drop it after `pci_device_remove()` returns. `drvdata_obtain()`
        // has cleared the driver data pointer, so that callback finds nothing left to drop.
        //
        // This is a special case for VFIO-PCI: `vfio_pci_core_unregister_device()` must be
        // called from `pci_device_remove()`. In general, private data must not rely on being
        // dropped from the bus remove callback; any point after the driver's remove callback and
        // before `devres_release_all()` in `device_unbind_cleanup()` is sufficient.
        drop(data);
    }

    extern "C" fn reset_prepare_callback(pdev: *mut bindings::pci_dev) {
        // SAFETY: The PCI core only ever calls the reset_prepare callback with a valid pointer to
        // a `struct pci_dev`, while holding the device lock.
        //
        // INVARIANT: `pdev` is valid for the duration of `reset_prepare_callback()`.
        let pdev = unsafe { &*pdev.cast::<Device<device::CoreInternal<'_>>>() };

        // SAFETY: The PCI core only calls this callback for a device bound to this driver. The
        // device lock excludes `probe_callback()` and `remove_callback()`, so the stored pointer
        // has type `T::Data<'_>` and remains valid throughout this callback.
        let data = unsafe { pdev.as_ref().drvdata_borrow::<T::Data<'_>>() };

        T::reset_prepare(pdev, data);
    }

    extern "C" fn reset_done_callback(pdev: *mut bindings::pci_dev) {
        // SAFETY: The PCI core only ever calls the reset_done callback with a valid pointer to a
        // `struct pci_dev`, while holding the device lock.
        //
        // INVARIANT: `pdev` is valid for the duration of `reset_done_callback()`.
        let pdev = unsafe { &*pdev.cast::<Device<device::CoreInternal<'_>>>() };

        // SAFETY: The PCI core only calls this callback for a device bound to this driver. The
        // device lock excludes `probe_callback()` and `remove_callback()`, so the stored pointer
        // has type `T::Data<'_>` and remains valid throughout this callback.
        let data = unsafe { pdev.as_ref().drvdata_borrow::<T::Data<'_>>() };

        T::reset_done(pdev, data);
    }

    extern "C" fn error_detected_callback(
        pdev: *mut bindings::pci_dev,
        state: bindings::pci_channel_state_t,
    ) -> bindings::pci_ers_result_t {
        // SAFETY: PCI error recovery only ever calls the error_detected callback with a valid
        // pointer to a `struct pci_dev`. AER (`report_error_detected()`) and EEH hold the device
        // lock while calling it.
        //
        // INVARIANT: `pdev` is valid for the duration of `error_detected_callback()`.
        let pdev = unsafe { &*pdev.cast::<Device<device::CoreInternal<'_>>>() };

        // SAFETY: PCI error recovery only calls this callback for a device bound to this driver.
        // The device lock excludes `probe_callback()` and `remove_callback()`, so the stored
        // pointer has type `T::Data<'_>` and remains valid throughout this callback.
        let data = unsafe { pdev.as_ref().drvdata_borrow::<T::Data<'_>>() };

        let Some(state) = ChannelState::from_raw(state) else {
            // PCI error recovery only reports the states `ChannelState` represents.
            return ErsResult::None.as_raw();
        };

        T::error_detected(pdev, data, state).as_raw()
    }

    const ERROR_HANDLERS: bindings::pci_error_handlers = bindings::pci_error_handlers {
        error_detected: if T::HAS_ERROR_DETECTED {
            Some(Self::error_detected_callback)
        } else {
            None
        },
        mmio_enabled: None,
        slot_reset: None,
        reset_prepare: if T::HAS_RESET_PREPARE {
            Some(Self::reset_prepare_callback)
        } else {
            None
        },
        reset_done: if T::HAS_RESET_DONE {
            Some(Self::reset_done_callback)
        } else {
            None
        },
        resume: None,
        cor_error_detected: None,
    };
}

/// Declares a kernel module that exposes a single PCI driver.
///
/// # Examples
///
///```ignore
/// kernel::module_pci_driver! {
///     type: MyDriver,
///     name: "Module name",
///     authors: ["Author name"],
///     description: "Description",
///     license: "GPL v2",
/// }
///```
#[macro_export]
macro_rules! module_pci_driver {
($($f:tt)*) => {
    $crate::module_driver!(<T>, $crate::pci::Adapter<T>, { $($f)* });
};
}

/// Abstraction for the PCI device ID structure ([`struct pci_device_id`]).
///
/// [`struct pci_device_id`]: https://docs.kernel.org/PCI/pci.html#c.pci_device_id
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct DeviceId(bindings::pci_device_id);

impl DeviceId {
    const PCI_ANY_ID: u32 = !0;

    /// Create a new `pci::DeviceId` for a VFIO driver from a vendor and device ID.
    ///
    /// The ID matches every device with this vendor and device ID, whatever its class. Matching
    /// through this entry requires `driver_override` to select the driver. The module alias
    /// generated for the ID has the `vfio_pci:` prefix, which lets userspace find the VFIO driver
    /// for a device.
    ///
    /// Equivalent to C's `PCI_DRIVER_OVERRIDE_DEVICE_VFIO` macro.
    #[inline]
    pub const fn from_id_vfio_override(vendor: Vendor, device: u32) -> Self {
        let mut id = Self::from_id(vendor, device);
        id.0.override_only = bindings::PCI_ID_F_VFIO_DRIVER_OVERRIDE;
        id
    }

    /// Equivalent to C's `PCI_DEVICE` macro.
    ///
    /// Create a new `pci::DeviceId` from a vendor and device ID.
    #[inline]
    pub const fn from_id(vendor: Vendor, device: u32) -> Self {
        Self(bindings::pci_device_id {
            vendor: vendor.as_raw() as u32,
            device,
            subvendor: DeviceId::PCI_ANY_ID,
            subdevice: DeviceId::PCI_ANY_ID,
            class: 0,
            class_mask: 0,
            driver_data: 0,
            override_only: 0,
        })
    }

    /// Equivalent to C's `PCI_DEVICE_CLASS` macro.
    ///
    /// Create a new `pci::DeviceId` from a class number and mask.
    #[inline]
    pub const fn from_class(class: u32, class_mask: u32) -> Self {
        Self(bindings::pci_device_id {
            vendor: DeviceId::PCI_ANY_ID,
            device: DeviceId::PCI_ANY_ID,
            subvendor: DeviceId::PCI_ANY_ID,
            subdevice: DeviceId::PCI_ANY_ID,
            class,
            class_mask,
            driver_data: 0,
            override_only: 0,
        })
    }

    /// Create a new [`DeviceId`] from a class number, mask, and specific vendor.
    ///
    /// This is more targeted than [`DeviceId::from_class`]: in addition to matching by [`Vendor`],
    /// it also matches the PCI [`Class`] (up to the entire 24 bits, depending on the
    /// [`ClassMask`]).
    #[inline]
    pub const fn from_class_and_vendor(
        class: Class,
        class_mask: ClassMask,
        vendor: Vendor,
    ) -> Self {
        Self(bindings::pci_device_id {
            vendor: vendor.as_raw() as u32,
            device: DeviceId::PCI_ANY_ID,
            subvendor: DeviceId::PCI_ANY_ID,
            subdevice: DeviceId::PCI_ANY_ID,
            class: class.as_raw(),
            class_mask: class_mask.as_raw(),
            driver_data: 0,
            override_only: 0,
        })
    }
}

// SAFETY: `DeviceId` is a `#[repr(transparent)]` wrapper of `pci_device_id` and does not add
// additional invariants, so it's safe to transmute to `RawType`.
unsafe impl RawDeviceId for DeviceId {
    type RawType = bindings::pci_device_id;
}

// SAFETY: `DRIVER_DATA_OFFSET` is the offset to the `driver_data` field.
unsafe impl RawDeviceIdIndex for DeviceId {
    const DRIVER_DATA_OFFSET: usize = core::mem::offset_of!(bindings::pci_device_id, driver_data);
}

/// Marker for a driver that manages DMA ownership of its devices by itself.
///
/// The driver core does not claim the default DMA domain for the devices of such a driver. See
/// [`Driver::DRIVER_MANAGED_DMA`].
pub struct DriverManagedDma<D: ?Sized>(PhantomData<fn() -> *mut D>);

impl<D: ?Sized> DriverManagedDma<D> {
    /// Declares that driver `D` manages DMA ownership of its devices by itself.
    ///
    /// # Safety
    ///
    /// The caller must ensure that devices bound to `D` are not used for DMA allocations or
    /// mappings through the kernel DMA API, directly or through helpers.
    pub const unsafe fn new() -> Self {
        Self(PhantomData)
    }
}

/// The state of the I/O channel to a device, as reported by PCI error recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelState {
    /// The I/O channel remains operational.
    Normal,
    /// I/O to the device is blocked.
    Frozen,
    /// The device has permanently failed.
    PermanentFailure,
}

impl ChannelState {
    fn from_raw(state: bindings::pci_channel_state_t) -> Option<Self> {
        match state {
            bindings::pci_channel_io_normal => Some(Self::Normal),
            bindings::pci_channel_io_frozen => Some(Self::Frozen),
            bindings::pci_channel_io_perm_failure => Some(Self::PermanentFailure),
            _ => None,
        }
    }
}

/// The result a driver reports to PCI error recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErsResult {
    /// The driver has no result to report.
    None,
    /// The driver can recover without a slot reset.
    CanRecover,
    /// The driver needs the slot to be reset.
    NeedReset,
    /// The device has failed completely and cannot be recovered.
    Disconnect,
    /// The driver has fully recovered and the device is operational.
    Recovered,
}

impl ErsResult {
    fn as_raw(self) -> bindings::pci_ers_result_t {
        match self {
            Self::None => bindings::pci_ers_result_PCI_ERS_RESULT_NONE,
            Self::CanRecover => bindings::pci_ers_result_PCI_ERS_RESULT_CAN_RECOVER,
            Self::NeedReset => bindings::pci_ers_result_PCI_ERS_RESULT_NEED_RESET,
            Self::Disconnect => bindings::pci_ers_result_PCI_ERS_RESULT_DISCONNECT,
            Self::Recovered => bindings::pci_ers_result_PCI_ERS_RESULT_RECOVERED,
        }
    }
}

/// `IdTable` type for PCI.
pub type IdTable<T> = &'static dyn kernel::device_id::IdTable<DeviceId, T>;

/// Create a PCI `IdTable` with its alias for modpost.
#[macro_export]
macro_rules! pci_device_table {
    ($($tt:tt)*) => {
        $crate::module_device_table!("pci", $crate::pci::DeviceId, $($tt)*);
    };
}

/// The PCI driver trait.
///
/// # Examples
///
///```
/// # use kernel::{bindings, device::Core, pci};
///
/// struct MyDriver;
///
/// kernel::pci_device_table!(
///     PCI_TABLE,
///     <MyDriver as pci::Driver>::IdInfo,
///     [
///         (
///             pci::DeviceId::from_id(pci::Vendor::REDHAT, bindings::PCI_ANY_ID as u32),
///             (),
///         )
///     ]
/// );
///
/// #[vtable]
/// impl pci::Driver for MyDriver {
///     type IdInfo = ();
///     type Data<'bound> = Self;
///     const ID_TABLE: pci::IdTable<Self::IdInfo> = &PCI_TABLE;
///
///     fn probe<'bound>(
///         _pdev: &'bound pci::Device<Core<'_>>,
///         _id_info: Option<&'bound Self::IdInfo>,
///     ) -> impl PinInit<Self::Data<'bound>, Error> + 'bound {
///         Err(ENODEV)
///     }
/// }
///```
/// Drivers must implement this trait in order to get a PCI driver registered. Please refer to the
/// `Adapter` documentation for an example.
#[vtable]
pub trait Driver {
    /// The type holding information about each device id supported by the driver.
    // TODO: Use `associated_type_defaults` once stabilized:
    //
    // ```
    // type IdInfo: 'static = ();
    // ```
    type IdInfo: 'static;

    /// The type of the driver's bus device private data.
    type Data<'bound>: Send + 'bound;

    /// The table of device ids supported by the driver.
    const ID_TABLE: IdTable<Self::IdInfo>;

    /// Set if the driver manages DMA ownership of its devices by itself, instead of using the
    /// default DMA domain. Construct with [`DriverManagedDma::new`].
    const DRIVER_MANAGED_DMA: Option<DriverManagedDma<Self>> = None;

    /// PCI driver probe.
    ///
    /// Called when a new pci device is added or discovered. Implementers should
    /// attempt to initialize the device here.
    fn probe<'bound>(
        dev: &'bound Device<device::Core<'_>>,
        id_info: Option<&'bound Self::IdInfo>,
    ) -> impl PinInit<Self::Data<'bound>, Error> + 'bound;

    /// PCI driver unbind.
    ///
    /// Called when a [`Device`] is unbound from its bound [`Driver`]. Implementing this callback
    /// is optional.
    ///
    /// This callback serves as a place for drivers to perform teardown operations that require a
    /// `&Device<Core>` or `&Device<Bound>` reference. For instance, drivers may try to perform I/O
    /// operations to gracefully tear down the device.
    ///
    /// Otherwise, release operations for driver resources should be performed in `Drop`.
    fn unbind<'bound>(dev: &'bound Device<device::Core<'_>>, this: Pin<&Self::Data<'bound>>) {
        let _ = (dev, this);
    }

    /// Called before a PCI reset, with the device lock held.
    #[optional]
    fn reset_prepare<'bound>(_dev: &Device<device::Core<'_>>, _this: Pin<&Self::Data<'bound>>);

    /// Called after a PCI reset attempt, with the device lock held.
    #[optional]
    fn reset_done<'bound>(_dev: &Device<device::Core<'_>>, _this: Pin<&Self::Data<'bound>>);

    /// Handle a PCI error and return the PCI recovery result, with the device lock held.
    #[optional]
    fn error_detected<'bound>(
        _dev: &Device<device::Core<'_>>,
        _this: Pin<&Self::Data<'bound>>,
        _state: ChannelState,
    ) -> ErsResult;

    /// Enables Single Root I/O Virtualization (SR-IOV) for a PF.
    ///
    /// This callback is only invoked when `CONFIG_PCI_IOV` is enabled.
    ///
    /// Called when userspace writes a nonzero VF count to `sriov_numvfs`. The token carries the
    /// requested count and permission to enable VFs on this PF. Return the guard obtained from
    /// [`SriovEnable::enable()`] after completing setup; dropping it rolls back the enable.
    ///
    /// The PF must own a [`VfRegistration`] before enabling VFs. That registration disables
    /// SR-IOV when the driver data is destroyed, while resources needed by VF drivers remain live.
    /// Implement this callback and [`Self::sriov_disable()`] together, or implement neither.
    ///
    /// See [PCI Express I/O Virtualization].
    ///
    /// [PCI Express I/O Virtualization]: https://docs.kernel.org/PCI/pci-iov-howto.html
    ///
    /// # Examples
    ///
    /// ```
    /// # use kernel::{
    /// #     device::Core,
    /// #     pci,
    /// #     prelude::*, //
    /// # };
    /// # struct Data;
    /// fn sriov_enable<'a>(
    ///     _dev: &'a pci::Device<Core<'_>>,
    ///     _data: Pin<&Data>,
    ///     token: pci::SriovEnable<'a>,
    /// ) -> Result<pci::SriovEnabled<'a>> {
    ///     let num_vfs = token.num_vfs();
    ///     let enabled = token.enable(num_vfs)?;
    ///     // Complete any additional setup before returning the guard.
    ///     Ok(enabled)
    /// }
    /// ```
    #[optional]
    fn sriov_enable<'a>(
        _dev: &'a Device<device::Core<'_>>,
        _data: Pin<&Self::Data<'a>>,
        _token: SriovEnable<'a>,
    ) -> Result<SriovEnabled<'a>>;

    /// Disables all VFs of a PF in response to a userspace request.
    ///
    /// This callback is only invoked when `CONFIG_PCI_IOV` is enabled.
    ///
    /// Called when userspace writes zero to `sriov_numvfs`. Call [`SriovDisable::disable()`]
    /// while resources used by VF drivers are still available. Returning an error before calling
    /// it leaves the VFs enabled. Returning success requires that all VFs have been disabled.
    ///
    /// This callback is not invoked during PF unbind; [`VfRegistration`] owns that teardown.
    /// Implement this callback and [`Self::sriov_enable()`] together, or implement neither.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kernel::{
    /// #     device::Core,
    /// #     pci,
    /// #     prelude::*, //
    /// # };
    /// # struct Data;
    /// fn sriov_disable<'a>(
    ///     _dev: &'a pci::Device<Core<'_>>,
    ///     _data: Pin<&Data>,
    ///     token: pci::SriovDisable<'a>,
    /// ) -> Result {
    ///     token.disable();
    ///     Ok(())
    /// }
    /// ```
    #[optional]
    fn sriov_disable<'a>(
        _dev: &'a Device<device::Core<'_>>,
        _data: Pin<&Self::Data<'a>>,
        _token: SriovDisable<'a>,
    ) -> Result;
}

/// The PCI device representation.
///
/// This structure represents the Rust abstraction for a C `struct pci_dev`. The implementation
/// abstracts the usage of an already existing C `struct pci_dev` within Rust code that we get
/// passed from the C side.
///
/// # Invariants
///
/// A [`Device`] instance represents a valid `struct pci_dev` created by the C portion of the
/// kernel.
#[repr(transparent)]
pub struct Device<Ctx: device::DeviceContext = device::Normal>(
    Opaque<bindings::pci_dev>,
    PhantomData<Ctx>,
);

impl<Ctx: device::DeviceContext> Device<Ctx> {
    #[inline]
    fn as_raw(&self) -> *mut bindings::pci_dev {
        self.0.get()
    }
}

impl Device {
    /// Returns `true` if this device is a Virtual Function (VF).
    #[inline]
    pub fn is_virtfn(&self) -> bool {
        // SAFETY: `self.as_raw` is a valid pointer to a `struct pci_dev`.
        unsafe { (*self.as_raw()).is_virtfn() != 0 }
    }

    /// Returns the PCI vendor ID as [`Vendor`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kernel::{device::Core, pci::{self, Vendor}, prelude::*};
    /// fn log_device_info(pdev: &pci::Device<Core<'_>>) -> Result {
    ///     // Get an instance of `Vendor`.
    ///     let vendor = pdev.vendor_id();
    ///     dev_info!(
    ///         pdev,
    ///         "Device: Vendor={}, Device=0x{:x}\n",
    ///         vendor,
    ///         pdev.device_id()
    ///     );
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn vendor_id(&self) -> Vendor {
        // SAFETY: `self.as_raw` is a valid pointer to a `struct pci_dev`.
        let vendor_id = unsafe { (*self.as_raw()).vendor };
        Vendor::from_raw(vendor_id)
    }

    /// Returns the PCI device ID.
    #[inline]
    pub fn device_id(&self) -> u16 {
        // SAFETY: By its type invariant `self.as_raw` is always a valid pointer to a
        // `struct pci_dev`.
        unsafe { (*self.as_raw()).device }
    }

    /// Returns the PCI revision ID.
    #[inline]
    pub fn revision_id(&self) -> u8 {
        // SAFETY: By its type invariant `self.as_raw` is always a valid pointer to a
        // `struct pci_dev`.
        unsafe { (*self.as_raw()).revision }
    }

    /// Returns the PCI bus device/function.
    #[inline]
    pub fn dev_id(&self) -> u16 {
        // SAFETY: By its type invariant `self.as_raw` is always a valid pointer to a
        // `struct pci_dev`.
        unsafe { bindings::pci_dev_id(self.as_raw()) }
    }

    /// Returns the PCI subsystem vendor ID.
    #[inline]
    pub fn subsystem_vendor_id(&self) -> u16 {
        // SAFETY: By its type invariant `self.as_raw` is always a valid pointer to a
        // `struct pci_dev`.
        unsafe { (*self.as_raw()).subsystem_vendor }
    }

    /// Returns the PCI subsystem device ID.
    #[inline]
    pub fn subsystem_device_id(&self) -> u16 {
        // SAFETY: By its type invariant `self.as_raw` is always a valid pointer to a
        // `struct pci_dev`.
        unsafe { (*self.as_raw()).subsystem_device }
    }

    /// Returns the start of the given PCI BAR resource.
    pub fn resource_start(&self, bar: u32) -> Result<bindings::resource_size_t> {
        if !Bar::index_is_valid(bar) {
            return Err(EINVAL);
        }

        // SAFETY:
        // - `bar` is a valid bar number, as guaranteed by the above call to `Bar::index_is_valid`,
        // - by its type invariant `self.as_raw` is always a valid pointer to a `struct pci_dev`.
        Ok(unsafe { bindings::pci_resource_start(self.as_raw(), bar.try_into()?) })
    }

    /// Returns the size of the given PCI BAR resource.
    pub fn resource_len(&self, bar: u32) -> Result<bindings::resource_size_t> {
        if !Bar::index_is_valid(bar) {
            return Err(EINVAL);
        }

        // SAFETY:
        // - `bar` is a valid bar number, as guaranteed by the above call to `Bar::index_is_valid`,
        // - by its type invariant `self.as_raw` is always a valid pointer to a `struct pci_dev`.
        Ok(unsafe { bindings::pci_resource_len(self.as_raw(), bar.try_into()?) })
    }

    /// Returns the resource flags (`IORESOURCE_*`) of the given PCI BAR.
    pub fn resource_flags(&self, bar: u32) -> Result<resource::Flags> {
        if !Bar::index_is_valid(bar) {
            return Err(EINVAL);
        }

        // SAFETY:
        // - `bar` is a valid bar number, as guaranteed by the above call to `Bar::index_is_valid`,
        // - by its type invariant `self.as_raw` is always a valid pointer to a `struct pci_dev`.
        let raw = unsafe { bindings::pci_resource_flags(self.as_raw(), bar.try_into()?) };
        Ok(resource::Flags::from_raw(raw))
    }

    /// Returns the PCI class as a `Class` struct.
    #[inline]
    pub fn pci_class(&self) -> Class {
        // SAFETY: `self.as_raw` is a valid pointer to a `struct pci_dev`.
        Class::from_raw(unsafe { (*self.as_raw()).class })
    }
}

impl Device<device::Bound> {
    /// Returns the PCI domain number of the bus that this device is on.
    #[inline]
    pub fn domain_nr(&self) -> u32 {
        // SAFETY: `self.as_raw()` points to a valid `struct pci_dev`, which holds a reference
        // to its bus. The bound context keeps the host controller data used by
        // `pci_domain_nr()` alive.
        let domain_nr = unsafe { bindings::pci_domain_nr((*self.as_raw()).bus) };

        debug_assert!(domain_nr >= 0);

        // CAST: `pci_domain_nr()` returns an `int`, but a registered bus never has a negative
        // domain. A negative value here is a kernel bug rather than a condition for a caller to
        // handle.
        domain_nr as u32
    }
}

impl<'a> Device<device::Core<'a>> {
    /// Returns the total number of VFs, or [`None`] if SR-IOV is not available.
    #[inline]
    pub fn sriov_get_totalvfs(&self) -> Option<NonZero<u16>> {
        // SAFETY: `self.as_raw()` is a valid pointer to a `struct pci_dev`.
        let total_vfs = unsafe { bindings::pci_sriov_get_totalvfs(self.as_raw()) };

        // CAST: The C function returns `unsigned int`, but the value originates
        // from TotalVFs/driver_max_VFs (which are defined as `u16`), so this cast
        // cannot truncate.
        NonZero::new(total_vfs as u16)
    }

    /// Enable memory resources for this device.
    pub fn enable_device_mem(&self) -> Result {
        // SAFETY: `self.as_raw` is guaranteed to be a pointer to a valid `struct pci_dev`.
        to_result(unsafe { bindings::pci_enable_device_mem(self.as_raw()) })
    }

    /// Enable bus-mastering for this device.
    #[inline]
    pub fn set_master(&self) {
        // SAFETY: `self.as_raw` is guaranteed to be a pointer to a valid `struct pci_dev`.
        unsafe { bindings::pci_set_master(self.as_raw()) };
    }
}

// SAFETY: `pci::Device` is a transparent wrapper of `struct pci_dev`.
// The offset is guaranteed to point to a valid device field inside `pci::Device`.
unsafe impl<Ctx: device::DeviceContext> device::AsBusDevice<Ctx> for Device<Ctx> {
    const OFFSET: usize = offset_of!(bindings::pci_dev, dev);
}

// SAFETY: `Device` is a transparent wrapper of a type that doesn't depend on `Device`'s generic
// argument.
kernel::impl_device_context_deref!(unsafe { Device });
kernel::impl_device_context_into_aref!(Device);

impl<'a> crate::dma::Device<'a> for Device<device::Core<'a>> {}

// SAFETY: Instances of `Device` are always reference-counted.
unsafe impl crate::sync::aref::AlwaysRefCounted for Device {
    #[inline]
    fn inc_ref(&self) {
        // SAFETY: The existence of a shared reference guarantees that the refcount is non-zero.
        unsafe { bindings::pci_dev_get(self.as_raw()) };
    }

    #[inline]
    unsafe fn dec_ref(obj: NonNull<Self>) {
        // SAFETY: The safety requirements guarantee that the refcount is non-zero.
        unsafe { bindings::pci_dev_put(obj.cast().as_ptr()) }
    }
}

impl<Ctx: device::DeviceContext> AsRef<device::Device<Ctx>> for Device<Ctx> {
    fn as_ref(&self) -> &device::Device<Ctx> {
        // SAFETY: By the type invariant of `Self`, `self.as_raw()` is a pointer to a valid
        // `struct pci_dev`.
        let dev = unsafe { addr_of_mut!((*self.as_raw()).dev) };

        // SAFETY: `dev` points to a valid `struct device`.
        unsafe { device::Device::from_raw(dev) }
    }
}

// SAFETY: A `Device` is always reference-counted and can be released from any thread.
unsafe impl Send for Device {}

// SAFETY: `Device` can be shared among threads because all methods of `Device`
// (i.e. `Device<Normal>) are thread safe.
unsafe impl Sync for Device {}

// SAFETY: Same as `Device<Normal>` -- the underlying `struct pci_dev` is the same;
// `Bound` is a zero-sized type-state marker that does not affect thread safety.
unsafe impl Sync for Device<device::Bound> {}
