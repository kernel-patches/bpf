// SPDX-License-Identifier: GPL-2.0 or MIT

use core::mem::offset_of;

use kernel::{
    drm::{
        self,
        Registered, //
    },
    num::casts::FromSafeCast,
    prelude::*,
    uaccess::UserSlice,
    uapi, //
};
use zerocopy::Immutable;

use crate::driver::{
    TyrDrmDevice,
    TyrDrmDriver,
    TyrDrmRegistrationData, //
};

trait UobjMinSize {
    fn min_size(&self) -> usize;
}

impl UobjMinSize for uapi::drm_panthor_gpu_info {
    fn min_size(&self) -> usize {
        offset_of!(Self, tiler_present) + size_of_val(&self.tiler_present)
    }
}

/// If the user buffer is at least the minimum required size, then copy as much of the kernel
/// object as will fit into the user buffer.
///
/// Doesn't fail if the user buffer is smaller than the kernel object. If the user buffer is bigger
/// than needed, the remainder is zeroed out.
fn set_uobj<T: IntoBytes + Immutable>(
    usr_dst: u64,
    size: u32,
    min_size: usize,
    src_obj: &T,
) -> Result {
    let size = usize::from_safe_cast(size);
    if size < min_size {
        return Err(EINVAL);
    }

    let mut writer = UserSlice::new(UserPtr::from_u64(usr_dst), size).writer();
    writer.write_slice_partial(src_obj.as_bytes(), 0)?;
    writer.clear()?;
    Ok(())
}

#[pin_data]
pub(crate) struct TyrDrmFileData {}

/// Convenience type alias for our DRM `File` type.
pub(crate) type TyrDrmFile = drm::file::File<TyrDrmDriver>;

impl drm::file::DriverFile<'_> for TyrDrmFileData {
    type Driver = TyrDrmDriver;

    fn open(
        _device: &TyrDrmDevice<Registered>,
        _reg_data: &TyrDrmRegistrationData<'_>,
    ) -> impl PinInit<Self, Error> {
        Ok(Self {})
    }
}

impl TyrDrmFileData {
    pub(crate) fn dev_query(
        _ddev: &TyrDrmDevice<Registered>,
        reg_data: &TyrDrmRegistrationData<'_>,
        devquery: &mut uapi::drm_panthor_dev_query,
        _file: &TyrDrmFile,
    ) -> Result<u32> {
        if devquery.pointer == 0 {
            match devquery.type_ {
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_GPU_INFO => {
                    devquery.size = core::mem::size_of_val(&reg_data.gpu_info) as u32;
                    Ok(0)
                }
                _ => Err(EINVAL),
            }
        } else {
            match devquery.type_ {
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_GPU_INFO => {
                    set_uobj(
                        devquery.pointer,
                        devquery.size,
                        reg_data.gpu_info.min_size(),
                        &reg_data.gpu_info,
                    )?;
                    Ok(0)
                }
                _ => Err(EINVAL),
            }
        }
    }
}
