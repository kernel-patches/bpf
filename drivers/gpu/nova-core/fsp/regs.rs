// SPDX-License-Identifier: GPL-2.0

use kernel::io::register;

use crate::driver::NovaRegisters;

register! {
    base: NovaRegisters;

    pub(super) NV_PFSP_FALCON_COMMON_SCRATCH_GROUP_3(u32)[4] @ 0x008f0330 {
        31:0 val;
    }

    /// FSP ucode version
    pub(super) NV_GFW_FSP_UCODE_VERSION(u32) => NV_PFSP_FALCON_COMMON_SCRATCH_GROUP_3[1] {
        11:0 full;
    }
}

impl NV_GFW_FSP_UCODE_VERSION {
    /// OpenRM kfspRequiresBug3957833WAR_HAL:
    /// returns `true` if the FSP ucode predates the fix for
    /// bug 3957833 and hence the sys timer offset must not be programmed.
    /// Can only be true on GH100 with older FSP.
    pub(super) fn is_bug_3957833_affected(self) -> bool {
        /// FSP ucode version from which on the fix for bug 3957833 is included.
        const FSP_BUG_3957833_FIX_VERSION: u32 = 0x44c;

        self.full() < FSP_BUG_3957833_FIX_VERSION
    }
}
