// SPDX-License-Identifier: GPL-2.0

use kernel::{
    bits,
    io::register,
    num::Bounded, //
};

use crate::driver::NovaRegisters;
use pin_init::Zeroable;

/// Field value for the NSEC field (31:5) of the `_0` registers: `nsec[31:5]`.
///
/// The GPU timer counts nanoseconds with 32 ns granularity, so `nsec[4:0]` is dropped.
fn nsec_lo(nsec: u64) -> Bounded<u32, 27> {
    // CAST: take the lowest 32-bits of nsec
    Bounded::<u32, 32>::from(nsec as u32).shr::<5, _>()
}

/// Field value for the NSEC field (28:0) of the `_1` registers: `nsec[60:32]`.
///
/// The GPU timer is 61 bits wide, so `nsec[63:61]` is not representable and is
/// truncated - the same bits the hardware discards on a raw register write.
fn nsec_hi(nsec: u64) -> Bounded<u32, 29> {
    // CAST: shift 64-bits down by 32-bits and take only those 32-bits
    Bounded::<u32, 29>::from_expr((nsec >> 32) as u32 & bits::genmask_u32(0..=28))
}

// PTIMER

register! {
    base: NovaRegisters;

    pub(super) NV_PTIMER_TIME_PRIV_LEVEL_MASK(u32) @ 0x00009430 {
        4:4 level0 => bool;
    }

    pub(super) NV_PTIMER_TIME_0(u32) @ 0x00009400 {
        31:5 nsec;
    }

    pub(super) NV_PTIMER_TIME_1(u32) @ 0x00009410 {
        28:0 nsec;
    }
}

impl NV_PTIMER_TIME_0 {
    pub(super) fn from_nsec(nsec: u64) -> Self {
        Self::zeroed().with_nsec(nsec_lo(nsec))
    }
}

impl NV_PTIMER_TIME_1 {
    pub(super) fn from_nsec(nsec: u64) -> Self {
        Self::zeroed().with_nsec(nsec_hi(nsec))
    }
}

pub(super) mod gh100 {
    use kernel::io::register;

    use super::{
        nsec_hi,
        nsec_lo, //
    };
    use crate::driver::NovaRegisters;
    use pin_init::Zeroable;

    // PGC6/TIMER
    register! {
        base: NovaRegisters;

        pub(in crate::timer) NV_PGC6_SCI_SEC_TIMER_TIME_0(u32) @ 0x00118f54 {
            31:5 nsec;
        }

        pub(in crate::timer) NV_PGC6_SCI_SEC_TIMER_TIME_1(u32) @ 0x00118f58 {
            28:0 nsec;
        }

        pub(in crate::timer) NV_PGC6_SCI_SYS_TIMER_OFFSET_0(u32) @ 0x00118df4 {
            0:0 update;
            31:5 nsec;
        }

        pub(in crate::timer) NV_PGC6_SCI_SYS_TIMER_OFFSET_1(u32) @ 0x00118df8 {
            28:0 nsec;
        }

    }

    impl NV_PGC6_SCI_SYS_TIMER_OFFSET_0 {
        pub(in crate::timer) fn from_nsec(nsec: u64) -> Self {
            Self::zeroed().with_nsec(nsec_lo(nsec))
        }
    }

    impl NV_PGC6_SCI_SYS_TIMER_OFFSET_1 {
        pub(in crate::timer) fn from_nsec(nsec: u64) -> Self {
            Self::zeroed().with_nsec(nsec_hi(nsec))
        }
    }
}
