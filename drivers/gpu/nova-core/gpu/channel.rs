// SPDX-License-Identifier: GPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

//! Channel ID allocation.

use core::{
    num::NonZero,
    ops::{
        Deref,
        Range, //
    }, //
};

use kernel::{
    id_pool::IdPool,
    prelude::*,
    ptr::Alignment,
    sync::{
        new_mutex,
        Mutex, //
    }, //
};

/// Pool for tracking reservations of channel IDs.
#[pin_data]
pub(crate) struct ChannelIdPool {
    #[pin]
    inner: Mutex<IdPool>,
}

impl ChannelIdPool {
    /// Creates a pool managing `num_chids` channel IDs.
    pub(crate) fn new(num_chids: NonZero<usize>) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            inner <- new_mutex!(IdPool::with_capacity(num_chids.get(), GFP_KERNEL)?),
        })
    }

    /// Reserves a contiguous area of `count` channel IDs starting at a multiple of `align`,
    /// returning a guard that releases the area on drop.
    pub(crate) fn reserve_ids(
        &self,
        count: NonZero<usize>,
        align: Alignment,
    ) -> Result<ChannelIdReservation<'_>> {
        let mut ids = self.inner.lock();
        let range = ids.reserve_ids(0, count, align).ok_or(ENOSPC)?;
        Ok(ChannelIdReservation { pool: self, range })
    }
}

/// A reserved contiguous area of channel IDs.
///
/// Releases the whole area back to its [`ChannelIdPool`] when dropped. Releasing locks a
/// sleeping [`Mutex`], so the area must be dropped in a context that is allowed to sleep.
#[must_use = "the channel ID reservation is released immediately when unused"]
pub(crate) struct ChannelIdReservation<'a> {
    pool: &'a ChannelIdPool,
    range: Range<usize>,
}

impl Drop for ChannelIdReservation<'_> {
    fn drop(&mut self) {
        self.pool.inner.lock().release_ids(&self.range);
    }
}

impl Deref for ChannelIdReservation<'_> {
    type Target = Range<usize>;

    fn deref(&self) -> &Self::Target {
        &self.range
    }
}

#[kunit_tests(nova_core_channel)]
mod tests {
    use super::*;
    use kernel::sizes::SizeConstants;

    #[test]
    fn chid_reservation() -> Result {
        let pool = KBox::pin_init(ChannelIdPool::new(cv!(2048)), GFP_KERNEL)?;

        let first = pool.reserve_ids(cv!(48), Alignment::SZ_1)?;
        assert_eq!(0..48, *first);

        let second = pool.reserve_ids(cv!(48), Alignment::SZ_1)?;
        assert_eq!(48..96, *second);

        drop(first);
        assert_eq!(0..48, *pool.reserve_ids(cv!(48), Alignment::SZ_1)?);
        Ok(())
    }

    #[test]
    fn chid_reservation_drop() -> Result {
        let pool = KBox::pin_init(ChannelIdPool::new(cv!(8)), GFP_KERNEL)?;

        let a = pool.reserve_ids(cv!(3), Alignment::SZ_1)?;
        let b = pool.reserve_ids(cv!(3), Alignment::SZ_1)?;
        let c = pool.reserve_ids(cv!(2), Alignment::SZ_1)?;
        assert_eq!(0..3, *a);
        assert_eq!(3..6, *b);
        assert_eq!(6..8, *c);

        drop(b);

        // Only have space for 3 IDs right now.
        assert_eq!(
            Err(ENOSPC),
            pool.reserve_ids(cv!(4), Alignment::SZ_1).map(|_| ())
        );
        let b = pool.reserve_ids(cv!(3), Alignment::SZ_1)?;
        assert_eq!(3..6, *b);

        drop(a);
        drop(c);
        drop(b);

        // Everything was dropped so the pool should be empty.
        assert_eq!(0..8, *pool.reserve_ids(cv!(8), Alignment::SZ_1)?);
        Ok(())
    }

    #[test]
    fn chid_bounded_by_num_chids() -> Result {
        let pool = KBox::pin_init(ChannelIdPool::new(cv!(4)), GFP_KERNEL)?;

        {
            let a = pool.reserve_ids(cv!(1), Alignment::SZ_1)?;
            let b = pool.reserve_ids(cv!(1), Alignment::SZ_1)?;
            let c = pool.reserve_ids(cv!(1), Alignment::SZ_1)?;
            let d = pool.reserve_ids(cv!(1), Alignment::SZ_1)?;
            assert_eq!(0..1, *a);
            assert_eq!(1..2, *b);
            assert_eq!(2..3, *c);
            assert_eq!(3..4, *d);
            assert_eq!(
                Err(ENOSPC),
                pool.reserve_ids(cv!(1), Alignment::SZ_1).map(|_| ())
            );
        }

        assert_eq!(0..4, *pool.reserve_ids(cv!(4), Alignment::SZ_1)?);
        assert_eq!(
            Err(ENOSPC),
            pool.reserve_ids(cv!(5), Alignment::SZ_1).map(|_| ())
        );

        let head = pool.reserve_ids(cv!(3), Alignment::SZ_1)?;
        assert_eq!(0..3, *head);
        assert_eq!(
            Err(ENOSPC),
            pool.reserve_ids(cv!(2), Alignment::SZ_1).map(|_| ())
        );
        assert_eq!(3..4, *pool.reserve_ids(cv!(1), Alignment::SZ_1)?);
        Ok(())
    }

    #[test]
    fn chid_reservation_aligned() -> Result {
        let pool = KBox::pin_init(ChannelIdPool::new(cv!(16)), GFP_KERNEL)?;

        // Alloc 0 so the first fit for the next area is unaligned.
        let pad = pool.reserve_ids(cv!(1), Alignment::SZ_1)?;
        assert_eq!(0..1, *pad);

        let a = pool.reserve_ids(cv!(4), Alignment::SZ_4)?;
        assert_eq!(4..8, *a);

        // The area skipped over by the aligned allocation should still be available.
        let b = pool.reserve_ids(cv!(1), Alignment::SZ_1)?;
        assert_eq!(1..2, *b);

        let c = pool.reserve_ids(cv!(8), Alignment::SZ_8)?;
        assert_eq!(8..16, *c);

        // Only 2 IDs left.
        assert_eq!(
            Err(ENOSPC),
            pool.reserve_ids(cv!(4), Alignment::SZ_4).map(|_| ())
        );
        assert_eq!(
            Err(ENOSPC),
            pool.reserve_ids(cv!(1), Alignment::SZ_32).map(|_| ())
        );

        assert_eq!(2..4, *pool.reserve_ids(cv!(2), Alignment::SZ_1)?);
        Ok(())
    }
}
