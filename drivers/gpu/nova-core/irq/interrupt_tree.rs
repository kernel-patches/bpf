// SPDX-License-Identifier: GPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

//! Vector addressing in the GIN CPU interrupt tree.
//!
//! A [`GinVector`] names an interrupt source, a [`LeafIndex`] the leaf register that latches it,
//! a [`LeafMask`] a set of vectors within one leaf, and a [`Subtree`] one `TOP` bit. The types
//! keep the four from being confused with one another.
//!
//! See `Documentation/gpu/nova/core/interrupts.rst`.

use kernel::{
    num::Bounded,
    prelude::*, //
};

use crate::num;

use super::regs::*;

/// Number of vectors one leaf register carries, one per bit.
const VECTORS_PER_LEAF: u32 = u32::BITS;

/// Number of leaves one subtree covers.
const LEAVES_PER_SUBTREE: u32 = 2;

/// Number of subtrees the widest supported tree implements.
const MAX_NUM_SUBTREES: u32 = 8;

/// Number of leaves the widest supported tree implements.
const MAX_NUM_LEAVES: u32 = MAX_NUM_SUBTREES * LEAVES_PER_SUBTREE;

/// Number of bits needed to address every vector in the widest supported tree.
const VECTOR_BITS: u32 = (MAX_NUM_LEAVES * VECTORS_PER_LEAF).ilog2();

/// Width of the vector field in the leaf trigger register.
const TRIGGER_VECTOR_BITS: u32 = {
    let range = NV_VIRTUAL_FUNCTION_PRIV_CPU_INTR_LEAF_TRIGGER::VECTOR_RANGE;
    num::u8_as_u32(*range.end() - *range.start() + 1)
};

/// Index of a leaf register within the widest supported tree. An 8-leaf tree implements only the
/// lower half of the range.
pub(super) type LeafIndex = Bounded<usize, { MAX_NUM_LEAVES.ilog2() }>;

/// Number of leaves a tree implements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(super) enum LeafCount {
    /// Turing through Ada.
    Eight = 8,

    /// Hopper and later.
    Sixteen = 16,
}

impl LeafCount {
    pub(super) const fn into_u32(self) -> u32 {
        // CAST: `LeafCount` is `repr(u32)`, so the cast is lossless.
        self as u32
    }

    pub(super) const fn into_raw(self) -> usize {
        num::u32_as_usize(self.into_u32())
    }

    /// Returns the number of subtrees a tree of this size implements.
    pub(super) const fn subtree_count(self) -> u32 {
        self.into_u32() / LEAVES_PER_SUBTREE
    }

    /// Returns the set of every subtree a tree of this size implements.
    pub(super) const fn subtree_set(self) -> SubtreeSet {
        SubtreeSet((1u32 << self.subtree_count()) - 1)
    }

    /// Returns the number of vectors a tree of this size carries.
    pub(super) const fn vector_count(self) -> u32 {
        self.into_u32() * VECTORS_PER_LEAF
    }
}

// `VECTOR_BITS` and `LeafCount::Sixteen` are written separately. This assert keeps them in
// agreement about the widest supported tree.
static_assert!(1 << VECTOR_BITS == LeafCount::Sixteen.vector_count());

/// Set of vectors within one leaf, one bit per vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LeafMask(u32);

impl LeafMask {
    /// Returns the mask with every vector set.
    pub(super) const fn all() -> Self {
        Self(u32::MAX)
    }

    pub(super) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub(super) const fn into_raw(self) -> u32 {
        self.0
    }

    pub(super) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns whether every vector in `other` is also in this mask.
    pub(super) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl From<Bounded<u32, 32>> for LeafMask {
    fn from(vectors: Bounded<u32, 32>) -> Self {
        Self(vectors.get())
    }
}

impl From<LeafMask> for Bounded<u32, 32> {
    fn from(vectors: LeafMask) -> Self {
        vectors.0.into()
    }
}

/// One subtree, held as the `TOP` bit that covers it.
///
/// # Invariants
///
/// Exactly one bit is set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Subtree(u32);

impl Subtree {
    /// Returns the subtree at index `idx`.
    const fn new(idx: u32) -> Self {
        // INVARIANT: shifting `1` left leaves exactly one bit set.
        Self(1 << idx)
    }

    /// Returns this subtree's index within the tree.
    pub(super) const fn index(self) -> u32 {
        self.0.trailing_zeros()
    }

    pub(super) const fn into_raw(self) -> u32 {
        self.0
    }
}

/// Set of subtrees, one bit per subtree, in the layout of the `TOP` registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SubtreeSet(u32);

impl SubtreeSet {
    pub(super) const fn contains(self, subtree: Subtree) -> bool {
        self.0 & subtree.into_raw() != 0
    }

    pub(super) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(super) const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Returns one more than the highest index in this set, or `0` for an empty set. An MSI-X
    /// allocation that covers the set needs this many entries.
    pub(super) const fn span(self) -> u32 {
        u32::BITS - self.0.leading_zeros()
    }

    /// Returns the subtrees of this set, lowest index first.
    #[expect(dead_code)]
    pub(super) fn iter(self) -> impl Iterator<Item = Subtree> {
        (0..u32::BITS)
            .map(Subtree::new)
            .filter(move |subtree| self.contains(*subtree))
    }
}

impl From<Subtree> for SubtreeSet {
    fn from(subtree: Subtree) -> Self {
        Self(subtree.into_raw())
    }
}

impl From<Bounded<u32, 32>> for SubtreeSet {
    fn from(subtrees: Bounded<u32, 32>) -> Self {
        Self(subtrees.get())
    }
}

impl From<SubtreeSet> for Bounded<u32, 32> {
    fn from(subtrees: SubtreeSet) -> Self {
        subtrees.0.into()
    }
}

/// A GIN interrupt vector, bounded to the widest tree that any supported chipset implements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct GinVector(Bounded<u32, VECTOR_BITS>);

impl GinVector {
    /// Returns vector number `VECTOR`.
    ///
    /// Fails to compile if `VECTOR` is beyond the widest supported tree.
    pub(super) const fn new<const VECTOR: u32>() -> Self {
        Self(Bounded::<u32, VECTOR_BITS>::new::<VECTOR>())
    }

    pub(super) const fn into_raw(self) -> u32 {
        self.0.get()
    }

    /// Returns this vector's leaf.
    pub(super) fn leaf_index(self) -> LeafIndex {
        // CALC: `self.0 / VECTORS_PER_LEAF`.
        self.0.shr::<{ VECTORS_PER_LEAF.ilog2() }, _>().cast()
    }

    /// Returns this vector's bit within its leaf.
    pub(super) const fn leaf_mask(self) -> LeafMask {
        LeafMask(1 << (self.0.get() % VECTORS_PER_LEAF))
    }

    /// Returns this vector's subtree.
    pub(super) const fn subtree(self) -> Subtree {
        Subtree::new(self.0.get() / (VECTORS_PER_LEAF * LEAVES_PER_SUBTREE))
    }

    /// Checks that a tree with `leaves` leaves implements this vector.
    ///
    /// # Errors
    ///
    /// `EINVAL` if it does not.
    pub(super) const fn validate(self, leaves: LeafCount) -> Result {
        if self.0.get() >= leaves.vector_count() {
            Err(EINVAL)
        } else {
            Ok(())
        }
    }
}

impl From<GinVector> for Bounded<u32, TRIGGER_VECTOR_BITS> {
    fn from(vector: GinVector) -> Self {
        vector.0.extend()
    }
}
