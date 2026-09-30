// SPDX-License-Identifier: GPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

//! GPU interrupt support.
//!
//! GIN, the GPU Interrupt and Notification unit, is the GPU's interrupt controller. It latches
//! every interrupt source in a two-level register tree and delivers the tree to the CPU as a
//! message-signaled PCI interrupt.
//!
//! See `Documentation/gpu/nova/core/interrupts.rst`.

mod interrupt_tree;
mod regs;
