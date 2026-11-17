// SPDX-License-Identifier: GPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

//! Wait queue.
//!
//! C header: [`include/linux/wait.h`](srctree/include/linux/wait.h)

use super::LockClassKey;
use crate::{
    prelude::*,
    str::CStr,
    task,
    time::{
        Delta,
        Jiffy, //
    },
    types::Opaque, //
};

use core::{
    pin::Pin,
    ptr, //
};

/// Creates a [`WaitQueue`] initialiser with the given name and a newly-created lock class.
#[macro_export]
macro_rules! new_waitqueue {
    ($($name:literal)?) => {
        $crate::sync::WaitQueue::new(
            $crate::optional_name!($($name)?),
            $crate::static_lock_class!(),
        )
    };
}
pub use new_waitqueue;

/// A wait queue for sleeping until a condition becomes true.
///
/// Exposes the kernel's [`struct wait_queue_head`] as a Rust wait queue.
///
/// A `WaitQueue` allows a thread to sleep until a caller-supplied condition becomes true,
/// re-checking the condition on each wake-up. This matches the C `wait_event()` family of macros.
///
/// For waiting with a lock guard (the condition variable pattern), use [`CondVar`](super::CondVar)
/// instead.
///
/// Instances of `WaitQueue` need a lock class and to be pinned. The recommended way to create such
/// instances is with the [`pin_init!`] and [`new_waitqueue!`] macros.
///
/// # Examples
///
/// ```
/// use kernel::sync::{
///     atomic::{
///         Atomic,
///         Relaxed,
///     },
///     new_waitqueue,
///     WaitQueue,
/// };
///
/// #[pin_data]
/// pub struct Example {
///     value: Atomic<i32>,
///     #[pin]
///     queue: WaitQueue,
/// }
///
/// fn wait_for_value(e: &Example, v: i32) {
///     e.queue.wait_event(|| e.value.load(Relaxed) == v);
/// }
///
/// fn set_value(e: &Example, v: i32) {
///     e.value.store(v, Relaxed);
///     e.queue.wake_up();
/// }
/// ```
///
/// [`struct wait_queue_head`]: srctree/include/linux/wait.h
#[pin_data]
pub struct WaitQueue {
    #[pin]
    wait_queue_head: Opaque<bindings::wait_queue_head>,
}

// SAFETY: `WaitQueue` only uses a `struct wait_queue_head`, which is safe to use on any thread.
unsafe impl Send for WaitQueue {}

// SAFETY: `WaitQueue` only uses a `struct wait_queue_head`, which is safe to use on multiple
// threads concurrently.
unsafe impl Sync for WaitQueue {}

impl WaitQueue {
    /// Constructs a new wait queue initialiser.
    pub fn new(name: &'static CStr, key: Pin<&'static LockClassKey>) -> impl PinInit<Self> {
        pin_init!(Self {
            // SAFETY: `slot` is valid while the closure is called and both `name` and `key` have
            // static lifetimes so they live indefinitely.
            wait_queue_head <- Opaque::ffi_init(|slot| unsafe {
                bindings::__init_waitqueue_head(slot, name.as_char_ptr(), key.as_ptr())
            }),
        })
    }

    /// Returns a raw pointer to the underlying `wait_queue_head`.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::wait_queue_head {
        self.wait_queue_head.get()
    }

    /// Sleeps until the condition returns `true`.
    ///
    /// The condition is checked before each sleep and after each wake-up. The wait is
    /// uninterruptible.
    #[track_caller]
    #[inline]
    pub fn wait_event<F: FnMut() -> bool>(&self, condition: F) {
        // An uninterruptible wait without a timeout cannot fail.
        let _ = self.wait_event_timeout_internal(
            task::TASK_UNINTERRUPTIBLE,
            condition,
            Delta::from_jiffies(task::MAX_SCHEDULE_TIMEOUT),
        );
    }

    /// Sleeps until the condition returns `true` or a signal is received.
    ///
    /// Returns `Ok(())` when the condition is met, or [`Interrupted`] if interrupted by a signal.
    #[track_caller]
    #[inline]
    pub fn wait_event_interruptible<F: FnMut() -> bool>(
        &self,
        condition: F,
    ) -> Result<(), Interrupted> {
        // Without a timeout, interruption is the only possible error.
        self.wait_event_timeout_internal(
            task::TASK_INTERRUPTIBLE,
            condition,
            Delta::from_jiffies(task::MAX_SCHEDULE_TIMEOUT),
        )
        .map_err(|_| Interrupted)
    }

    /// Sleeps until the condition returns `true` or the timeout expires.
    ///
    /// Returns `Ok(())` when the condition is met, or [`TimedOut`] if the timeout elapsed first.
    /// A negative timeout is treated as zero.
    #[track_caller]
    #[inline]
    pub fn wait_event_timeout<F: FnMut() -> bool>(
        &self,
        condition: F,
        timeout: Delta<Jiffy>,
    ) -> Result<(), TimedOut> {
        // An uninterruptible wait can only fail by timing out.
        self.wait_event_timeout_internal(task::TASK_UNINTERRUPTIBLE, condition, timeout)
            .map_err(|_| TimedOut)
    }

    /// Sleeps until the condition returns `true`, a signal is received, or the timeout expires.
    ///
    /// Returns `Ok(())` when the condition is met, or [`WaitError`] on signal or timeout.
    /// A negative timeout is treated as zero.
    #[track_caller]
    #[inline]
    pub fn wait_event_interruptible_timeout<F: FnMut() -> bool>(
        &self,
        condition: F,
        timeout: Delta<Jiffy>,
    ) -> Result<(), WaitError> {
        self.wait_event_timeout_internal(task::TASK_INTERRUPTIBLE, condition, timeout)
    }

    #[track_caller]
    fn wait_event_timeout_internal<F: FnMut() -> bool>(
        &self,
        wait_state: c_int,
        mut condition: F,
        timeout: Delta<Jiffy>,
    ) -> Result<(), WaitError> {
        task::might_sleep();

        if condition() {
            return Ok(());
        }

        if timeout <= Delta::ZERO {
            return Err(TimedOut.into());
        }

        let wait = Opaque::<bindings::wait_queue_entry>::uninit();

        // SAFETY: `wait` points to valid memory.
        unsafe { bindings::init_wait(wait.get()) };

        let mut remaining = timeout;

        let result = loop {
            // SAFETY: Both pointers are valid, and `wait` was initialised by `init_wait()` above.
            let ret = unsafe {
                bindings::prepare_to_wait_event(self.wait_queue_head.get(), wait.get(), wait_state)
            };

            if condition() {
                break Ok(());
            }

            if ret != 0 {
                break Err(Interrupted.into());
            }

            remaining = task::schedule_timeout(remaining);

            if condition() {
                break Ok(());
            }

            if remaining == Delta::ZERO {
                break Err(TimedOut.into());
            }
        };

        // SAFETY: Both pointers are valid, and `wait` is no longer used after this call.
        unsafe { bindings::finish_wait(self.wait_queue_head.get(), wait.get()) };

        result
    }

    /// Performs a single non-exclusive prepare-to-wait / finish-wait cycle, calling `schedule_fn`
    /// in between. Non-exclusive waiters are all woken by [`wake_up()`](Self::wake_up).
    #[inline]
    #[expect(unused)]
    pub(super) fn wait_once<F, R>(&self, wait_state: c_int, schedule_fn: F) -> R
    where
        F: FnOnce() -> R,
    {
        self.wait_once_internal(wait_state, false, schedule_fn)
    }

    /// Performs a single exclusive prepare-to-wait / finish-wait cycle, calling `schedule_fn`
    /// in between.
    #[inline]
    pub(super) fn wait_once_exclusive<F, R>(&self, wait_state: c_int, schedule_fn: F) -> R
    where
        F: FnOnce() -> R,
    {
        self.wait_once_internal(wait_state, true, schedule_fn)
    }

    fn wait_once_internal<F, R>(&self, wait_state: c_int, exclusive: bool, schedule_fn: F) -> R
    where
        F: FnOnce() -> R,
    {
        let wait = Opaque::<bindings::wait_queue_entry>::uninit();

        // SAFETY: `wait` points to valid memory.
        unsafe { bindings::init_wait(wait.get()) };

        // SAFETY: Both `wait` and `wait_queue_head` point to valid memory.
        unsafe {
            if exclusive {
                bindings::prepare_to_wait_exclusive(
                    self.wait_queue_head.get(),
                    wait.get(),
                    wait_state,
                );
            } else {
                bindings::prepare_to_wait(self.wait_queue_head.get(), wait.get(), wait_state);
            }
        };

        let ret = schedule_fn();

        // SAFETY: Both `wait` and `wait_queue_head` point to valid memory.
        unsafe { bindings::finish_wait(self.wait_queue_head.get(), wait.get()) };

        ret
    }

    /// Wakes up waiters.
    ///
    /// Wakes all non-exclusive waiters and one exclusive waiter, if any.  Matches C's `wake_up()`.
    #[inline]
    pub fn wake_up(&self) {
        // SAFETY: `wait_queue_head` points to valid memory.
        unsafe {
            bindings::__wake_up(
                self.wait_queue_head.get(),
                bindings::TASK_NORMAL,
                1,
                ptr::null_mut(),
            )
        };
    }

    /// Wakes up all waiters.
    ///
    /// Wakes all non-exclusive and all exclusive waiters, if any.
    /// Matches C's `wake_up_all()`.
    #[inline]
    pub fn wake_up_all(&self) {
        // SAFETY: `wait_queue_head` points to valid memory.
        unsafe {
            bindings::__wake_up(
                self.wait_queue_head.get(),
                bindings::TASK_NORMAL,
                0,
                ptr::null_mut(),
            )
        };
    }

    /// Like [`wake_up()`](Self::wake_up), but hints to the scheduler that the current task
    /// expects to sleep soon. Matches C's `wake_up_sync()`.
    #[inline]
    pub fn wake_up_sync(&self) {
        // SAFETY: `wait_queue_head` points to valid memory.
        unsafe { bindings::__wake_up_sync(self.wait_queue_head.get(), bindings::TASK_NORMAL) };
    }

    /// Wakes up all waiters and clears poll registrations.
    ///
    /// Used when a wait queue is about to be freed, to ensure epoll items are properly removed.
    /// Matches C's `wake_up_pollfree()`.
    #[inline]
    pub(super) fn wake_up_pollfree(&self) {
        // SAFETY: `wait_queue_head` points to valid memory.
        unsafe { bindings::__wake_up_pollfree(self.wait_queue_head.get()) };
    }
}

/// A wait was interrupted by a signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interrupted;

/// A wait timed out before its condition was met.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimedOut;

impl From<Interrupted> for Error {
    #[inline]
    fn from(_: Interrupted) -> Error {
        ERESTARTSYS
    }
}

impl From<TimedOut> for Error {
    #[inline]
    fn from(_: TimedOut) -> Error {
        ETIMEDOUT
    }
}

/// Error returned by [`WaitQueue`] wait functions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitError {
    /// Interrupted by a signal.
    Signal,
    /// The timeout elapsed without the condition being met.
    Timeout,
}

impl From<Interrupted> for WaitError {
    #[inline]
    fn from(_: Interrupted) -> Self {
        Self::Signal
    }
}

impl From<TimedOut> for WaitError {
    #[inline]
    fn from(_: TimedOut) -> Self {
        Self::Timeout
    }
}

impl From<WaitError> for Error {
    #[inline]
    fn from(e: WaitError) -> Error {
        match e {
            WaitError::Signal => ERESTARTSYS,
            WaitError::Timeout => ETIMEDOUT,
        }
    }
}

#[cfg(CONFIG_RUST_WAITQUEUE_KUNIT_TEST)]
#[macros::kunit_tests(rust_waitqueue)]
mod tests {
    use super::*;
    use crate::{
        sync::{
            atomic::{
                Atomic,
                Relaxed, //
            },
            Arc,
        },
        time::delay::fsleep,
        workqueue,
    };

    #[pin_data]
    struct State {
        value: Atomic<i32>,
        #[pin]
        wq: WaitQueue,
    }

    impl State {
        fn new() -> Result<Arc<Self>> {
            Arc::pin_init(
                pin_init!(Self {
                    value: Atomic::new(0),
                    wq <- new_waitqueue!(),
                }),
                GFP_KERNEL,
            )
        }
    }

    #[test]
    fn wait_event_from_work() {
        let s = State::new().unwrap();

        let s2 = s.clone();
        workqueue::system_dfl()
            .try_spawn(GFP_KERNEL, move || {
                s2.value.store(1, Relaxed);
                s2.wq.wake_up();
            })
            .unwrap();

        s.wq.wait_event(|| s.value.load(Relaxed) == 1);
        assert_eq!(s.value.load(Relaxed), 1);
    }

    #[test]
    fn wait_event_condition_already_true() {
        let s = State::new().unwrap();
        let mut calls = 0;

        s.wq.wait_event(|| {
            calls += 1;
            true
        });

        assert_eq!(calls, 1);
    }

    #[test]
    fn wait_event_condition_not_yet_met() {
        let s = State::new().unwrap();

        let s2 = s.clone();
        workqueue::system_dfl()
            .try_spawn(GFP_KERNEL, move || {
                s2.value.store(1, Relaxed);
                s2.wq.wake_up_all();

                fsleep(Delta::from_millis(50));

                s2.value.store(2, Relaxed);
                s2.wq.wake_up_all();
            })
            .unwrap();

        s.wq.wait_event(|| s.value.load(Relaxed) == 2);
        assert_eq!(s.value.load(Relaxed), 2);
    }

    #[test]
    fn wait_event_timeout_expires() {
        let s = State::new().unwrap();

        let ret =
            s.wq.wait_event_timeout(|| s.value.load(Relaxed) == 1, Delta::from_jiffies(1));
        assert_eq!(ret, Err(TimedOut));
    }

    #[test]
    fn wait_event_does_not_recheck_success() {
        enum WaitKind {
            Uninterruptible,
            Interruptible,
            Timeout,
            InterruptibleTimeout,
        }

        let s = State::new().unwrap();

        for kind in [
            WaitKind::Uninterruptible,
            WaitKind::Interruptible,
            WaitKind::Timeout,
            WaitKind::InterruptibleTimeout,
        ] {
            let mut calls = 0;
            let condition = || {
                // Bypass the initial fast path to exercise the wait loop.
                calls += 1;
                calls > 1
            };

            let ret = match kind {
                WaitKind::Uninterruptible => {
                    s.wq.wait_event(condition);
                    Ok(())
                }
                WaitKind::Interruptible => {
                    s.wq.wait_event_interruptible(condition).map_err(Into::into)
                }
                WaitKind::Timeout => {
                    s.wq.wait_event_timeout(condition, Delta::from_jiffies(1))
                        .map_err(Into::into)
                }
                WaitKind::InterruptibleTimeout => {
                    s.wq.wait_event_interruptible_timeout(condition, Delta::from_jiffies(1))
                }
            };

            assert_eq!(ret, Ok(()));
            assert_eq!(calls, 2);
        }
    }

    #[test]
    fn wait_event_zero_timeout() {
        let s = State::new().unwrap();

        for interruptible in [false, true] {
            let mut calls = 0;
            let condition = || {
                calls += 1;
                false
            };

            let ret = if interruptible {
                s.wq.wait_event_interruptible_timeout(condition, Delta::ZERO)
            } else {
                s.wq.wait_event_timeout(condition, Delta::ZERO)
                    .map_err(Into::into)
            };

            assert_eq!(ret, Err(WaitError::Timeout));
            assert_eq!(calls, 1);
        }
    }
}
