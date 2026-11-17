// SPDX-License-Identifier: GPL-2.0

//! A condition variable.
//!
//! This module allows Rust code to use the kernel's [`struct wait_queue_head`] as a condition
//! variable.

use super::{
    lock::Backend,
    lock::Guard,
    LockClassKey,
    WaitQueue, //
};

use crate::{
    prelude::*,
    str::CStr,
    task::{
        self,
        TASK_FREEZABLE,
        TASK_INTERRUPTIBLE,
        TASK_UNINTERRUPTIBLE, //
    },
    time::{
        Delta,
        Jiffy, //
    },
};

use core::pin::Pin;

/// Creates a [`CondVar`] initialiser with the given name and a newly-created lock class.
#[macro_export]
macro_rules! new_condvar {
    ($($name:literal)?) => {
        $crate::sync::CondVar::new($crate::optional_name!($($name)?), $crate::static_lock_class!())
    };
}
pub use new_condvar;

/// A conditional variable.
///
/// Exposes the kernel's [`struct wait_queue_head`] as a condition variable. It allows the caller to
/// atomically release the given lock and go to sleep. It reacquires the lock when it wakes up. And
/// it wakes up when notified by another thread (via [`CondVar::notify_one`] or
/// [`CondVar::notify_all`]) or because the thread received a signal. It may also wake up
/// spuriously.
///
/// Instances of [`CondVar`] need a lock class and to be pinned. The recommended way to create such
/// instances is with the [`pin_init`](pin_init::pin_init!) and [`new_condvar`] macros.
///
/// # Examples
///
/// The following is an example of using a condvar with a mutex:
///
/// ```
/// use kernel::sync::{new_condvar, new_mutex, CondVar, Mutex};
///
/// #[pin_data]
/// pub struct Example {
///     #[pin]
///     value: Mutex<u32>,
///
///     #[pin]
///     value_changed: CondVar,
/// }
///
/// /// Waits for `e.value` to become `v`.
/// fn wait_for_value(e: &Example, v: u32) {
///     let mut guard = e.value.lock();
///     while *guard != v {
///         e.value_changed.wait(&mut guard);
///     }
/// }
///
/// /// Increments `e.value` and notifies all potential waiters.
/// fn increment(e: &Example) {
///     *e.value.lock() += 1;
///     e.value_changed.notify_all();
/// }
///
/// /// Allocates a new boxed `Example`.
/// fn new_example() -> Result<Pin<KBox<Example>>> {
///     KBox::pin_init(pin_init!(Example {
///         value <- new_mutex!(0),
///         value_changed <- new_condvar!(),
///     }), GFP_KERNEL)
/// }
/// ```
///
/// [`struct wait_queue_head`]: srctree/include/linux/wait.h
#[pin_data]
pub struct CondVar {
    #[pin]
    pub(crate) wq: WaitQueue,
}

impl CondVar {
    /// Constructs a new condvar initialiser.
    pub fn new(name: &'static CStr, key: Pin<&'static LockClassKey>) -> impl PinInit<Self> {
        pin_init!(Self {
            wq <- WaitQueue::new(name, key),
        })
    }

    fn wait_internal<T: ?Sized, B: Backend>(
        &self,
        wait_state: c_int,
        guard: &mut Guard<'_, T, B>,
        timeout: Delta<Jiffy>,
    ) -> Delta<Jiffy> {
        self.wq.wait_once_exclusive(wait_state, || {
            guard.do_unlocked(|| task::schedule_timeout(timeout))
        })
    }

    /// Releases the lock and waits for a notification in uninterruptible mode.
    ///
    /// Atomically releases the given lock (whose ownership is proven by the guard) and puts the
    /// thread to sleep, reacquiring the lock on wake up. It wakes up when notified by
    /// [`CondVar::notify_one`] or [`CondVar::notify_all`]. Note that it may also wake up
    /// spuriously.
    pub fn wait<T: ?Sized, B: Backend>(&self, guard: &mut Guard<'_, T, B>) {
        self.wait_internal(
            TASK_UNINTERRUPTIBLE,
            guard,
            Delta::from_jiffies(task::MAX_SCHEDULE_TIMEOUT),
        );
    }

    /// Releases the lock and waits for a notification in interruptible mode.
    ///
    /// Similar to [`CondVar::wait`], except that the wait is interruptible. That is, the thread may
    /// wake up due to signals. It may also wake up spuriously.
    ///
    /// Returns whether there is a signal pending.
    #[must_use = "wait_interruptible returns if a signal is pending, so the caller must check the return value"]
    pub fn wait_interruptible<T: ?Sized, B: Backend>(&self, guard: &mut Guard<'_, T, B>) -> bool {
        self.wait_internal(
            TASK_INTERRUPTIBLE,
            guard,
            Delta::from_jiffies(task::MAX_SCHEDULE_TIMEOUT),
        );
        crate::current!().signal_pending()
    }

    /// Releases the lock and waits for a notification in interruptible and freezable mode.
    ///
    /// The process is allowed to be frozen during this sleep. No lock should be held when calling
    /// this function, and there is a lockdep assertion for this. Freezing a task that holds a lock
    /// can trivially deadlock vs another task that needs that lock to complete before it too can
    /// hit freezable.
    #[must_use = "wait_interruptible_freezable returns if a signal is pending, so the caller must check the return value"]
    pub fn wait_interruptible_freezable<T: ?Sized, B: Backend>(
        &self,
        guard: &mut Guard<'_, T, B>,
    ) -> bool {
        self.wait_internal(
            TASK_INTERRUPTIBLE | TASK_FREEZABLE,
            guard,
            Delta::from_jiffies(task::MAX_SCHEDULE_TIMEOUT),
        );
        crate::current!().signal_pending()
    }

    /// Releases the lock and waits for a notification in interruptible mode.
    ///
    /// Atomically releases the given lock (whose ownership is proven by the guard) and puts the
    /// thread to sleep. It wakes up when notified by [`CondVar::notify_one`] or
    /// [`CondVar::notify_all`], or when a timeout occurs, or when the thread receives a signal.
    ///
    /// A negative timeout is treated as zero.
    #[must_use = "wait_interruptible_timeout returns if a signal is pending, so the caller must check the return value"]
    pub fn wait_interruptible_timeout<T: ?Sized, B: Backend>(
        &self,
        guard: &mut Guard<'_, T, B>,
        timeout: Delta<Jiffy>,
    ) -> CondVarTimeoutResult {
        let remaining = self.wait_internal(TASK_INTERRUPTIBLE, guard, timeout);

        match (remaining, current!().signal_pending()) {
            (remainder, true) => CondVarTimeoutResult::Signal { remainder },
            (Delta::ZERO, false) => CondVarTimeoutResult::Timeout,
            (remainder, false) => CondVarTimeoutResult::Woken { remainder },
        }
    }

    /// Calls the kernel function to notify one thread synchronously.
    ///
    /// This method behaves like `notify_one`, except that it hints to the scheduler that the
    /// current thread expects to sleep soon.
    #[inline]
    pub fn notify_sync(&self) {
        self.wq.wake_up_sync();
    }

    /// Wakes a single waiter up, if any.
    ///
    /// This is not 'sticky' in the sense that if no thread is waiting, the notification is lost
    /// completely (as opposed to automatically waking up the next waiter).
    #[inline]
    pub fn notify_one(&self) {
        self.wq.wake_up();
    }

    /// Wakes all waiters up, if any.
    ///
    /// This is not 'sticky' in the sense that if no thread is waiting, the notification is lost
    /// completely (as opposed to automatically waking up the next waiter).
    #[inline]
    pub fn notify_all(&self) {
        self.wq.wake_up_all();
    }
}

/// The return type of `wait_timeout`.
pub enum CondVarTimeoutResult {
    /// The timeout was reached.
    Timeout,
    /// Somebody woke us up.
    Woken {
        /// Remaining sleep duration.
        remainder: Delta<Jiffy>,
    },
    /// A signal occurred.
    Signal {
        /// Remaining sleep duration.
        remainder: Delta<Jiffy>,
    },
}
