use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{ready, Context, Poll};

use futures_util::lock::{Mutex, OwnedMutexGuard, OwnedMutexLockFuture};
use futures_util::task::AtomicWaker;


/// A pseudo-future which locks a [`Mutex<T>`] and can be polled repeatedly.
#[derive(Debug)]
#[must_use = "futures are lazy and do nothing unless polled"]
pub(crate) enum RepeatableLockFuture<T: ?Sized> {
    /// The underlying future is still pending and must be polled.
    Poll(OwnedMutexLockFuture<T>),
    /// The underlying future resolved.
    Done(OwnedMutexGuard<T>),
}

impl<T: ?Sized> RepeatableLockFuture<T> {
    /// Returns a new [`RepeatableLockFuture`] to lock `mutex`.
    pub(crate) fn new(mutex: Arc<Mutex<T>>) -> Self {
        Self::Poll(mutex.lock_owned())
    }

    /// Drives the underlying future to completion, eventually returning a
    /// reference to the locked data.
    ///
    /// [`RepeatableLockFuture`] cannot implement [`std::future::Future`]
    /// directly as its output is a derived reference.
    pub(crate) fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<&mut T> {
        let this = self.get_mut();
        if let Self::Poll(fut) = this {
            let g = ready!(Pin::new(fut).poll(cx));
            *this = Self::Done(g);
        }
        match this {
            Self::Done(g) => Poll::Ready(&mut *g),
            Self::Poll(_) => unreachable!("RepeatableLockFuture should always be Done here"),
        }
    }
}


// Adapted from https://github.com/laizy/waitgroup-rs
#[derive(Default)]
struct WaitGroupInner {
    /// The task to wake when the last TaskToken is dropped.
    waker: AtomicWaker,
}

impl Drop for WaitGroupInner {
    #[inline]
    fn drop(&mut self) {
        self.waker.wake();
    }
}

/// A token to track the number of active tasks in a [`WaitGroup`].
///
/// Cloning an existing [`TaskToken`] is equivalent to `WaitGroup::add_task`.
#[derive(Clone)]
#[must_use = "TaskToken must be kept alive until the end of the task"]
pub(crate) struct TaskToken(Arc<WaitGroupInner>);

/// A future that waits for all tasks in a [`WaitGroup`] to finish.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct WaitGroupFuture(Weak<WaitGroupInner>);
impl Future for WaitGroupFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        // Weak::upgrade returns None iff all TaskTokens have been dropped
        match self.0.upgrade() {
            None => Poll::Ready(()),
            Some(wg) => {
                wg.waker.register(cx.waker());
                Poll::Pending
            },
        }
    }
}


/// An efficient structure to await the completion of a group of tasks.
#[derive(Default)]
pub(crate) struct WaitGroup(Arc<WaitGroupInner>);

impl WaitGroup {
    /// Creates a new, empty [`WaitGroup`].
    #[inline]
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Adds a task to the [`WaitGroup`], represented by a [`TaskToken`].
    ///
    /// Dropping the returned [`TaskToken`] marks the task as finished.
    #[inline]
    pub(crate) fn add_task(&self) -> TaskToken {
        TaskToken(self.0.clone())
    }

    /// Returns the number of active tasks.
    #[inline]
    #[must_use]
    pub(crate) fn tasks(&self) -> usize {
        Arc::strong_count(&self.0) - 1
    }
}

impl std::future::IntoFuture for WaitGroup {
    type Output = ();
    type IntoFuture = WaitGroupFuture;

    fn into_future(self) -> Self::IntoFuture {
        WaitGroupFuture(Arc::downgrade(&self.0))
    }
}


impl fmt::Debug for TaskToken {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TaskToken")
    }
}

impl fmt::Debug for WaitGroupFuture {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tasks = self.0.strong_count();
        f.debug_struct("WaitGroupFuture").field("tasks", &tasks).finish()
    }
}

impl fmt::Debug for WaitGroup {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("WaitGroup").field("tasks", &self.tasks()).finish()
    }
}


#[cfg(test)]
mod tests {
    use super::super::tests::CountWaker;
    use super::*;

    #[test]
    fn mutex_lock() {
        let counter = CountWaker::new();
        let waker = counter.clone().into();
        let mut cx = Context::from_waker(&waker);
        let mutex = Arc::new(Mutex::new(()));

        {
            let mut fut = RepeatableLockFuture::new(mutex.clone());
            let mut fut = Pin::new(&mut fut);
            assert!(fut.as_mut().poll(&mut cx).is_ready());
            // Repeated poll should be ok
            assert!(fut.as_mut().poll(&mut cx).is_ready());
        }

        {
            let g = mutex.try_lock_owned().unwrap();
            let mut fut = RepeatableLockFuture::new(mutex);
            let mut fut = Pin::new(&mut fut);
            assert!(fut.as_mut().poll(&mut cx).is_pending());

            // Dropping the guard should wake fut
            std::mem::drop(g);
            assert_eq!(counter.wakes(), 1);
            assert!(fut.as_mut().poll(&mut cx).is_ready());
            assert!(fut.as_mut().poll(&mut cx).is_ready());
        }
    }

    #[test]
    fn waitgroup() {
        use futures_util::FutureExt;
        let counter = CountWaker::new();
        let waker = counter.clone().into();
        let mut cx = Context::from_waker(&waker);

        let wg = WaitGroup::new();
        let mut tasks: Vec<_> = (0..7).map(|_| wg.add_task()).collect();
        assert_eq!(wg.tasks(), 7);
        assert_eq!(format!("{wg:?}"), "WaitGroup { tasks: 7 }");

        tasks.truncate(4);
        assert_eq!(wg.tasks(), 4);
        assert_eq!(format!("{wg:?}"), "WaitGroup { tasks: 4 }");

        let mut fut = std::future::IntoFuture::into_future(wg);
        assert!(fut.poll_unpin(&mut cx).is_pending());
        assert_eq!(format!("{fut:?}"), "WaitGroupFuture { tasks: 4 }");

        // Only the last dropped token should wake fut
        tasks.truncate(1);
        assert_eq!(counter.wakes(), 0);
        tasks.clear();
        assert_eq!(counter.wakes(), 1);
        assert!(fut.poll_unpin(&mut cx).is_ready());
    }
}
