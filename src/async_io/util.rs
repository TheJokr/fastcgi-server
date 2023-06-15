use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use futures_util::lock::{Mutex, OwnedMutexGuard, OwnedMutexLockFuture};


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
