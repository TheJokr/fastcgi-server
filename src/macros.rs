/// Constructs an event at the trace level if `trace-more` is enabled.
#[cfg(feature = "trace-more")]
macro_rules! trace {
    ($($arg:tt)+) => (::tracing::trace!($($arg)+));
}
/// Constructs an event at the trace level if `trace-more` is enabled.
#[cfg(not(feature = "trace-more"))]
macro_rules! trace {
    ($($arg:tt)+) => {};
}
pub(crate) use trace;
