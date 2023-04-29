use std::borrow::{Borrow, Cow};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str;

use compact_str::CompactString;

mod intern;

pub use intern::StaticVarName;
pub use StaticVarName::*;


/// A string wrapper for CGI/1.1 variable names, as used in FastCGI.
///
/// CGI/1.1 specifies variable names as case-insensitive (RFC 3875,
/// Section 4.1), hence this wrapper provides case-insensitive equality,
/// ordering, and hashing implementations for its wrapped string. The string
/// itself is not modified.
#[derive(Debug, ref_cast::RefCastCustom)]
#[repr(transparent)]
pub struct VarName(str);

impl VarName {
    /// Wraps a string reference in a [`VarName`].
    ///
    /// Other conversions from string-like types are available as traits:
    /// [`VarName`] implements [`From<&T>`] for any `T: AsRef<str>`. This
    /// includes [`StaticVarName`].
    #[ref_cast::ref_cast_custom]
    // Unsafe code is generated and checked by ref-cast
    #[allow(unsafe_code, clippy::let_underscore_untyped)]
    #[must_use]
    pub const fn new(s: &str) -> &Self;

    /// Creates an iterator over the normalized bytes of the [`VarName`].
    #[inline]
    fn norm_iter(&self) -> impl Iterator<Item = u8> + '_ {
        self.0.as_bytes().iter().map(u8::to_ascii_uppercase)
    }
}

impl<'a, T: AsRef<str> + ?Sized> From<&'a T> for &'a VarName {
    #[inline]
    fn from(v: &'a T) -> Self {
        VarName::new(v.as_ref())
    }
}

impl From<StaticVarName> for &VarName {
    #[inline]
    fn from(v: StaticVarName) -> Self {
        VarName::new(v.into())
    }
}

impl<'a> From<&'a VarName> for &'a str {
    #[inline]
    fn from(v: &'a VarName) -> Self {
        &v.0
    }
}

impl fmt::Display for VarName {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl PartialEq for VarName {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}
impl Eq for VarName {}

impl PartialOrd for VarName {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VarName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.norm_iter().cmp(other.norm_iter())
    }
}

impl Hash for VarName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.norm_iter() {
            state.write_u8(byte);
        }
        // Ensure prefix-freeness
        state.write_u8(0xff);
    }
}


// Most variable names are shorter than CompactString's inline buffer,
// so we can avoid allocations with it. Niche optimization makes this
// only 8 bytes larger than a Box<str>!
#[derive(Clone)]
enum VarNameInner {
    Static(StaticVarName),
    Custom(CompactString),
}

/// An owned variant of [`VarName`] for use in data structures.
///
/// There are two internal representations. Well-known CGI/1.1 variable
/// and HTTP header names are stored as a [`StaticVarName`] variant. Any
/// name not matching one of these static values is stored as an actual
/// string. Short strings (<=3*pointer size) are inlined into [`OwnedVarName`],
/// longer strings are heap-allocated.
#[derive(Clone)]
#[repr(transparent)]
pub struct OwnedVarName(VarNameInner);

impl OwnedVarName {
    /// Copies the input string into an [`OwnedVarName`] while potentially
    /// modifying it in the process.
    ///
    /// By modifying the input in-place, we can normalize it to the format defined
    /// in the CGI/1.1 specification without allocating. This allows the
    /// [`StaticVarName`] parser to replace strings more often. The function is
    /// particularly useful if the input is discarded afterwards anyway.
    pub fn from_mut_str(name: &mut str) -> Self {
        name.make_ascii_uppercase();
        (&*name).into()
    }

    // Internal alias because self.borrow() can't infer type
    #[inline]
    fn as_var(&self) -> &VarName {
        self.borrow()
    }
}

impl From<StaticVarName> for OwnedVarName {
    #[inline]
    fn from(v: StaticVarName) -> Self {
        Self(VarNameInner::Static(v))
    }
}

impl From<&str> for OwnedVarName {
    fn from(v: &str) -> Self {
        Self(match v.parse() {
            Ok(s) => VarNameInner::Static(s),
            Err(_) => VarNameInner::Custom(v.into()),
        })
    }
}

impl From<&VarName> for OwnedVarName {
    #[inline]
    fn from(v: &VarName) -> Self {
        v.0.into()
    }
}

impl From<String> for OwnedVarName {
    /// Converts a [`String`] into an [`OwnedVarName`], normalizing its contents
    /// in the process.
    fn from(mut v: String) -> Self {
        v.make_ascii_uppercase();
        // CompactString can reuse String's allocation here
        // if we don't use v.as_str().into()
        Self(match v.parse() {
            Ok(s) => VarNameInner::Static(s),
            Err(_) => VarNameInner::Custom(v.into()),
        })
    }
}

impl From<Box<str>> for OwnedVarName {
    /// Converts a [`Box<str>`] into an [`OwnedVarName`], normalizing its contents
    /// in the process.
    #[inline]
    fn from(v: Box<str>) -> Self {
        v.into_string().into()
    }
}

impl<'a> From<Cow<'a, str>> for OwnedVarName {
    /// Converts a [`Cow<'a, str>`] into an [`OwnedVarName`], normalizing its
    /// contents if `Cow` is owned.
    #[inline]
    fn from(v: Cow<'a, str>) -> Self {
        match v {
            Cow::Borrowed(b) => b.into(),
            Cow::Owned(o) => o.into(),
        }
    }
}


impl AsRef<str> for OwnedVarName {
    #[inline]
    fn as_ref(&self) -> &str {
        match &self.0 {
            VarNameInner::Static(s) => s.as_ref(),
            VarNameInner::Custom(s) => s.as_ref(),
        }
    }
}

impl Borrow<VarName> for OwnedVarName {
    #[inline]
    fn borrow(&self) -> &VarName {
        self.as_ref().into()
    }
}

impl ToOwned for VarName {
    type Owned = OwnedVarName;

    #[inline]
    fn to_owned(&self) -> Self::Owned {
        self.into()
    }
}

impl fmt::Debug for OwnedVarName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "OwnedVarName({:?})", self.as_ref())
    }
}

impl fmt::Display for OwnedVarName {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.as_ref(), f)
    }
}

impl PartialEq for OwnedVarName {
    fn eq(&self, other: &Self) -> bool {
        use VarNameInner::*;
        if let (&Static(s1), &Static(s2)) = (&self.0, &other.0) {
            return s1 == s2;
        }
        self.as_var() == other.as_var()
    }
}
impl Eq for OwnedVarName {}

impl PartialOrd for OwnedVarName {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OwnedVarName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use VarNameInner::*;
        if let (&Static(s1), &Static(s2)) = (&self.0, &other.0) {
            return s1.cmp(&s2);
        }
        self.as_var().cmp(other.as_var())
    }
}

impl Hash for OwnedVarName {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_var().hash(state);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_check() {
        use std::mem::size_of;
        assert_eq!(size_of::<OwnedVarName>(), size_of::<CompactString>());
    }
}
