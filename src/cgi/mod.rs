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
    /// includes [`StaticVarName`] and [`OwnedVarName`].
    #[ref_cast::ref_cast_custom]
    // Unsafe code is generated and checked by ref-cast
    #[allow(unsafe_code, clippy::let_underscore_untyped)]
    #[inline]
    #[must_use]
    pub const fn new(s: &str) -> &Self;
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
        let lhs = self.0.as_bytes().iter().map(u8::to_ascii_uppercase);
        let rhs = other.0.as_bytes().iter().map(u8::to_ascii_uppercase);
        lhs.cmp(rhs)
    }
}

impl Hash for VarName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // 16-byte chunks for SIMD uppercase conversion
        const LANES: usize = 16;
        let mut chunks = self.0.as_bytes().chunks_exact(LANES);

        for c in &mut chunks {
            let mut arr: [u8; LANES] = c.try_into().expect("chunk should be LANES-sized");
            arr.make_ascii_uppercase();
            state.write(&arr);
        }

        let mut arr = [0; LANES];
        let rem = chunks.remainder();
        if !rem.is_empty() {
            arr[..rem.len()].copy_from_slice(rem);
            arr.make_ascii_uppercase();
        }
        // Ensure prefix-freeness
        arr[rem.len()] = 0xff;
        state.write(&arr[..=rem.len()]);
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
/// string. Short strings (<= `3*pointer size`) are inlined into
/// [`OwnedVarName`], longer strings are heap-allocated.
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

    /// Converts a [`CompactString`] into an [`OwnedVarName`], normalizing its
    /// contents in the process.
    #[must_use]
    pub(crate) fn from_compact(mut name: CompactString) -> Self {
        name.make_ascii_uppercase();
        Self(match name.parse() {
            Ok(s) => VarNameInner::Static(s),
            Err(_) => VarNameInner::Custom(name),
        })
    }

    // Internal alias because self.borrow() can't infer type
    #[must_use]
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
    #[inline]
    fn from(v: String) -> Self {
        Self::from_compact(v.into())
    }
}

impl From<Box<str>> for OwnedVarName {
    /// Converts a [`Box<str>`] into an [`OwnedVarName`], normalizing its contents
    /// in the process.
    #[inline]
    fn from(v: Box<str>) -> Self {
        Self::from_compact(v.into())
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

#[cfg(feature = "http")]
impl From<http::header::HeaderName> for OwnedVarName {
    /// Converts an [`http::HeaderName`] into an [`OwnedVarName`] by mapping
    /// the header to its CGI/1.1 representation.
    fn from(v: http::header::HeaderName) -> Self {
        let mut var = CompactString::new_inline("HTTP_");
        var.push_str(v.as_str());
        Self::from_compact(var)
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
    use std::collections::hash_map::DefaultHasher;
    use std::iter::repeat_with;
    use strum::IntoEnumIterator;
    use super::*;

    #[test]
    fn size_check() {
        use std::mem::size_of;
        assert_eq!(size_of::<OwnedVarName>(), size_of::<CompactString>());
    }

    fn rand_name() -> String {
        let len = fastrand::usize(5..=35);
        // Non-whitespace printable ASCII characters
        repeat_with(|| fastrand::u8(33..127) as char).take(len).collect()
    }

    const MIXED_REF: &[(StaticVarName, &str)] = &[
        (CONTENT_LENGTH, "CONTENT_LENGTH"),
        (REQUEST_METHOD, "request_method"),
        (DOCUMENT_ROOT, "doCUMeNt_RooT"),
        (HTTPS, "Https"),
        (HTTP_CACHE_CONTROL, "http_CACHE_control"),
        (HTTP_USER_AGENT, "HTTP_USER_AGENT"),
        (HTTP_X_REQUEST_ID, "HTTP_x_reQUeSt_id"),
    ];

    #[test]
    fn static_eq() {
        let mut static_vars: Vec<_> = StaticVarName::iter().map(OwnedVarName::from).collect();
        for stat in &static_vars {
            let cmp = stat.clone();
            assert_eq!(*stat, cmp);
            assert_eq!(stat.as_var(), cmp.as_var());
        }

        fastrand::shuffle(&mut static_vars);
        let mut chunks = static_vars.chunks_exact(2);
        while let Some([v1, v2]) = chunks.next() {
            assert_ne!(v1, v2);
            assert_ne!(v1.as_var(), v2.as_var());
        }
    }

    #[test]
    fn mixed_eq() {
        for &(stat, cust) in MIXED_REF {
            let stat = OwnedVarName::from(stat);
            let cust = OwnedVarName::from(cust);
            assert_eq!(stat, cust);
            assert_eq!(cust, stat);
            assert_eq!(stat.as_var(), cust.as_var());
        }

        const MIXED_NEQ: &[(StaticVarName, &str)] = &[
            (SERVER_PROTOCOL, "asdf%&&afsaFq$UZW84wbn3gv5w3w5w%!W%q3b5b32wwa"),
            (SCRIPT_NAME, "SCRIPT_FILENAME"),
            (REMOTE_ADDR, "server_addr"),
            (HTTP_COOKIE, "_cookie"),
            (HTTP_X_FORWARDED_FOR, "http_x_forwarded"),
        ];
        for &(stat, cust) in MIXED_NEQ {
            let stat = OwnedVarName::from(stat);
            let cust = OwnedVarName::from(cust);
            assert_ne!(stat, cust);
            assert_ne!(cust, stat);
            assert_ne!(stat.as_var(), cust.as_var());
        }
    }

    #[test]
    fn str_eq() {
        fn do_nothing(_: &mut str) {}

        for mut cust in repeat_with(rand_name).take(20) {
            let orig = OwnedVarName::from(cust.as_str());
            for modify in [do_nothing, str::make_ascii_uppercase, str::make_ascii_lowercase] {
                modify(&mut cust);
                let cmp = OwnedVarName::from(cust.as_str());
                assert_eq!(orig, cmp);
                assert_eq!(orig.as_var(), cmp.as_var());
            }
        }

        const STR_NEQ: &[(&str, &str)] = &[
            ("YX,oyd'p^&4ER:eI9AddsB", "2'J6&^WP}3AS2#%(cERkb"),
            ("xKM$>O&a%(8'", "REMOTE_PORT"),
            (":P+?*", "2pr|y5CY\\*hNA7rT7$"),
            ("SERVER_PORT", "HTTP_ACCEPT_ENCODING"),
            ("HTTP_X_FORWARDED_PROTO", "W{.[2W]|^bRI[25/?s@^]I|b:I)OE%%tf"),
        ];
        for &(v1, v2) in STR_NEQ {
            let v1 = OwnedVarName::from(v1);
            let v2 = OwnedVarName::from(v2);
            assert_ne!(v1, v2);
            assert_ne!(v1.as_var(), v2.as_var());
        }
    }

    #[test]
    fn cmp() {
        use std::cmp::Ordering::*;
        let mut vars: Vec<_> = StaticVarName::iter().map(OwnedVarName::from).collect();
        vars.extend(repeat_with(rand_name).map(OwnedVarName::from).take(50));

        fastrand::shuffle(&mut vars);
        vars.sort_unstable();
        let mut windows = vars.windows(2);
        while let Some([v1, v2]) = windows.next() {
            if v1 == v2 {
                assert!(matches!(v1.partial_cmp(v2), Some(Equal)));
                assert!(matches!(v2.partial_cmp(v1), Some(Equal)));
            } else {
                assert!(matches!(v1.partial_cmp(v2), Some(Less)));
                assert!(matches!(v2.partial_cmp(v1), Some(Greater)));
                assert!(v1.as_var() < v2.as_var());
                assert!(v2.as_var() > v1.as_var());
            }
        }
    }

    #[test]
    fn borrow_hash() {
        // Custom hasher to check bytestream equality
        #[derive(Default)]
        struct TestHasher(Vec<u8>);
        impl Hasher for TestHasher {
            fn write(&mut self, bytes: &[u8]) {
                self.0.extend(bytes);
            }
            fn finish(&self) -> u64 {
                let mut real_hasher = DefaultHasher::default();
                real_hasher.write(&self.0);
                real_hasher.finish()
            }
        }

        let var_iter = StaticVarName::iter().map(OwnedVarName::from)
            .chain(repeat_with(rand_name).map(OwnedVarName::from).take(100));

        for owned in var_iter {
            let mut own_hasher = TestHasher::default();
            let mut ref_hasher = TestHasher::default();
            owned.hash(&mut own_hasher);
            owned.as_var().hash(&mut ref_hasher);
            assert_eq!(own_hasher.0, ref_hasher.0);
        }
    }

    #[test]
    fn parse_static() {
        for &(stat, name) in MIXED_REF {
            let name = name.to_owned();
            let var = OwnedVarName::from(name);
            assert!(matches!(var, OwnedVarName(VarNameInner::Static(s)) if s == stat));
        }

        for stat in StaticVarName::iter() {
            let name: &str = stat.into();
            let var = OwnedVarName::from(name);
            assert!(matches!(var, OwnedVarName(VarNameInner::Static(s)) if s == stat));
        }
    }

    #[test]
    fn custom_norm() {
        const STR_REF: &[(&str, &str)] = &[
            ("some-var-name", "SOME-VAR-NAME"),
            ("a39j_AZMVTW**jw621", "A39J_AZMVTW**JW621"),
            ("6ar2!463'_2!51D6A---a$$a&agw2", "6AR2!463'_2!51D6A---A$$A&AGW2"),
        ];
        for &(name, exp) in STR_REF {
            let name = name.to_owned();
            let var = OwnedVarName::from(name);
            assert_eq!(var.as_ref(), exp);
        }
    }
}
