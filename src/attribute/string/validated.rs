use crate::{
    attribute::string::{dns, length, opaque, quoted},
    error::{new_error, ErrorKind, StunError},
    util,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Validated<T, const DNS: bool, const QUOTED: bool, const OPAQUE: bool>(pub(crate) T);

impl<T: AsRef<str>, const D: bool, const Q: bool, const O: bool> Validated<T, D, Q, O> {
    const MAX_LEN: usize = if D { dns::MAX_NAME_LENGTH } else { length::MAX_BYTES };
    #[inline]
    pub fn as_str(&self) -> &str {
        let s = self.0.as_ref();
        unsafe { util::assert_unchecked!(s.len() <= Self::MAX_LEN) }
        s
    }

    #[inline]
    pub fn as_validated_str(&self) -> Validated<&str, D, Q, O> {
        Validated(self.0.as_ref())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<'a, const D: bool, const Q: bool, const O: bool> Validated<&'a str, D, Q, O> {
    #[inline]
    pub const fn const_try_from(s: &'a str) -> Result<Self, impl ErrorKind> {
        new_error!(StringTooLongConst, ValueTooLong, "string must be below 128 bytes");
        #[derive(Debug)]
        enum Error {
            A(StringTooLongConst),
            B(StringNotQuoted),
            C(StringNotOPaque),
            D(dns::InvalidDnsName),
        }

        impl core::fmt::Display for Error {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    Self::A(err) => err.fmt(f),
                    Self::B(err) => err.fmt(f),
                    Self::C(err) => err.fmt(f),
                    Self::D(err) => err.fmt(f),
                }
            }
        }

        new_error!(Error);
        impl ErrorKind for Error {
            fn error_kind(&self) -> crate::error::StunErrorKind {
                match self {
                    Self::A(err) => err.error_kind(),
                    Self::B(err) => err.error_kind(),
                    Self::C(err) => err.error_kind(),
                    Self::D(err) => err.error_kind(),
                }
            }
        }

        if D {
            if let Err(err) = dns::validate_domain_name(s.as_bytes()) {
                return Err(Error::D(err));
            }
        } else if s.len() > length::MAX_CHARS {
            return Err(Error::A(StringTooLongConst));
        }
        if Q && !quoted::is_quoted_text_ascii(s) {
            return Err(Error::B(StringNotQuoted));
        }
        if O && !opaque::is_opaque_string_ascii(s) {
            return Err(Error::C(StringNotOPaque));
        }
        Ok(Self(s))
    }
}

macro_rules! try_from {
    ($ty:ty $(, $($tt:tt)+)?) => {
        impl <$($($tt)+)? const D: bool, const Q: bool, const O: bool> TryFrom<$ty> for Validated<$ty, D, Q, O> {
            type Error = StunError;
            #[inline]
            fn try_from(value: $ty) -> Result<Self, Self::Error> {
                let s: &str = value.as_ref();
                if D { dns::validate_domain_name(s.as_bytes())?; } else { length::validate_str_len(s)? }
                validate_quoted_opaque::<Q, O>(s)?;
                Ok(Self(value))
            }
        }
    };
}

impl<'a, const D: bool, const Q: bool, const O: bool> TryFrom<&'a [u8]>
    for Validated<&'a str, D, Q, O>
{
    type Error = StunError;

    #[inline]
    fn try_from(b: &'a [u8]) -> Result<Self, Self::Error> {
        let s = if D { dns::validate_domain_name(b)? } else { length::validate_str_bytes(b)? };
        validate_quoted_opaque::<Q, O>(s)?;
        Ok(Self(s))
    }
}

#[inline]
fn validate_quoted_opaque<const Q: bool, const O: bool>(s: &str) -> Result<(), StunError> {
    if Q && !quoted::is_quoted_text(s) {
        return Err(StringNotQuoted.into());
    }
    if O && !opaque::is_opaque_string(s) {
        return Err(StringNotOPaque.into());
    }
    Ok(())
}

try_from!(&'a str, 'a,);
#[cfg(feature = "alloc")]
try_from!(alloc::string::String);
#[cfg(feature = "heapless")]
try_from!(heapless::String<N>, const N: usize,);

#[cfg(feature = "alloc")]
impl<const D: bool, const Q: bool, const O: bool> From<Validated<&str, D, Q, O>>
    for Validated<alloc::string::String, D, Q, O>
{
    #[inline]
    fn from(value: Validated<&str, D, Q, O>) -> Self {
        Self(value.0.into())
    }
}

#[cfg(feature = "heapless")]
impl<const N: usize, const D: bool, const Q: bool, const O: bool> TryFrom<Validated<&str, D, Q, O>>
    for Validated<heapless::String<N>, D, Q, O>
{
    type Error = ();
    #[inline]
    fn try_from(value: Validated<&str, D, Q, O>) -> Result<Self, Self::Error> {
        value.0.try_into().map(Self)
    }
}

new_error!(StringNotQuoted, InvalidParameter, "string is not a sequence of qdtext or quoted-pair");
new_error!(
    StringNotOPaque,
    InvalidParameter,
    "string does not meet the PRECIS OpaqueString specification",
);
