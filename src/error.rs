use core::fmt::{Debug, Display, Formatter, Result};
use inline_dyn::{inline_dyn, InlineDyn};

pub struct StunError {
    repr: InlineDyn<dyn ErrorKind, 8>,
}

impl StunError {
    fn new<D: ErrorKind>(repr: D) -> Self {
        Self { repr: inline_dyn!(repr) }
    }

    #[inline]
    pub fn error_kind(&self) -> StunErrorKind {
        self.repr.error_kind()
    }

    #[inline]
    #[cfg(feature = "std")]
    pub fn source(&self) -> &(dyn StdError + Send + Sync + 'static) {
        &self.repr
    }
}

impl<K: ErrorKind> From<K> for StunError {
    #[inline]
    fn from(repr: K) -> Self {
        Self::new(repr)
    }
}

impl Debug for StunError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("StunError")
            .field("kind", &self.error_kind())
            .field("payload", &self.repr)
            .finish()
    }
}

impl Display for StunError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_fmt(format_args!("{}. {}", self.error_kind(), &self.repr))
    }
}

pub trait ErrorKind: StdError + Send + Sync + 'static {
    fn error_kind(&self) -> StunErrorKind;
}

cfg_if::cfg_if! {
    if #[cfg(feature = "error_in_core")] {
        pub(crate) use core::error::Error as StdError;
    } else if #[cfg(feature = "std")] {
        pub(crate) use std::error::Error as StdError;
    } else {
        pub trait StdError: Debug + Display {}
        impl <T: Debug + Display> StdError for T {}
    }
}

#[cfg(any(feature = "error_in_core", feature = "std"))]
impl StdError for StunError {
    #[cfg(feature = "std")]
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.repr)
    }
}

macro_rules! new_error {
    ($error:ident, $kind:ident, $str:literal$(,)?) => {
        #[derive(::core::fmt::Debug)]
        pub(crate) struct $error;
        impl ::core::fmt::Display for $error {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str($str)
            }
        }
        $crate::error::new_error!($error, $kind);
    };
    ($error:ident{ $($field:ident: $t:ident),*$(,)?}, $kind:ident, $($arg:tt)*) => {
        #[derive(::core::fmt::Debug)]
        pub(crate) struct $error {$($field: $t,)*}
        impl $error {
            #[inline]
            #[allow(unused)]
            pub const fn new($($field: $t,)*) -> Self {
                Self { $($field,)* }
            }
        }
        impl ::core::fmt::Display for $error {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                let Self { $($field,)* } = self;
                ::core::write!(f, $($arg)*)
            }
        }
        $crate::error::new_error!($error, $kind);
    };
    ($error:ident, $kind:ident$(,)?) => {
        $crate::error::new_error!($error);
        $crate::error::wrap_error!($error, $kind);
    };
    ($error:ident$(,)?) => {
        #[cfg(any(feature = "error_in_core", feature = "std"))]
        impl $crate::error::StdError for $error {}
    }
}

pub(crate) use new_error;

macro_rules! wrap_error {
    ($error:ident, $kind:ident) => {
        impl $crate::error::ErrorKind for $error {
            #[inline]
            fn error_kind(&self) -> $crate::error::StunErrorKind {
                $crate::error::StunErrorKind::$kind
            }
        }
    };
}
pub(crate) use wrap_error;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum StunErrorKind {
    InvalidParameter,
    ValidationFailed,
    ValueTooLong,
    BufferTooSmall,
    TooManyAttributes,
    MagicCookie,
}

impl StunErrorKind {
    #[inline]
    fn description_str(&self) -> &'static str {
        match *self {
            Self::InvalidParameter => "invalid parameter",
            Self::ValidationFailed => "validation failed",
            Self::ValueTooLong => "value is too long",
            Self::BufferTooSmall => "buffer is too small for the message",
            Self::TooManyAttributes => "attribute buffer is too small for the message",
            Self::MagicCookie => "magic cookie doesn't match",
        }
    }
}

impl Display for StunErrorKind {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.description_str())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_error() {
        assert_eq!(core::mem::size_of::<StunError>(), 16);
    }
}
