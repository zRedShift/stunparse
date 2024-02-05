use crate::error::{new_error, StunError};
use core::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug)]
pub(crate) struct Utf8Error {
    valid_up_to: u16,
    error_len: Option<u8>,
}

impl From<core::str::Utf8Error> for StunError {
    #[inline]
    fn from(err: core::str::Utf8Error) -> Self {
        Self::from(Utf8Error {
            valid_up_to: err.valid_up_to() as _,
            error_len: err.error_len().map(|len| len as _),
        })
    }
}

impl Display for Utf8Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if let Some(error_len) = self.error_len {
            write!(f, "invalid utf-8 sequence of {error_len} bytes from index {}", self.valid_up_to)
        } else {
            write!(f, "incomplete utf-8 byte sequence from index {}", self.valid_up_to)
        }
    }
}

new_error!(Utf8Error, InvalidParameter);

#[derive(Debug)]
pub(crate) struct StringTooLong {
    bytes: u16,
    chars: Option<u8>,
}

impl StringTooLong {
    pub fn new(bytes: usize, chars: Option<usize>) -> Self {
        Self { bytes: bytes.try_into().unwrap_or(u16::MAX), chars: chars.map(|c| c as u8) }
    }
}

impl Display for StringTooLong {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if let Some(chars) = self.chars {
            write!(f, "the string is {chars} characters long, must be below 128")
        } else {
            write!(
                f,
                "the string is at least {} bytes long and is above the 128 character limit",
                self.bytes
            )
        }
    }
}

new_error!(StringTooLong, ValueTooLong);
