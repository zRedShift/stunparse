use crate::{attribute::string::error::StringTooLong, error::StunError};

#[inline]
pub(super) fn validate_str_len(s: &str) -> Result<(), StringTooLong> {
    match s.len() {
        0..=MAX_CHARS => Ok(()),
        bytes @ CHAR_CHECK_START_LEN..=MAX_BYTES => {
            let count = s.chars().count();
            if count > MAX_CHARS {
                Err(StringTooLong::new(bytes, Some(count)))
            } else {
                Ok(())
            }
        }
        bytes => Err(StringTooLong::new(bytes, None)),
    }
}

#[inline]
pub(super) fn validate_str_bytes(s: &[u8]) -> Result<&str, StunError> {
    if s.len() > MAX_BYTES {
        return Err(StringTooLong::new(s.len(), None).into());
    }
    let s = core::str::from_utf8(s)?;
    match s.len() {
        0..=MAX_CHARS => Ok(s),
        bytes => {
            let count = s.chars().count();
            if count > MAX_CHARS {
                Err(StringTooLong::new(bytes, Some(count)).into())
            } else {
                Ok(s)
            }
        }
    }
}

const CHAR_CHECK_START_LEN: usize = MAX_CHARS + 1;
pub(super) const MAX_CHARS: usize = 127;
pub(super) const MAX_BYTES: usize = MAX_CHARS * core::mem::size_of::<char>();
