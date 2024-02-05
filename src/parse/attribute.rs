use crate::{
    attribute::Type,
    error::{new_error, StunError},
    util,
};
use core::{mem::MaybeUninit, num::NonZeroU16, slice};

#[repr(align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawAttribute {
    pub attr: Type,
    pub len: u16,
    pub off: u16,
    pub pad: u16,
}

impl RawAttribute {
    pub const TL_LEN: usize = 4;
    pub const MAX_PADDING_LEN: usize = MAX_PADDING_LEN as usize;

    fn parse_uninit(mut src: &[u8], attrs: &mut [MaybeUninit<Self>]) -> Result<usize, StunError> {
        let mut iter = attrs.iter_mut();
        Self::parse_inner(src.as_ptr(), &mut src, &mut iter)?;
        let remaining_len = iter.len();
        Ok(attrs.len() - remaining_len)
    }

    fn parse_inner(
        start: *const u8,
        src: &mut &[u8],
        attrs: &mut slice::IterMut<MaybeUninit<Self>>,
    ) -> Result<(), ParseError> {
        let mut slc;
        while src.len() >= Self::TL_LEN {
            let Some(curr) = attrs.next() else {
                return Err(ParseError::Full);
            };
            (slc, *src) = util::split_array_ref(src);
            let (attr, len) = Self::decode_type_length(slc);
            let off = unsafe { src.as_ptr().offset_from(start) as u16 };
            let pad = Self::padding(len);
            match src.get(len as usize + pad as usize..) {
                Some(next) => *src = next,
                None => {
                    let (rem, len) = (src.len() as u16, len.try_into().unwrap());
                    return Err(ParseError::Invalid(AttributeTooBig::new(attr, off, rem, len)));
                }
            }
            *curr = MaybeUninit::new(Self { attr, len, off, pad });
        }
        // input src.len() has to be a multiple of 4, and so is len + pad, so there can't be anything remaining.
        // parse() is only used internally
        Ok(())
    }

    #[inline]
    pub fn encode_type_length(t: Type, l: u16, dst: &mut [u8; Self::TL_LEN]) {
        let (attr, len) = util::split_array_exact_mut(dst);
        *attr = t.codepoint().to_be_bytes();
        *len = l.to_be_bytes();
    }

    #[inline]
    pub fn decode_type_length(src: &[u8; Self::TL_LEN]) -> (Type, u16) {
        let (attr, len) = util::split_array_exact_ref(src);
        (Type::new(u16::from_be_bytes(*attr)), u16::from_be_bytes(*len))
    }

    #[inline]
    pub const fn padding(len: u16) -> u16 {
        (-(len as i16) as u16) & MAX_PADDING_LEN
    }

    #[inline]
    pub const fn padded_len(len: u16) -> u16 {
        const PADDED_MASK: u16 = u16::MAX - MAX_PADDING_LEN;
        (len + MAX_PADDING_LEN) & PADDED_MASK
    }
}

pub trait Container {
    fn parse(&mut self, src: &[u8]) -> Result<&mut [RawAttribute], StunError>;
}

impl Container for [MaybeUninit<RawAttribute>] {
    fn parse(&mut self, src: &[u8]) -> Result<&mut [RawAttribute], StunError> {
        let len = RawAttribute::parse_uninit(src, self)?;
        Ok(unsafe { slice::from_raw_parts_mut(self.as_ptr() as _, len) })
    }
}

impl<const N: usize> Container for [MaybeUninit<RawAttribute>; N] {
    fn parse(&mut self, src: &[u8]) -> Result<&mut [RawAttribute], StunError> {
        self.as_mut_slice().parse(src)
    }
}

const MAX_PADDING_LEN: u16 = 3;

#[cfg(feature = "alloc")]
impl Container for alloc::vec::Vec<RawAttribute> {
    fn parse(&mut self, mut src: &[u8]) -> Result<&mut [RawAttribute], StunError> {
        let src_ptr = src.as_ptr();
        self.truncate(0);
        loop {
            let capacity = self.spare_capacity_mut();
            let mut iter = capacity.iter_mut();
            let res = RawAttribute::parse_inner(src_ptr, &mut src, &mut iter);
            let (remaining, capacity) = (iter.len(), self.capacity());
            unsafe { self.set_len(capacity - remaining) };
            match res {
                Ok(()) => return Ok(self.as_mut_slice()),
                Err(ParseError::Full) => self.reserve(1),
                Err(ParseError::Invalid(err)) => return Err(err.into()),
            }
        }
    }
}

#[cfg(feature = "heapless")]
impl<const N: usize> Container for heapless::Vec<RawAttribute, N> {
    fn parse(&mut self, src: &[u8]) -> Result<&mut [RawAttribute], StunError> {
        unsafe {
            let len = RawAttribute::parse_uninit(src, &mut *(self.as_mut_ptr() as *mut [_; N]))?;
            self.set_len(len);
        }
        Ok(self.as_mut_slice())
    }
}

new_error!(
    AttributeTooBig { attr: Type, off: u16, rem: u16, len: NonZeroU16 },
    BufferTooSmall,
    "attribute of type {attr} at offset {off} requires length of {len} (padded to {pad}), \
    but buffer only has {rem} remaining",
    pad = len.get() + RawAttribute::padding(len.get()),
);

enum ParseError {
    Invalid(AttributeTooBig),
    Full,
}

impl From<ParseError> for StunError {
    fn from(err: ParseError) -> Self {
        new_error!(TooManyAttributes, TooManyAttributes, "could not parse the rest of the message");
        match err {
            ParseError::Invalid(err) => err.into(),
            ParseError::Full => TooManyAttributes.into(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_data::*;

    #[test]
    fn test_parse() {
        let mut arr = [MaybeUninit::uninit(); 32];
        #[cfg(feature = "alloc")]
        let mut alloc = alloc::vec![];
        #[cfg(feature = "heapless")]
        let mut heapless = heapless::Vec::<_, 32>::new();
        for &Parts { attributes, attr_parts, .. } in TEST_VECTOR {
            let v = assert_ok!(arr.parse(attributes), "error parsing raw attr");
            #[cfg(feature = "alloc")]
            {
                let r = assert_ok!(alloc.parse(attributes), "error parsing raw attr into vec");
                assert_eq!(r, v);
                assert_eq!(&alloc, v);
            }
            #[cfg(feature = "heapless")]
            {
                let r = assert_ok!(heapless.parse(attributes), "error parsing raw attr into hvec");
                assert_eq!(r, v);
                assert_eq!(&heapless, v);
            }
            for (parsed, test) in v.iter().zip(attr_parts) {
                assert_eq!(&parsed.attr.codepoint().to_be_bytes(), test.t);
                assert_eq!(&parsed.len.to_be_bytes(), test.l);
                let (off, end) = (parsed.off as usize, parsed.off as usize + parsed.len as usize);
                assert_eq!(&attributes[off..end], test.v);
                assert_eq!(&attributes[end..end + parsed.pad as usize], test.p);
            }
        }
    }
}
