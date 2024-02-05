use crate::{
    attribute::{DecodeAttribute, Type},
    error::{new_error, StunError},
    header::{Class, Header, Method, TransactionId},
    parse::attribute::{Container, RawAttribute},
    util, MAGIC_COOKIE,
};
use core::{iter::Map, slice::Iter as SliceIter};

pub struct MessageParser<'src, 'attr> {
    class: Class,
    method: Method,
    transaction_id: TransactionId,
    src: &'src [u8],
    attrs: &'attr [RawAttribute],
}

impl<'src, 'attr> MessageParser<'src, 'attr> {
    pub fn from_complete_message<C: Container + ?Sized>(
        src: &'src [u8],
        attrs: &'attr mut C,
    ) -> Result<Self, StunError> {
        if src.len() < Header::LEN {
            new_error!(
                HeaderTooBig { len: usize },
                BufferTooSmall,
                "src of len {len} can't fit a header of len 20",
            );
            return Err(HeaderTooBig::new(src.len()).into());
        }
        let (header, src) = util::split_array_ref(src);
        let header = Header::decode(header)?;
        Self::from_header_and_attrs(header, src, attrs)
    }

    pub fn from_header_and_attrs<C: Container + ?Sized>(
        header: Header,
        src: &'src [u8],
        attrs: &'attr mut C,
    ) -> Result<Self, StunError> {
        if header.is_rfc3489() {
            new_error!(
                MagicCookie { cookie: u32 },
                MagicCookie,
                "the magic cookie parsed ({cookie:#06X}) doesn't correspond to {MAGIC_COOKIE:#06X}. \
                either it's part of an rfc3489 stun message's transaction id or a different protocol",
            );
            return Err(MagicCookie::new(header.magic_cookie).into());
        }
        if header.length as usize != src.len() {
            new_error!(
                BufferLenMismatch { header: u16, actual: u16 },
                InvalidParameter,
                "attribute buffer length according to the header: {header}, while given src len: {actual}",
            );
            let len = src.len().try_into().unwrap_or(u16::MAX);
            return Err(BufferLenMismatch::new(header.length, len).into());
        }
        let Header { class, method, transaction_id, .. } = header;
        attrs.parse(src).map(|attrs| Self { class, method, transaction_id, src, attrs })
    }

    #[inline]
    #[cfg(feature = "type_alias_impl_trait")]
    pub fn iter_raw(&self) -> Iter<'attr, ConvertRaw<'src, 'attr>> {
        self.attrs.iter().map(|attr: &'attr RawAttribute| convert(self.src, *attr))
    }

    #[inline]
    #[cfg(not(feature = "type_alias_impl_trait"))]
    pub fn iter_raw(&self) -> Iter<'attr, impl FnMut(&'attr RawAttribute) -> Item<'src>> {
        self.attrs.iter().map(|attr: &'attr RawAttribute| convert(self.src, *attr))
    }

    #[inline]
    #[cfg(feature = "type_alias_impl_trait")]
    pub fn iter<D: DecodeAttribute<'src>>(&'src self) -> Iter<'attr, Convert<'src, 'attr, D>> {
        self.attrs.iter().map(|attr: &'attr RawAttribute| {
            let item = convert(self.src, *attr);
            D::decode(item.attr, item.value, self.transaction_id())
        })
    }

    #[inline]
    #[cfg(not(feature = "type_alias_impl_trait"))]
    pub fn iter<D: DecodeAttribute<'src>>(
        &'src self,
    ) -> Iter<'attr, impl FnMut(&'attr RawAttribute) -> Result<D, StunError> + 'src> {
        self.attrs.iter().map(|attr: &'attr RawAttribute| {
            let item = convert(self.src, *attr);
            D::decode(item.attr, item.value, self.transaction_id())
        })
    }

    #[inline]
    pub fn class(&self) -> Class {
        self.class
    }

    #[inline]
    pub fn method(&self) -> Method {
        self.method
    }

    #[inline]
    pub fn transaction_id(&self) -> &TransactionId {
        &self.transaction_id
    }

    #[inline]
    pub fn validation_header(&self) -> ValidationHeader {
        let &Self { class, method, transaction_id, .. } = self;
        let (magic_cookie, length) = (MAGIC_COOKIE, self.src.len() as _);
        let mut validation_header = ValidationHeader([0; Header::LEN]);
        Header { class, method, transaction_id, magic_cookie, length }
            .encode(&mut validation_header.0);
        validation_header
    }

    // pub fn validate(&mut self) -> Result<Validation, ValidationError> {
    //     if self.header.is_rfc3489() {
    //         return Err(ValidationError::MagicCookie);
    //     }
    //     let mut validation = Validation { fingerprint: None };
    //     let mut iter = self.attrs.iter();
    //     let Some(last) = iter.next_back() else {
    //         return Ok(validation);
    //     };
    //     struct HeaderCustom<'a> {
    //         class_method: [u8; 2],
    //         transaction_id: &'a TransactionId,
    //     }
    //
    //     impl<'a> HeaderCustom<'a> {
    //         fn from_header(header: &'a Header) -> Self {
    //             Self { class_method: header.class_method(), transaction_id: &header.transaction_id }
    //         }
    //
    //         fn with_length(&self, length: u16, mut f: impl FnMut(&[u8])) {
    //             f(&self.class_method);
    //             f(&length.to_be_bytes());
    //             f(&MAGIC_COOKIE_BYTES);
    //             f(&self.transaction_id.0);
    //         }
    //     }
    //
    //     let header = HeaderCustom::from_header(&self.header);
    //     if last.typ == AttributeType::FINGERPRINT {
    //         let mut digest = Fingerprint::DIGEST;
    //         let fingerprint = last.val.try_into().map_err(|_| ValidationError::Fingerprint)?;
    //         let fingerprint = validation.fingerprint.insert(fingerprint);
    //         header.with_length(self.header.length, |b| digest.update(b));
    //         digest.update(Self::slice_up_to(self.src, last.val));
    //         let crc = digest.finalize() ^ Fingerprint::XOR;
    //         if crc != fingerprint.crc32() {
    //             return Err(ValidationError::Fingerprint);
    //         }
    //         self.attrs = iter.as_slice();
    //     }
    //     Ok(validation)
    // }
}

pub struct Item<'src> {
    pub(crate) attr: Type,
    pub(crate) value: &'src [u8],
    pub(crate) attrs_up_to: &'src [u8],
}

impl<'src> Item<'src> {
    #[inline]
    pub fn attr(&self) -> Type {
        self.attr
    }

    #[inline]
    pub fn value(&self) -> &'src [u8] {
        self.value
    }

    #[inline]
    pub fn attrs_up_to(&self) -> &'src [u8] {
        self.attrs_up_to
    }
}

pub type Iter<'attr, T> = Map<SliceIter<'attr, RawAttribute>, T>;
#[cfg(feature = "type_alias_impl_trait")]
pub type ConvertRaw<'src, 'attr> = impl FnMut(&'attr RawAttribute) -> Item<'src>;
#[cfg(feature = "type_alias_impl_trait")]
pub type Convert<'src, 'attr, D: DecodeAttribute<'src>> =
    impl FnMut(&'attr RawAttribute) -> Result<D, StunError> + 'src;

#[inline]
fn convert(src: &[u8], RawAttribute { attr, len, off, .. }: RawAttribute) -> Item {
    let (offset, len) = (off as usize, len as usize);
    let (value, attrs_up_to) = unsafe { (value(src, offset, len), attrs_up_to(src, offset)) };
    Item { attr, value, attrs_up_to }
}

unsafe fn attrs_up_to(src: &[u8], offset: usize) -> &[u8] {
    src.get_unchecked(0..offset - RawAttribute::TL_LEN)
}

unsafe fn value(src: &[u8], offset: usize, len: usize) -> &[u8] {
    src.get_unchecked(offset..offset + len)
}

pub struct ValidationHeader([u8; Header::LEN]);

impl ValidationHeader {
    pub fn as_bytes(&self) -> &[u8; Header::LEN] {
        &self.0
    }

    pub fn set_len_from_item(&mut self, item: &Item) {
        let len = RawAttribute::TL_LEN as u16
            + item.attrs_up_to.len() as u16
            + RawAttribute::padded_len(item.value.len() as u16);
        self.set_len(len);
    }

    pub fn set_len(&mut self, len: u16) {
        self.0[2..4].copy_from_slice(&len.to_be_bytes());
    }
}

// pub struct Validation {
//     fingerprint: Option<Fingerprint>,
// }
//
// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// pub enum ValidationError {
//     Fingerprint,
//     MessageIntegrity,
//     MagicCookie,
// }

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_data::*;

    #[test]
    fn test_parse() {
        let mut v = [core::mem::MaybeUninit::uninit(); 32];
        for parts in TEST_VECTOR {
            let msg = assert_ok!(
                MessageParser::from_complete_message(parts.message, &mut v),
                "error parsing raw msg",
            );
            for (parsed, test) in msg.attrs.iter().zip(parts.attr_parts) {
                assert_eq!(&parsed.attr.codepoint().to_be_bytes(), test.t);
                assert_eq!(&parsed.len.to_be_bytes(), test.l);
                let (off, len) = (parsed.off as usize, parsed.len as usize);
                let end = off + len;
                assert_eq!(&msg.src[off..end], test.v);
                assert_eq!(&msg.src[end..end + parsed.pad as usize], test.p);
            }
        }
    }

    #[test]
    fn test_iter() {
        let mut v = [core::mem::MaybeUninit::uninit(); 32];
        for parts in TEST_VECTOR {
            let msg = assert_ok!(
                MessageParser::from_complete_message(parts.message, &mut v),
                "error parsing raw msg",
            );
            for (parsed, test) in msg.iter_raw().zip(parts.attr_parts) {
                assert_eq!(&parsed.attr.codepoint().to_be_bytes(), test.t);
                assert_eq!(&u16::try_from(parsed.value.len()).unwrap().to_be_bytes(), test.l);
                assert_eq!(parsed.value, test.v);
            }
        }
    }
}
