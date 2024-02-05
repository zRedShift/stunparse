use crate::{
    attribute::{
        encode_type_length, encode_variable_len, ensure_space, total_len, Attribute,
        DecodeAttribute, EncodeAttribute, Type, ValueTooLong, MAX_VALUE_LEN,
    },
    error::new_error,
    util, StunError, TransactionId,
};
use core::{iter::Map, slice};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct UnknownAttributes<T>(T);

impl<T> UnknownAttributes<T> {
    pub const TYPE: Type = Type::UNKNOWN_ATTRIBUTES;

    #[inline]
    pub const fn new(inner: T) -> Self {
        Self(inner)
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Parsed<'a> {
    chunks: &'a [TypeBuffer],
}

impl<'a> UnknownAttributes<Parsed<'a>> {
    pub fn from_bytes(src: &'a [u8]) -> Result<Self, StunError> {
        if src.len() % Type::LEN != 0 {
            new_error!(
                InvalidAttrTypeArray,
                InvalidParameter,
                "UNKNOWN-ATTRIBUTES array must be a multiple of 2 in bytes",
            );
            return Err(InvalidAttrTypeArray.into());
        }
        Ok(Self(Parsed { chunks: util::as_chunks_exact(src) }))
    }

    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        let chunks = self.0.chunks;
        unsafe { slice::from_raw_parts(chunks.as_ptr().cast(), chunks.len() * Type::LEN) }
    }

    #[inline]
    #[cfg(feature = "type_alias_impl_trait")]
    pub fn iter(&self) -> TypeIter<'a, Convert<'a>> {
        self.0.chunks.iter().map(convert)
    }

    #[inline]
    #[cfg(not(feature = "type_alias_impl_trait"))]
    pub fn iter(&self) -> TypeIter<'a, impl FnMut(&'a TypeBuffer) -> Type> {
        self.0.chunks.iter().map(convert)
    }
}

pub type TypeIter<'a, T> = Map<slice::Iter<'a, TypeBuffer>, T>;
#[cfg(feature = "type_alias_impl_trait")]
pub type Convert<'a> = impl FnMut(&'a TypeBuffer) -> Type;

impl<'b> EncodeAttribute for UnknownAttributes<Parsed<'b>> {
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        len_from_count(self.0.chunks.len())
    }

    #[inline]
    fn encode<'a>(&self, dst: &'a mut [u8], _: &TransactionId) -> Result<&'a mut [u8], StunError> {
        encode_variable_len(Self::TYPE, self.as_bytes(), dst)
    }
}

impl<'d> DecodeAttribute<'d> for UnknownAttributes<Parsed<'d>> {
    fn decode(_: Type, src: &'d [u8], _: &TransactionId) -> Result<Self, StunError> {
        Self::from_bytes(src)
    }
}

impl<T> Attribute for UnknownAttributes<T> {
    fn attribute_type(&self) -> Type {
        Self::TYPE
    }
}

impl<T: AsRef<[Type]>> EncodeAttribute for UnknownAttributes<T> {
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        len_from_count(self.0.as_ref().len())
    }

    fn encode<'a>(&self, dst: &'a mut [u8], _: &TransactionId) -> Result<&'a mut [u8], StunError> {
        encode_unknown_attributes(
            self.0.as_ref().iter(),
            |(t, o)| *o = t.codepoint().to_be_bytes(),
            dst,
        )
    }
}

pub struct CloneIter<T> {
    iter: T,
}

impl<T: ExactSizeIterator<Item = Type> + Clone> UnknownAttributes<CloneIter<T>> {
    pub fn from_clone_iter<I: IntoIterator<IntoIter = T>>(iter: I) -> Self {
        Self(CloneIter { iter: iter.into_iter() })
    }
}

impl<T> EncodeAttribute for UnknownAttributes<CloneIter<T>>
where
    T: ExactSizeIterator<Item = Type> + Clone,
{
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        len_from_count(self.0.iter.len())
    }

    fn encode<'a>(&self, dst: &'a mut [u8], _: &TransactionId) -> Result<&'a mut [u8], StunError> {
        encode_unknown_attributes(
            self.0.iter.clone(),
            |(t, o)| *o = t.codepoint().to_be_bytes(),
            dst,
        )
    }
}

impl<'d, T: FromIterator<Type>> DecodeAttribute<'d> for UnknownAttributes<T> {
    fn decode(_: Type, src: &'d [u8], _: &TransactionId) -> Result<Self, StunError> {
        UnknownAttributes::from_bytes(src).map(|p| Self(p.iter().collect()))
    }
}

fn encode_unknown_attributes<I>(
    iter: impl ExactSizeIterator<Item = I>,
    f: impl FnMut((I, &mut TypeBuffer)),
    dst: &mut [u8],
) -> Result<&mut [u8], StunError> {
    let len = len_from_count(iter.len());
    let total_len = total_len(len);
    ensure_space(total_len, len, dst.len())?;
    let (tlvp, rest) = dst.split_at_mut(total_len);
    let (v, pad) =
        encode_type_length(Type::UNKNOWN_ATTRIBUTES, len, tlvp).split_at_mut(len as usize);
    let output: &mut [TypeBuffer] = util::as_chunks_exact_mut(v);
    iter.zip(output).for_each(f);
    pad.fill(0);
    Ok(rest)
}

fn len_from_count(count: usize) -> u16 {
    (count * Type::LEN) as u16
}

#[inline]
const fn convert(&b: &TypeBuffer) -> Type {
    Type::new(u16::from_be_bytes(b))
}

type TypeBuffer = [u8; Type::LEN];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownAttribute<'a> {
    pub(crate) attr: Type,
    pub(crate) value: &'a [u8],
}

impl<'a> UnknownAttribute<'a> {
    pub fn new(attr: Type, value: &'a [u8]) -> Result<Self, StunError> {
        if value.len() > MAX_VALUE_LEN {
            return Err(ValueTooLong::new(value.len()).into());
        }
        Ok(Self { attr, value })
    }

    #[inline]
    pub fn attr(&self) -> Type {
        self.attr
    }

    #[inline]
    pub fn value(&self) -> &'a [u8] {
        self.value
    }
}

impl Attribute for UnknownAttribute<'_> {
    #[inline]
    fn attribute_type(&self) -> Type {
        self.attr
    }
}

impl EncodeAttribute for UnknownAttribute<'_> {
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        self.value.len() as u16
    }

    #[inline]
    fn encode<'a>(&self, dst: &'a mut [u8], _: &TransactionId) -> Result<&'a mut [u8], StunError> {
        encode_variable_len(self.attr, self.value, dst)
    }
}

impl<'d> DecodeAttribute<'d> for UnknownAttribute<'d> {
    #[inline]
    fn decode(attr: Type, src: &'d [u8], _: &TransactionId) -> Result<Self, StunError> {
        Self::new(attr, src)
    }
}
