#[macro_export]
macro_rules! new_empty_attr {
    ($attr:ident, $codepoint:expr$(,)?) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $attr;

        impl $attr {
            pub const TYPE: $crate::attribute::Type = $codepoint;
        }

        impl $crate::attribute::Attribute for $attr {
            #[inline]
            fn attribute_type(&self) -> $crate::attribute::Type {
                Self::TYPE
            }
        }

        impl $crate::attribute::EncodeAttribute for $attr {
            #[inline]
            fn encoded_value_len(&self) -> u16 {
                0
            }

            #[inline]
            fn encode<'a>(
                &self,
                dst: &'a mut [u8],
                _: &$crate::TransactionId,
            ) -> Result<&'a mut [u8], $crate::StunError> {
                Ok($crate::attribute::empty::encode_empty(Self::TYPE, dst)?)
            }
        }

        impl $crate::attribute::DecodeAttribute<'_> for $attr {
            #[inline]
            fn decode(
                _: $crate::attribute::Type,
                src: &[u8],
                _: &$crate::TransactionId,
            ) -> Result<Self, $crate::StunError> {
                $crate::attribute::empty::decode_empty(src)?;
                Ok(Self)
            }
        }
    };
}

use crate::{
    attribute::{encode_type_length, Type, TypeLenTooBig},
    error::{new_error, ErrorKind},
    parse::RawAttribute,
};

#[inline]
pub fn encode_empty(attr: Type, dst: &mut [u8]) -> Result<&mut [u8], impl ErrorKind> {
    (dst.len() >= RawAttribute::TL_LEN)
        .then(|| encode_type_length(attr, 0, dst))
        .ok_or(TypeLenTooBig)
}

#[inline]
pub fn decode_empty(src: &[u8]) -> Result<(), impl ErrorKind> {
    new_error!(
        LenMismatch { actual: usize },
        InvalidParameter,
        "empty attribute requires an empty buffer , buffer of length {actual} provided",
    );
    if !src.is_empty() {
        Ok(())
    } else {
        Err(LenMismatch::new(src.len()))
    }
}

new_empty_attr!(DontFragment, Type::DONT_FRAGMENT);
new_empty_attr!(UseCandidate, Type::USE_CANDIDATE);

#[cfg(test)]
mod test {
    crate::new_empty_attr!(TestAttr, crate::attribute::Type::MAPPED_ADDRESS);
}
