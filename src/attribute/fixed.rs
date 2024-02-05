#[macro_export]
macro_rules! new_fixed_attr {
    ($attr:ident, $codepoint:expr, $len:expr $(,)?) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $attr<T = &'static [u8; $len]>(T);

        impl<T> $attr<T> {
            pub const TYPE: $crate::attribute::Type = $codepoint;

            pub const LEN: usize = $len;

            #[inline]
            pub fn new(value: T) -> Self {
                Self(value)
            }

            #[inline]
            pub fn value(&self) -> &[u8; $len]
            where
                T: ::core::borrow::Borrow<[u8; $len]>,
            {
                self.0.borrow()
            }

            #[inline]
            pub fn into_inner(self) -> T {
                self.0
            }
        }

        impl<'a> $attr<&'a [u8; $len]> {
            #[inline]
            pub const fn const_new(value: &'a [u8; $len]) -> Self {
                Self(value)
            }
        }

        impl<T: ::core::borrow::Borrow<[u8; $len]>> $crate::attribute::Attribute for $attr<T> {
            #[inline]
            fn attribute_type(&self) -> $crate::attribute::Type {
                Self::TYPE
            }
        }

        impl<T: ::core::borrow::Borrow<[u8; $len]>> $crate::attribute::EncodeAttribute
            for $attr<T>
        {
            #[inline]
            fn encoded_value_len(&self) -> u16 {
                Self::LEN as u16
            }

            #[inline]
            fn encode<'a>(
                &self,
                dst: &'a mut [u8],
                _: &$crate::TransactionId,
            ) -> Result<&'a mut [u8], $crate::StunError> {
                $crate::attribute::fixed::encode_fixed(Self::TYPE, dst, self.value())
            }
        }

        impl<'d> $crate::attribute::DecodeAttribute<'d> for $attr<&'d [u8; $len]> {
            #[inline]
            fn decode(
                _: $crate::attribute::Type,
                src: &'d [u8],
                _: &$crate::TransactionId,
            ) -> Result<Self, $crate::StunError> {
                Ok(Self($crate::attribute::fixed::decode_fixed(src)?))
            }
        }
    };
}

use crate::{
    attribute::Type,
    error::{new_error, ErrorKind, StunError},
    util,
};

#[inline]
pub fn encode_fixed<'a, const N: usize>(
    attr: Type,
    dst: &'a mut [u8],
    value: &[u8; N],
) -> Result<&'a mut [u8], StunError> {
    #![allow(clippy::let_unit_value)]
    let () = util::AssertLess::<N, { super::MAX_VALUE_LEN + 1 }>::OK;
    super::encode_variable_len(attr, value, dst)
}

#[inline]
pub fn decode_fixed<const N: usize>(src: &[u8]) -> Result<&[u8; N], impl ErrorKind> {
    new_error!(
        LenMismatch { expected: u16, actual: u16 },
        BufferTooSmall,
        "attribute requires a buffer of {expected} bytes, buffer of length {actual} provided",
    );
    src.try_into().map_err(|_| LenMismatch::new(N as u16, src.len() as u16))
}

new_fixed_attr!(UserHash, Type::USERHASH, 32);
new_fixed_attr!(MessageIntegrity, Type::MESSAGE_INTEGRITY, 20);
new_fixed_attr!(MessageIntegritySha256, Type::MESSAGE_INTEGRITY_SHA256, 32);

#[cfg(test)]
mod test {
    crate::new_fixed_attr!(TestAttr, crate::attribute::Type::MAPPED_ADDRESS, 32);
}
