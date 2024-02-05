#[macro_export]
macro_rules! new_int_attr {
    ($attr:ident, $codepoint:expr, $int_type:ident $(,)?) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $attr($int_type);

        impl $attr {
            pub const TYPE: $crate::attribute::Type = $codepoint;

            #[inline]
            pub const fn new(value: $int_type) -> Self {
                Self(value)
            }

            #[inline]
            pub fn value(&self) -> $int_type {
                self.0
            }
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
                ::core::mem::size_of::<$int_type>() as _
            }

            #[inline]
            fn encode<'a>(
                &self,
                dst: &'a mut [u8],
                _: &$crate::TransactionId,
            ) -> Result<&'a mut [u8], $crate::StunError> {
                const N: usize = ::core::mem::size_of::<$int_type>();
                const M: usize = N + $crate::parse::RawAttribute::TL_LEN;
                $crate::attribute::integer::encode_integer::<_, N, M>(Self::TYPE, dst, || {
                    self.0.to_be_bytes()
                })
            }
        }

        impl $crate::attribute::DecodeAttribute<'_> for $attr {
            #[inline]
            fn decode(
                _: $crate::attribute::Type,
                src: &[u8],
                _: &$crate::TransactionId,
            ) -> Result<Self, $crate::StunError> {
                Ok(Self($crate::attribute::integer::decode_integer(src, $int_type::from_be_bytes)?))
            }
        }
    };
}

use crate::{
    attribute::Type,
    error::{new_error, ErrorKind, StunError},
    parse::RawAttribute,
    util,
};

#[inline]
pub fn encode_integer<F: FnOnce() -> [u8; N], const N: usize, const M: usize>(
    attr: Type,
    dst: &mut [u8],
    f: F,
) -> Result<&mut [u8], StunError> {
    #![allow(clippy::let_unit_value)]
    let () = util::AssertLess::<N, 65>::OK;
    let () = util::AssertDivisible::<N, 4>::OK;
    let () = util::AssertSplitExact::<M, { RawAttribute::TL_LEN }, N>::OK;
    super::ensure_space(M, N as u16, dst.len())?;
    let (tlv, rest) = util::split_array_mut::<_, M>(dst);
    let (tl, v) = util::split_array_exact_mut(tlv);
    RawAttribute::encode_type_length(attr, N as u16, tl);
    *v = f();
    Ok(rest)
}

#[inline]
pub fn decode_integer<T, F: FnOnce([u8; N]) -> T, const N: usize>(
    src: &[u8],
    f: F,
) -> Result<T, impl ErrorKind> {
    new_error!(
        LenMismatch { expected: u16, actual: u16 },
        InvalidParameter,
        "integer attribute requires a buffer of {expected} bytes, buffer of length {actual} provided",
    );
    src.try_into().map(f).map_err(|_| LenMismatch::new(N as u16, src.len() as u16))
}

new_int_attr!(IceControlled, Type::ICE_CONTROLLED, u64);
new_int_attr!(IceControlling, Type::ICE_CONTROLLING, u64);
new_int_attr!(Fingerprint, Type::FINGERPRINT, u32);
new_int_attr!(Priority, Type::PRIORITY, u32);
new_int_attr!(Lifetime, Type::LIFETIME, u32);

#[cfg(test)]
mod test {
    crate::new_int_attr!(TestAttr, crate::attribute::Type::MAPPED_ADDRESS, u32);
}
