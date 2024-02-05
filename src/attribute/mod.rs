use crate::{
    error::{new_error, StunError},
    header::TransactionId,
    parse::RawAttribute,
    util,
};

pub mod addr;
mod attr_enum;
mod change_request;
pub mod data;
pub mod empty;
pub mod error_code;
pub mod fixed;
pub mod integer;
pub mod password;
pub mod string;
mod r#type;
pub mod unknown;

pub use r#type::Type;
pub use rfc8445 as ice;
pub use rfc8489 as stun;
pub use rfc8656 as turn;
pub use string::{AsStr, Validated};
pub use unknown::UnknownAttribute;

pub mod rfc8489 {
    pub use super::{
        addr::{AlternateServer, MappedAddress, XorMappedAddress},
        error_code::ErrorCode,
        fixed::{MessageIntegrity, MessageIntegritySha256, UserHash},
        integer::Fingerprint,
        password::{PasswordAlgorithm, PasswordAlgorithms},
        string::{AlternateDomain, Nonce, Realm, Software, Username},
        unknown::UnknownAttributes,
    };
    pub mod parsed {
        pub use super::{AlternateServer, Fingerprint, MappedAddress, XorMappedAddress};
        use crate::attribute::{password, unknown, Validated};
        pub type ErrorCode<'a> = super::ErrorCode<Validated<&'a str, false, false, false>>;
        pub type AlternateDomain<'a> =
            super::AlternateDomain<Validated<&'a str, true, false, false>>;
        pub type Nonce<'a> = super::Nonce<Validated<&'a str, false, true, false>>;
        pub type Software<'a> = super::Software<Validated<&'a str, false, false, false>>;
        pub type Realm<'a> = super::Realm<Validated<&'a str, false, true, true>>;
        pub type Username<'a> = super::Username<Validated<&'a str, false, false, true>>;
        pub type MessageIntegrity<'a> =
            super::MessageIntegrity<&'a [u8; super::MessageIntegrity::<()>::LEN]>;
        pub type MessageIntegritySha256<'a> =
            super::MessageIntegritySha256<&'a [u8; super::MessageIntegritySha256::<()>::LEN]>;
        pub type UserHash<'a> = super::UserHash<&'a [u8; super::UserHash::<()>::LEN]>;
        pub type PasswordAlgorithm<'a> = super::PasswordAlgorithm<&'a [u8]>;
        pub type PasswordAlgorithms<'a> = super::PasswordAlgorithms<password::Parsed<'a>>;
        pub type UnknownAttributes<'a> = super::UnknownAttributes<unknown::Parsed<'a>>;
    }
}

pub mod rfc5780 {
    pub use super::change_request::ChangeRequest;
}

pub mod rfc8445 {
    pub use super::{
        empty::UseCandidate,
        integer::{IceControlled, IceControlling, Priority},
    };
}

pub mod rfc8656 {
    pub use super::{
        addr::{
            AdditionalAddressFamily, RequestedAddressFamily, XorPeerAddress, XorRelayedAddress,
        },
        data::Data,
        empty::DontFragment,
        error_code::AddressErrorCode,
        integer::Lifetime,
    };

    pub mod parsed {
        pub use super::Lifetime;
        pub type Data<'a> = super::Data<&'a [u8]>;

        crate::new_int_attr!(RequestedTransport, crate::attribute::Type::REQUESTED_TRANSPORT, u32);
    }
}

pub trait Attribute {
    fn attribute_type(&self) -> Type;
}

pub trait EncodeAttribute: Attribute {
    fn encoded_value_len(&self) -> u16;

    #[inline]
    fn encoded_len(&self) -> usize {
        total_len(self.encoded_value_len())
    }

    fn encode<'a>(
        &self,
        dst: &'a mut [u8],
        transaction_id: &TransactionId,
    ) -> Result<&'a mut [u8], StunError>;
}

pub trait DecodeAttribute<'d>: Attribute + Sized {
    fn decode(attr: Type, src: &'d [u8], transaction_id: &TransactionId)
        -> Result<Self, StunError>;
}

fn encode_variable_len<'a>(
    attr: Type,
    src: &[u8],
    dst: &'a mut [u8],
) -> Result<&'a mut [u8], StunError> {
    // ensuring no shenanigans
    let src = shrink_to_u16(src);
    let len = src.len() as u16;
    let total_len = total_len(len);
    ensure_space(total_len, len, dst.len())?;
    let (tlvp, rest) = dst.split_at_mut(total_len);
    let (v, pad) = encode_type_length(attr, len, tlvp).split_at_mut(src.len());
    v.copy_from_slice(src);
    pad.fill(0);
    Ok(rest)
}

#[inline]
fn encode_type_length(attr: Type, len: u16, dst: &mut [u8]) -> &mut [u8] {
    let (tl, rest) = util::split_array_mut(dst);
    RawAttribute::encode_type_length(attr, len, tl);
    rest
}

#[inline]
fn shrink_to_u16(src: &[u8]) -> &[u8] {
    &src[..(src.len() as u16) as usize]
}

#[inline]
fn total_len(len: u16) -> usize {
    RawAttribute::TL_LEN + len as usize + RawAttribute::padding(len) as usize
}

#[inline]
fn ensure_space(total_len: usize, len: u16, dst_len: usize) -> Result<(), StunError> {
    if dst_len >= total_len {
        Ok(())
    } else if dst_len >= RawAttribute::TL_LEN {
        Err(BufferTooSmallForValue::new(dst_len as u16, len).into())
    } else {
        Err(TypeLenTooBig.into())
    }
}

// Ignoring all MTU concerns here since IPv6 technically has jumbograms. The maximum length of a single value can be
// at most u16::MAX - MAX_PADDING_LEN - TL_LEN, since the length in the header must be the TLV padded length,
// so it has to be a multiple of 4, and fit in 2 bytes.
pub const MAX_VALUE_LEN: usize =
    u16::MAX as usize - RawAttribute::MAX_PADDING_LEN - RawAttribute::TL_LEN;

new_error!(TypeLenTooBig, BufferTooSmall, "buffer too small for the type-length part of TLV");
new_error!(
    BufferTooSmallForValue { rem: u16, len: u16 },
    BufferTooSmall,
    "buffer with {rem} bytes remaining is too small to hold the value of len {padded} ({len} without padding)",
    padded = RawAttribute::padded_len(*len),
);
new_error!(
    ValueTooLong { len: usize },
    ValueTooLong,
    "the value is {len} bytes, larger than the max value allowed ({MAX_VALUE_LEN})",
);

#[cfg(test)]
mod test {
    use super::{rfc8489::*, *};
    use crate::{
        test_data::{assert_ok, TEST_VECTOR},
        MessageParser,
    };

    #[test]
    fn test_iter() {
        let mut v = [core::mem::MaybeUninit::uninit(); 32];
        let msg = assert_ok!(
            MessageParser::from_complete_message(TEST_VECTOR[3].message, &mut v),
            "error parsing raw msg",
        );
        let id = TransactionId::new([0; 12]);
        let attributes = msg.iter().collect::<Result<Vec<attributes::Attributes>, _>>().unwrap();
        println!("{attributes:?}");
        let msg = assert_ok!(
            MessageParser::from_complete_message(TEST_VECTOR[4].message, &mut v),
            "error parsing raw msg",
        );
        let attributes = msg.iter().collect::<Result<Vec<attributes::Attributes>, _>>().unwrap();
        println!(
            "{attributes:?}, {}, {}",
            core::mem::size_of::<attributes::Attributes>(),
            core::mem::size_of::<Result<attributes::Attributes, StunError>>(),
        );
    }
}
