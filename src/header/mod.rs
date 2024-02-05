use crate::error::{new_error, StunError};

mod class;
mod method;
mod transaction_id;

pub use class::Class;
pub use method::Method;
pub use transaction_id::TransactionId;

pub struct Header {
    pub(crate) class: Class,
    pub(crate) method: Method,
    pub(crate) length: u16,
    pub(crate) magic_cookie: u32,
    pub(crate) transaction_id: TransactionId,
}

impl Header {
    pub const LEN: usize = 20;

    // todo
    pub const fn new(
        class: Class,
        method: Method,
        length: u16,
        transaction_id: TransactionId,
    ) -> Self {
        Self { class, method, length, transaction_id, magic_cookie: crate::MAGIC_COOKIE }
    }

    pub fn decode(src: &[u8; Self::LEN]) -> Result<Self, StunError> {
        let [m0, m1, l0, l1, c0, c1, c2, c3, t @ ..] = *src;
        let msg_type = u16::from_be_bytes([m0, m1]);
        let length = u16::from_be_bytes([l0, l1]);
        let magic_cookie = u32::from_be_bytes([c0, c1, c2, c3]);
        let transaction_id = TransactionId(t);
        let class = Class::from_msg_type(msg_type);
        let method = Method::from_msg_type(msg_type);
        if msg_type > 0x3FFF {
            new_error!(
                MsbNotZero { bits: u8 },
                InvalidParameter,
                "the 2 most significant bits of the STUN message ({bits:#04b}) are not set to zero",
            );
            return Err(MsbNotZero::new((msg_type >> 14) as u8).into());
        }
        if length % 4 != 0 {
            new_error!(
                InvalidLen { len: u16 },
                InvalidParameter,
                "the length of the attributes ({len}) is invalid. it must be multiple of 4"
            );
            return Err(InvalidLen::new(length).into());
        }
        Ok(Self { class, method, length, magic_cookie, transaction_id })
    }

    #[inline]
    pub fn encode(&self, src: &mut [u8; Self::LEN]) {
        src[..2].copy_from_slice(&self.msg_type().to_be_bytes());
        src[2..4].copy_from_slice(&self.length.to_be_bytes());
        src[4..8].copy_from_slice(&self.magic_cookie.to_be_bytes());
        src[8..].copy_from_slice(&self.transaction_id.0);
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
    pub fn length(&self) -> u16 {
        self.length
    }

    #[inline]
    pub fn magic_cookie(&self) -> u32 {
        self.magic_cookie
    }

    #[inline]
    pub fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    #[inline]
    pub fn msg_type(&self) -> u16 {
        self.method.into_msg_type() | self.class.into_msg_type()
    }

    #[inline]
    pub fn is_rfc3489(&self) -> bool {
        self.magic_cookie() != crate::MAGIC_COOKIE
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_data::*;

    #[test]
    fn test_decode() {
        let mut arr = [0; Header::LEN];
        for &Parts { header, header_parts, .. } in TEST_VECTOR {
            let h = assert_ok!(Header::decode(header), "error decoding header");
            h.encode(&mut arr);
            assert_eq!(&arr, header);
            assert_eq!(&h.msg_type().to_be_bytes(), header_parts.t);
            assert_eq!(&h.length.to_be_bytes(), header_parts.l);
            assert_eq!(&h.magic_cookie.to_be_bytes(), header_parts.c);
            assert_eq!(h.transaction_id.get(), header_parts.i);
        }
    }
}
