use super::{integer, Attribute, DecodeAttribute, EncodeAttribute, StunError, TransactionId, Type};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChangeRequest(Request);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Request {
    None = 0x0,
    Port = 0x2,
    Ip = 0x4,
    Both = 0x2 | 0x4,
}

impl ChangeRequest {
    pub const TYPE: Type = Type::CHANGE_REQUEST;

    #[inline]
    pub const fn new(ip: bool, port: bool) -> Self {
        Self(match (ip, port) {
            (false, false) => Request::None,
            (false, true) => Request::Port,
            (true, false) => Request::Ip,
            (true, true) => Request::Both,
        })
    }

    #[inline]
    pub fn ip(&self) -> bool {
        matches!(self.0, Request::Ip | Request::Both)
    }

    #[inline]
    pub fn port(&self) -> bool {
        matches!(self.0, Request::Port | Request::Both)
    }
}

impl Attribute for ChangeRequest {
    #[inline]
    fn attribute_type(&self) -> Type {
        Self::TYPE
    }
}

impl EncodeAttribute for ChangeRequest {
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        LEN as _
    }

    #[inline]
    fn encode<'a>(&self, dst: &'a mut [u8], _: &TransactionId) -> Result<&'a mut [u8], StunError> {
        integer::encode_integer::<_, LEN, TOTAL_LEN>(Self::TYPE, dst, || {
            (self.0 as u32).to_be_bytes()
        })
    }
}

impl DecodeAttribute<'_> for ChangeRequest {
    #[inline]
    fn decode(_: Type, src: &[u8], _: &TransactionId) -> Result<Self, StunError> {
        let x = integer::decode_integer(src, u32::from_be_bytes)?;
        Ok(Self::new(x & 0x4 != 0, x & 0x2 != 0))
    }
}

const LEN: usize = core::mem::size_of::<u32>();
const TOTAL_LEN: usize = LEN + super::RawAttribute::TL_LEN;
