use super::{Attribute, DecodeAttribute, EncodeAttribute, StunError, TransactionId, Type};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Data<T>(T);

impl<T> Data<T> {
    pub const TYPE: Type = Type::DATA;

    #[inline]
    pub const fn new(data: T) -> Self {
        Self(data)
    }

    #[inline]
    pub fn data(&self) -> &[u8]
    where
        T: AsRef<[u8]>,
    {
        self.0.as_ref()
    }
}

impl<T> Attribute for Data<T> {
    #[inline]
    fn attribute_type(&self) -> Type {
        Self::TYPE
    }
}

impl<T: AsRef<[u8]>> EncodeAttribute for Data<T> {
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        self.data().len() as u16
    }

    #[inline]
    fn encode<'a>(&self, dst: &'a mut [u8], _: &TransactionId) -> Result<&'a mut [u8], StunError> {
        super::encode_variable_len(Self::TYPE, self.data(), dst)
    }
}

impl<'d> DecodeAttribute<'d> for Data<&'d [u8]> {
    #[inline]
    fn decode(_: Type, src: &'d [u8], _: &TransactionId) -> Result<Self, StunError> {
        Ok(Self::new(src))
    }
}
