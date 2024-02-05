#[macro_export]
macro_rules! define_attribute_enum {
    ($attr:ident<$t:lifetime>, [$($variant:ident$(<$l:lifetime>)?,)+]) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $attr<$t> {
            $($variant($variant$(<$l>)?),)+
            UnknownAttribute($crate::attribute::UnknownAttribute<'a>),
        }

        $(impl <'a> ::core::convert::From<$variant$(<$l>)?> for $attr<'a> {
            #[inline]
            fn from(v: $variant$(<$l>)?) -> Self {
                Self::$variant(v)
            }
        })+

        impl<'a> ::core::convert::From<$crate::attribute::UnknownAttribute<'a>> for $attr<'a> {
            #[inline]
            fn from(v: $crate::attribute::UnknownAttribute<'a>) -> Self {
                Self::UnknownAttribute(v)
            }
        }


        impl<'a> $crate::attribute::Attribute for $attr<'a> {
            #[inline]
            fn attribute_type(&self) -> $crate::attribute::Type {
                match self {
                    $(Self::$variant(_) => $variant::TYPE,)+
                    Self::UnknownAttribute(attr) => attr.attribute_type(),
                }
            }
        }

        impl <'b> $crate::attribute::EncodeAttribute for $attr<'b> {
            #[inline]
            fn encoded_value_len(&self) -> u16 {
                match self {
                    $(Self::$variant(attr) => attr.encoded_value_len(),)+
                    Self::UnknownAttribute(attr) => attr.encoded_value_len(),
                }
            }

            fn encode<'a>(
                &self,
                dst: &'a mut [u8],
                transaction_id: &$crate::TransactionId,
            ) -> Result<&'a mut [u8], $crate::StunError> {
                match self {
                    $(Self::$variant(attr) => attr.encode(dst, transaction_id),)+
                    Self::UnknownAttribute(attr) => attr.encode(dst, transaction_id),
                }
            }
        }

        impl<'d> $crate::attribute::DecodeAttribute<'d> for $attr<'d> {
            fn decode(
                attr: $crate::attribute::Type,
                src: &'d [u8],
                transaction_id: &$crate::TransactionId,
            ) -> Result<Self, $crate::StunError> {
                match attr {
                    $($variant::TYPE => $variant::decode(attr, src, transaction_id).map(Self::$variant),)+
                    _ => $crate::attribute::UnknownAttribute::decode(attr, src, transaction_id).map(Self::UnknownAttribute),
                }
            }
        }
    };
}
