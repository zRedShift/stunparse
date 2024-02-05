#[macro_export]
macro_rules! new_text_attr {
    ($attr:ident, $codepoint:expr, $dns:tt, $quoted:tt, $opaque:tt) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $attr<T = $crate::attribute::Validated<&'static str, $dns, true, true>> {
            inner: T,
        }

        impl<T> $attr<T> {
            pub const TYPE: $crate::attribute::Type = $codepoint;

            #[inline]
            pub fn new(inner: T) -> Self {
                Self { inner }
            }

            #[inline]
            pub fn into_inner(self) -> T {
                self.inner
            }

            #[inline]
            pub fn as_str(&self) -> &str
            where
                T: $crate::attribute::AsStr,
            {
                self.inner.as_str()
            }

            #[inline]
            pub fn validate(
                &self,
            ) -> Result<$attr<$crate::attribute::Validated<&str, $dns, $quoted, $opaque>>, $crate::StunError>
            where
                T: ::core::convert::AsRef<str>,
            {
                self.as_str().try_into().map($attr::new)
            }
        }

        impl<T> $crate::attribute::Attribute for $attr<T> {
            #[inline]
            fn attribute_type(&self) -> $crate::attribute::Type {
                Self::TYPE
            }
        }

        $crate::new_text_attr!(private $attr, $dns, $quoted, $opaque);

        impl<T: ::core::convert::AsRef<str>> $crate::attribute::EncodeAttribute for $attr<T> {
            #[inline]
            fn encoded_value_len(&self) -> u16 {
                self.as_str().len() as u16
            }

            #[inline]
            fn encode<'a>(
                &self,
                dst: &'a mut [u8],
                t: &$crate::TransactionId,
            ) -> Result<&'a mut [u8], $crate::StunError> {
                self.validate().and_then(|this| this.encode(dst, t))
            }
        }

        impl<'d> $crate::attribute::DecodeAttribute<'d>
            for $attr<$crate::attribute::Validated<&'d str, $dns, $quoted, $opaque>>
        {
            #[inline]
            fn decode(
                _: $crate::attribute::Type,
                src: &'d [u8],
                _: &$crate::TransactionId,
            ) -> Result<Self, $crate::StunError> {
                $crate::attribute::Validated::try_from(src).map(Self::const_new)
            }
        }
    };
    (private $attr:ident, $dns:tt, false, false) => {
        $crate::new_text_attr!(private inner $attr, $dns, Q, O, const Q: bool, const O: bool,);
    };
    (private $attr:ident, $dns:tt,  false, true) => {
        $crate::new_text_attr!(private inner $attr, Q, $dns, true, const Q: bool,);
    };
    (private $attr:ident, $dns:tt, true, false) => {
        $crate::new_text_attr!(private inner $attr, $dns, true, O, const O: bool,);
    };
    (private $attr:ident, $dns:tt, true, true) => {
        $crate::new_text_attr!(private inner $attr, $dns, true, true,);
    };

    (private inner $attr:ident, $d:tt, $q:tt, $o:tt, $(const $konst:ident: bool,)*) => {
        impl<'a, $(const $konst: bool,)*> $attr<$crate::attribute::Validated<&'a str, $d, $q, $o>> {
            #[inline]
            pub const fn const_new(inner: $crate::attribute::Validated<&'a str, $d, $q, $o>) -> Self {
                Self { inner }
            }
        }

        impl<T: ::core::convert::AsRef<str>, $(const $konst: bool,)*> $crate::attribute::EncodeAttribute
            for $attr<$crate::attribute::Validated<T, $d, $q, $o>>
        {
            #[inline]
            fn encoded_value_len(&self) -> u16 {
                self.as_str().len() as u16
            }

            #[inline]
            fn encode<'a>(
                &self,
                dst: &'a mut [u8],
                _: &$crate::TransactionId,
            ) -> Result<&'a mut [u8], $crate::StunError> {
                $crate::attribute::encode_variable_len(Self::TYPE, self.as_str().as_bytes(), dst)
            }
        }
    };
}

use crate::attribute::Type;
new_text_attr!(Realm, Type::REALM, false, true, true);
new_text_attr!(Username, Type::USERNAME, false, false, true);
new_text_attr!(Nonce, Type::NONCE, false, true, false);
new_text_attr!(Software, Type::SOFTWARE, false, false, false);
new_text_attr!(AlternateDomain, Type::ALTERNATE_DOMAIN, true, false, false);

#[cfg(test)]
mod test {
    new_text_attr!(TestAttr, crate::attribute::Type::REALM, true, true, true);
}
