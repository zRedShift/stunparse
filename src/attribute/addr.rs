use crate::{
    attribute::{integer, Type, TypeLenTooBig},
    error::{new_error, StunError},
    header::TransactionId,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    parse::RawAttribute,
    util, MAGIC_COOKIE, MAGIC_COOKIE_BYTES,
};

#[macro_export]
macro_rules! new_addr_attr {
    ($attr:ident, $codepoint:expr) => {
        new_addr_attr!($attr, $codepoint, _, ());
    };
    ($attr:ident, $codepoint:expr, xor) => {
        new_addr_attr!($attr, $codepoint, transaction_id, transaction_id);
    };
    ($attr:ident, $codepoint:expr, $t:tt, $xor:tt) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $attr($crate::net::SocketAddr);

        impl $attr {
            pub const TYPE: $crate::attribute::Type = $codepoint;

            #[inline]
            pub const fn new(addr: $crate::net::SocketAddr) -> Self {
                Self(addr)
            }

            #[inline]
            pub fn addr(&self) -> &$crate::net::SocketAddr {
                &self.0
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
                $crate::attribute::addr::encoded_value_len(&self.0)
            }

            #[inline]
            fn encode<'a>(
                &self,
                dst: &'a mut [u8],
                $t: &$crate::TransactionId,
            ) -> Result<&'a mut [u8], $crate::StunError> {
                $crate::attribute::addr::encode(Self::TYPE, &self.0, dst, $xor)
            }
        }

        impl $crate::attribute::DecodeAttribute<'_> for $attr {
            #[inline]
            fn decode(
                _: $crate::attribute::Type,
                src: &[u8],
                $t: &$crate::TransactionId,
            ) -> Result<Self, $crate::StunError> {
                $crate::attribute::addr::decode(src, $xor).map(Self)
            }
        }
    };
}

new_addr_attr!(MappedAddress, Type::MAPPED_ADDRESS);
new_addr_attr!(AlternateServer, Type::ALTERNATE_SERVER);
new_addr_attr!(XorMappedAddress, Type::XOR_MAPPED_ADDRESS, xor);
new_addr_attr!(XorPeerAddress, Type::XOR_PEER_ADDRESS, xor);
new_addr_attr!(XorRelayedAddress, Type::XOR_RELAYED_ADDRESS, xor);

pub fn encode<'a, X: OptXor>(
    t: Type,
    addr: &SocketAddr,
    dst: &'a mut [u8],
    xor: X,
) -> Result<&'a mut [u8], StunError> {
    const TLV_AND_HEADER: usize = RawAttribute::TL_LEN + HEADER_LEN;
    #[cold]
    fn error(is_v6: bool, len: usize) -> StunError {
        if len < RawAttribute::TL_LEN {
            TypeLenTooBig.into()
        } else if len < TLV_AND_HEADER {
            HeaderTooBig.into()
        } else {
            IpLenMismatch::new(is_v6, (len - TLV_AND_HEADER) as u16).into()
        }
    }
    macro_rules! socket_addr {
        ($sock:ident, $addr:ident, $family:ident, $len:ident) => {{
            const TOTAL_LEN: usize = TLV_AND_HEADER + $len;
            const VALUE_LEN: usize = HEADER_LEN + $len;
            if dst.len() < TOTAL_LEN {
                return Err(error($len == IPV6_LEN, dst.len()));
            }
            let (tlv, rest) = util::split_array_mut::<_, TOTAL_LEN>(dst);
            let (tl, v): (_, &mut [u8; VALUE_LEN]) = util::split_array_exact_mut(tlv);
            RawAttribute::encode_type_length(t, VALUE_LEN as u16, tl);
            let (header, ip) = util::split_array_exact_mut(v);
            encode_header($family, $sock.port(), header, xor);
            *ip = $sock.ip().octets();
            xor.$addr(ip);
            rest
        }};
    }
    Ok(match addr {
        SocketAddr::V4(v4) => socket_addr!(v4, ipv4, FAMILY_IPV4, IPV4_LEN),
        SocketAddr::V6(v6) => socket_addr!(v6, ipv6, FAMILY_IPV6, IPV6_LEN),
    })
}

fn encode_header<X: OptXor>(
    family: u8,
    mut port: u16,
    [z, f, p @ ..]: &mut [u8; HEADER_LEN],
    xor: X,
) {
    xor.port(&mut port);
    *z = 0;
    *f = family;
    *p = port.to_be_bytes();
}

pub fn decode<X: OptXor>(src: &[u8], xor: X) -> Result<SocketAddr, StunError> {
    if src.len() < HEADER_LEN {
        return Err(HeaderTooBig.into());
    }
    let (&[_, family, port @ ..], ip) = util::split_array_ref::<_, HEADER_LEN>(src);
    let mut port = u16::from_be_bytes(port);
    xor.port(&mut port);
    Ok(match into_family(family)? {
        AddressFamily::IPv4 => {
            let mut ip = ip.try_into().map_err(|_| IpLenMismatch::new(false, ip.len() as _))?;
            xor.ipv4(&mut ip);
            (Ipv4Addr::from(ip), port).into()
        }
        AddressFamily::IPv6 => {
            let mut ip = ip.try_into().map_err(|_| IpLenMismatch::new(true, ip.len() as _))?;
            xor.ipv6(&mut ip);
            (Ipv6Addr::from(ip), port).into()
        }
    })
}

const fn encoded_value_len(addr: &SocketAddr) -> u16 {
    match addr {
        SocketAddr::V4(_) => (HEADER_LEN + IPV4_LEN) as u16,
        SocketAddr::V6(_) => (HEADER_LEN + IPV6_LEN) as u16,
    }
}

const HEADER_LEN: usize = 4;
const FAMILY_IPV4: u8 = 0x01;
const IPV4_LEN: usize = 4;
const FAMILY_IPV6: u8 = 0x02;
const IPV6_LEN: usize = 16;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    IPv4,
    IPv6,
}

#[macro_export]
macro_rules! new_addr_family_attr {
    ($attr:ident, $codepoint:expr$(,)?) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $attr($crate::attribute::addr::AddressFamily);

        impl $attr {
            pub const TYPE: $crate::attribute::Type = $codepoint;

            #[inline]
            pub const fn new(family: $crate::attribute::addr::AddressFamily) -> Self {
                Self(family)
            }

            #[inline]
            pub fn family(&self) -> $crate::attribute::addr::AddressFamily {
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
                ::core::mem::size_of::<u32>() as u16
            }

            #[inline]
            fn encode<'a>(
                &self,
                dst: &'a mut [u8],
                _: &$crate::TransactionId,
            ) -> Result<&'a mut [u8], $crate::StunError> {
                $crate::attribute::addr::encode_family(Self::TYPE, self.0, dst)
            }
        }

        impl $crate::attribute::DecodeAttribute<'_> for $attr {
            #[inline]
            fn decode(
                _: $crate::attribute::Type,
                src: &[u8],
                _: &$crate::TransactionId,
            ) -> Result<Self, $crate::StunError> {
                $crate::attribute::addr::decode_family(src).map(Self)
            }
        }
    };
}

new_addr_family_attr!(AdditionalAddressFamily, Type::ADDITIONAL_ADDRESS_FAMILY);
new_addr_family_attr!(RequestedAddressFamily, Type::REQUESTED_ADDRESS_FAMILY);

#[inline]
pub fn decode_family(src: &[u8]) -> Result<AddressFamily, StunError> {
    let [f, _, _, _] = src else {
        new_error!(
            LenMismatch { actual: usize },
            InvalidParameter,
            "address family attribute requires a buffer of size 4, buffer of length {actual} provided",
        );
        return Err(LenMismatch::new(src.len()).into());
    };
    Ok(into_family(*f)?)
}

#[inline]
pub fn encode_family(
    t: Type,
    family: AddressFamily,
    dst: &mut [u8],
) -> Result<&mut [u8], StunError> {
    const FAMILY_LEN: usize = 4;
    const TOTAL_LEN: usize = RawAttribute::TL_LEN + FAMILY_LEN;
    integer::encode_integer::<_, FAMILY_LEN, TOTAL_LEN>(t, dst, || {
        (from_family(family) as u32).to_le_bytes()
    })
}

#[inline]
pub(crate) fn from_family(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::IPv4 => FAMILY_IPV4,
        AddressFamily::IPv6 => FAMILY_IPV6,
    }
}

#[inline]
pub(crate) fn into_family(f: u8) -> Result<AddressFamily, InvalidFamily> {
    match f {
        FAMILY_IPV4 => Ok(AddressFamily::IPv4),
        FAMILY_IPV6 => Ok(AddressFamily::IPv6),
        _ => Err(InvalidFamily::new(f)),
    }
}

new_error!(HeaderTooBig, BufferTooSmall, "buffer too small for an address attribute header");
new_error!(
    IpLenMismatch { is_v6: bool, actual: u16 },
    BufferTooSmall,
    "ipv{family} requires a buffer of {expected} bytes, buffer of length {actual} provided",
    family = if *is_v6 { 6 } else { 4 },
    expected = if *is_v6 { IPV6_LEN } else { IPV4_LEN },
);
new_error!(
    InvalidFamily { family: u8 },
    InvalidParameter,
    "family {family:#04x} is invalid. only {FAMILY_IPV4:#04x} (ipv4) and {FAMILY_IPV6:#04x} (ipv6) are supported",
);

pub trait OptXor: private::Sealed + Copy + Sized {
    fn port(self, _: &mut u16) {}
    fn ipv4(self, _: &mut [u8; IPV4_LEN]) {}
    fn ipv6(self, _: &mut [u8; IPV6_LEN]) {}
}

impl OptXor for Option<&TransactionId> {
    fn port(self, port: &mut u16) {
        if let Some(t) = self {
            t.port(port)
        }
    }
    fn ipv4(self, ip: &mut [u8; IPV4_LEN]) {
        if let Some(t) = self {
            t.ipv4(ip)
        }
    }

    fn ipv6(self, ip: &mut [u8; IPV6_LEN]) {
        if let Some(t) = self {
            t.ipv6(ip)
        }
    }
}

impl OptXor for &TransactionId {
    fn port(self, port: &mut u16) {
        const PORT_XOR: u16 = (MAGIC_COOKIE >> 16) as u16;
        *port ^= PORT_XOR
    }

    fn ipv4(self, ip: &mut [u8; IPV4_LEN]) {
        for (ip, &xor) in ip.iter_mut().zip(&MAGIC_COOKIE_BYTES) {
            *ip ^= xor;
        }
    }

    fn ipv6(self, ip: &mut [u8; IPV6_LEN]) {
        let magic: &mut [u8; MAGIC_COOKIE_BYTES.len()];
        let transaction: &mut [u8; TransactionId::LEN];
        (magic, transaction) = util::split_array_exact_mut(ip);
        for (ip, &xor) in magic.iter_mut().zip(&MAGIC_COOKIE_BYTES) {
            *ip ^= xor;
        }
        for (ip, &xor) in transaction.iter_mut().zip(&self.0) {
            *ip ^= xor;
        }
    }
}

impl OptXor for () {}

mod private {
    use crate::TransactionId;

    pub trait Sealed {}

    impl Sealed for () {}
    impl Sealed for &TransactionId {}
    impl Sealed for Option<&TransactionId> {}
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        attribute::{DecodeAttribute, EncodeAttribute},
        test_data::*,
        MessageParser,
    };

    fn sockets() -> [SocketAddr; 2] {
        [
            "192.0.2.1:32853".parse().unwrap(),
            "[2001:db8:1234:5678:11:2233:4455:6677]:32853".parse().unwrap(),
        ]
    }

    #[test]
    fn test_parse() {
        let mut v = [core::mem::MaybeUninit::uninit(); 32];
        let mut buf = [0; IPV6_LEN + HEADER_LEN + RawAttribute::TL_LEN];
        for (parts, test_addr) in TEST_VECTOR[1..=2].iter().zip(sockets()) {
            let msg = assert_ok!(
                MessageParser::from_complete_message(parts.message, &mut v),
                "error parsing raw msg",
            );
            let item = msg.iter_raw().nth(1).expect("2nd attribute");
            assert_eq!(item.attr, XorMappedAddress::TYPE);
            let addr = assert_ok!(
                XorMappedAddress::decode(XorMappedAddress::TYPE, item.value, msg.transaction_id()),
                "error decoding xor mapped addr",
            );
            assert_eq!(addr.addr(), &test_addr);
            let remaining = assert_ok!(
                addr.encode(&mut buf, msg.transaction_id()),
                "error encoding xor mapped addr"
            );
            let remaining = remaining.len();
            let written_len = buf.len() - remaining;
            assert_eq!(written_len, addr.encoded_len());
            let expected = parts.attr_parts[1].a;
            assert_eq!(&buf[..written_len], expected);
        }
    }

    mod private {
        crate::new_addr_attr!(TestAttr1, crate::attribute::Type::MAPPED_ADDRESS);
        crate::new_addr_family_attr!(TestAttr2, crate::attribute::Type::MAPPED_ADDRESS);
    }
}
