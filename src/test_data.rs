// STUN Test Vectors [`RFC5769`](https://datatracker.ietf.org/doc/html/rfc5769)

/// 2.1. Sample Request.
/// This request uses the following parameters:
/// Software name: "STUN test client" (without quotes)
/// `Username`: `evtj:h6vY` (without quotes)
/// Password: `VOkJxbRl1RmTxUk/WvJxBt` (without quotes)
pub static SAMPLE_REQUEST: [u8; 108] = [
    0x00, 0x01, 0x00, 0x58, // Request type and message length
    0x21, 0x12, 0xa4, 0x42, // Magic cookie
    0xb7, 0xe7, 0xa7, 0x01, // }
    0xbc, 0x34, 0xd6, 0x86, // }  Transaction ID
    0xfa, 0x87, 0xdf, 0xae, // }
    0x80, 0x22, 0x00, 0x10, // SOFTWARE attribute header
    0x53, 0x54, 0x55, 0x4e, // }
    0x20, 0x74, 0x65, 0x73, // }  User-agent...
    0x74, 0x20, 0x63, 0x6c, // }  ...name
    0x69, 0x65, 0x6e, 0x74, // }
    0x00, 0x24, 0x00, 0x04, // PRIORITY attribute header
    0x6e, 0x00, 0x01, 0xff, // } ICE priority value
    0x80, 0x29, 0x00, 0x08, // ICE-CONTROLLED attribute header
    0x93, 0x2f, 0xf9, 0xb1, // }  Pseudo-random tie breaker...
    0x51, 0x26, 0x3b, 0x36, // }   ...for ICE control
    0x00, 0x06, 0x00, 0x09, // `USERNAME` attribute header
    0x65, 0x76, 0x74, 0x6a, // }
    0x3a, 0x68, 0x36, 0x76, // }  `Username` (9 bytes) and padding (3 bytes)
    0x59, 0x20, 0x20, 0x20, // }
    0x00, 0x08, 0x00, 0x14, // MESSAGE-INTEGRITY attribute header
    0x9a, 0xea, 0xa7, 0x0c, // }
    0xbf, 0xd8, 0xcb, 0x56, // }
    0x78, 0x1e, 0xf2, 0xb5, // }  HMAC-SHA1 fingerprint
    0xb2, 0xd3, 0xf2, 0x49, // }
    0xc1, 0xb5, 0x71, 0xa2, // }
    0x80, 0x28, 0x00, 0x04, // FINGERPRINT attribute header
    0xe5, 0x7a, 0x3b, 0xcf, // CRC32 fingerprint
];

/// 2.2. Sample IPv4 Response.
/// This response uses the following parameter:
/// Password: `VOkJxbRl1RmTxUk/WvJxBt` (without quotes)
/// Software name: "test vector" (without quotes)
/// Mapped address: 192.0.2.1 port 32853
pub static SAMPLE_IPV4_RESPONSE: [u8; 80] = [
    0x01, 0x01, 0x00, 0x3c, // Response type and message length
    0x21, 0x12, 0xa4, 0x42, // Magic cookie
    0xb7, 0xe7, 0xa7, 0x01, // }
    0xbc, 0x34, 0xd6, 0x86, // }  Transaction ID
    0xfa, 0x87, 0xdf, 0xae, // }
    0x80, 0x22, 0x00, 0x0b, // SOFTWARE attribute header
    0x74, 0x65, 0x73, 0x74, // }
    0x20, 0x76, 0x65, 0x63, // }  UTF-8 server name
    0x74, 0x6f, 0x72, 0x20, // }
    0x00, 0x20, 0x00, 0x08, // XOR-MAPPED-ADDRESS attribute header
    0x00, 0x01, 0xa1, 0x47, // Address family (IPv4) and xor'd mapped port number
    0xe1, 0x12, 0xa6, 0x43, // Xor'd mapped IPv4 address
    0x00, 0x08, 0x00, 0x14, // MESSAGE-INTEGRITY header
    0x2b, 0x91, 0xf5, 0x99, // }
    0xfd, 0x9e, 0x90, 0xc3, // }
    0x8c, 0x74, 0x89, 0xf9, // } HMAC-SHA1 fingerprint
    0x2a, 0xf9, 0xba, 0x53, // }
    0xf0, 0x6b, 0xe7, 0xd7, // }
    0x80, 0x28, 0x00, 0x04, // FINGERPRINT attribute header
    0xc0, 0x7d, 0x4c, 0x96, // Reserved for CRC32 fingerprint
];

/// 2.3. Sample IPv6 Response.
/// This response uses the following parameter:
/// Password: `VOkJxbRl1RmTxUk/WvJxBt` (without quotes)
/// Software name: "test vector" (without quotes)
/// Mapped address: `2001:db8:1234:5678:11:2233:4455:6677` port 32853
pub static SAMPLE_IPV6_RESPONSE: [u8; 92] = [
    0x01, 0x01, 0x00, 0x48, //Response type and message length
    0x21, 0x12, 0xa4, 0x42, //   Magic cookie
    0xb7, 0xe7, 0xa7, 0x01, // }
    0xbc, 0x34, 0xd6, 0x86, // }  Transaction ID
    0xfa, 0x87, 0xdf, 0xae, // }
    0x80, 0x22, 0x00, 0x0b, //    SOFTWARE attribute header
    0x74, 0x65, 0x73, 0x74, // }
    0x20, 0x76, 0x65, 0x63, // }  UTF-8 server name
    0x74, 0x6f, 0x72, 0x20, // }
    0x00, 0x20, 0x00, 0x14, //    XOR-MAPPED-ADDRESS attribute header
    0x00, 0x02, 0xa1, 0x47, //    Address family (IPv6) and xor'd mapped port number
    0x01, 0x13, 0xa9, 0xfa, // }
    0xa5, 0xd3, 0xf1, 0x79, // }  Xor'd mapped IPv6 address
    0xbc, 0x25, 0xf4, 0xb5, // }
    0xbe, 0xd2, 0xb9, 0xd9, // }
    0x00, 0x08, 0x00, 0x14, //    MESSAGE-INTEGRITY attribute header
    0xa3, 0x82, 0x95, 0x4e, // }
    0x4b, 0xe6, 0x7b, 0xf1, // }
    0x17, 0x84, 0xc9, 0x7c, // }  HMAC-SHA1 fingerprint
    0x82, 0x92, 0xc2, 0x75, // }
    0xbf, 0xe3, 0xed, 0x41, // }
    0x80, 0x28, 0x00, 0x04, // FINGERPRINT attribute header
    0xc8, 0xfb, 0x0b, 0x4c, // CRC32 fingerprint
];

/// 2.4. Sample Request with Long-Term Authentication.
/// This request uses the following parameters:
/// `Username`: `"<U+30DE><U+30C8><U+30EA><U+30C3><U+30AF><U+30B9>"`
///       (without quotes) unaffected by `SASLprep` [`RFC4013`](https://datatracker.ietf.org/doc/html/rfc4013) processing
/// Password: `"The<U+00AD>M<U+00AA>tr<U+2168>"` and `TheMatrIX` (without
///       quotes) respectively before and after `SASLprep` processing
/// Nonce: `f//499k954d6OL34oL9FSTvy64sA` (without quotes)
/// Realm:  "example.org" (without quotes)
pub static SAMPLE_REQUEST_LONG_TERM_AUTH: [u8; 116] = [
    0x00, 0x01, 0x00, 0x60, // Request type and message length
    0x21, 0x12, 0xa4, 0x42, // Magic cookie
    0x78, 0xad, 0x34, 0x33, // }
    0xc6, 0xad, 0x72, 0xc0, // }  Transaction ID
    0x29, 0xda, 0x41, 0x2e, // }
    0x00, 0x06, 0x00, 0x12, // `USERNAME` attribute header
    0xe3, 0x83, 0x9e, 0xe3, // }
    0x83, 0x88, 0xe3, 0x83, // }
    0xaa, 0xe3, 0x83, 0x83, // } `Username` value (18 bytes) and padding (2 bytes)
    0xe3, 0x82, 0xaf, 0xe3, // }
    0x82, 0xb9, 0x00, 0x00, // }
    0x00, 0x15, 0x00, 0x1c, // NONCE attribute header
    0x66, 0x2f, 0x2f, 0x34, // }
    0x39, 0x39, 0x6b, 0x39, // }
    0x35, 0x34, 0x64, 0x36, // }
    0x4f, 0x4c, 0x33, 0x34, // } Nonce value
    0x6f, 0x4c, 0x39, 0x46, // }
    0x53, 0x54, 0x76, 0x79, // }
    0x36, 0x34, 0x73, 0x41, // }
    0x00, 0x14, 0x00, 0x0b, // REALM attribute header
    0x65, 0x78, 0x61, 0x6d, // }
    0x70, 0x6c, 0x65, 0x2e, // }  Realm value (11 bytes) and padding (1 byte)
    0x6f, 0x72, 0x67, 0x00, // }
    0x00, 0x08, 0x00, 0x14, // MESSAGE_INTEGRITY header
    0xf6, 0x70, 0x24, 0x65, // }
    0x6d, 0xd6, 0x4a, 0x3e, // }
    0x02, 0xb8, 0xe0, 0x71, // } HMAC-SHA1 fingerprint
    0x2e, 0x85, 0xc9, 0xa2, // }
    0x8c, 0xa8, 0x96, 0x66, // }
];

// [`RFC8489`](https://datatracker.ietf.org/doc/html/rfc8489)

/// B.1.  Sample Request with Long-Term Authentication with
/// MESSAGE-INTEGRITY-SHA256, PASSWORD-ALGORITHM and USER-HASH.
/// This request uses the following parameters:
/// User name: `"<U+30DE><U+30C8><U+30EA><U+30C3><U+30AF><U+30B9>"` (without
///     quotes) unaffected by OpaqueString [`RFC8265`](https://datatracker.ietf.org/doc/html/rfc8265) processing
/// Password: `"The<U+00AD>M<U+00AA>tr<U+2168>"` and `"TheMatrIX"` (without
///     quotes) respectively before and after OpaqueString [`RFC8265`](https://datatracker.ietf.org/doc/html/rfc8265)
///     processing
/// Nonce: `"obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA"` (without quotes)
/// Realm: "example.org" (without quotes)
pub static SAMPLE_REQUEST_LONG_TERM_AUTH_SHA256: [u8; 164] = [
    0x00, 0x01, 0x00, 0x90, //    Request type and message length
    0x21, 0x12, 0xa4, 0x42, //    Magic cookie
    0x78, 0xad, 0x34, 0x33, // }
    0xc6, 0xad, 0x72, 0xc0, // }  Transaction ID
    0x29, 0xda, 0x41, 0x2e, // }
    0x00, 0x1e, 0x00, 0x20, //    `USERHASH` attribute header
    0x4a, 0x3c, 0xf3, 0x8f, // }
    0xef, 0x69, 0x92, 0xbd, // }
    0xa9, 0x52, 0xc6, 0x78, // }
    0x04, 0x17, 0xda, 0x0f, // }  `Userhash` value (32 bytes)
    0x24, 0x81, 0x94, 0x15, // }
    0x56, 0x9e, 0x60, 0xb2, // }
    0x05, 0xc4, 0x6e, 0x41, // }
    0x40, 0x7f, 0x17, 0x04, // }
    0x00, 0x15, 0x00, 0x29, //    NONCE attribute header
    0x6f, 0x62, 0x4d, 0x61, // }
    0x74, 0x4a, 0x6f, 0x73, // }
    0x32, 0x41, 0x41, 0x41, // }
    0x43, 0x66, 0x2f, 0x2f, // }
    0x34, 0x39, 0x39, 0x6b, // }  Nonce value and padding (3 bytes)
    0x39, 0x35, 0x34, 0x64, // }
    0x36, 0x4f, 0x4c, 0x33, // }
    0x34, 0x6f, 0x4c, 0x39, // }
    0x46, 0x53, 0x54, 0x76, // }
    0x79, 0x36, 0x34, 0x73, // }
    0x41, 0x00, 0x00, 0x00, // }
    0x00, 0x14, 0x00, 0x0b, //    REALM attribute header
    0x65, 0x78, 0x61, 0x6d, // }
    0x70, 0x6c, 0x65, 0x2e, // }  Realm value (11 bytes) and padding (1 byte)
    0x6f, 0x72, 0x67, 0x00, // }
    0x00, 0x1d, 0x00, 0x04, //    PASSWORD-ALGORITHM attribute header
    0x00, 0x02, 0x00, 0x00, //    PASSWORD-ALGORITHM value (4 bytes)
    0x00, 0x1c, 0x00, 0x20, //    MESSAGE-INTEGRITY-SHA256 attribute header
    0xb5, 0xc7, 0xbf, 0x00, // }
    0x5b, 0x6c, 0x52, 0xa2, // }
    0x1c, 0x51, 0xc5, 0xe8, // }
    0x92, 0xf8, 0x19, 0x24, // }  HMAC-SHA256 value
    0x13, 0x62, 0x96, 0xcb, // }
    0x92, 0x7c, 0x43, 0x14, // }
    0x93, 0x09, 0x27, 0x8c, // }
    0xc6, 0x51, 0x8e, 0x65, // }
];

macro_rules! attr_array {
    ($s:ident, $(($v:literal, $p:literal)),+$(,)?) => {{
        static ATTRS: &[AttributeParts] = &{
            let mut attrs = parse_init(&$s).attributes;
            let arr = [
                $({
                    let part;
                    (part, attrs) = process_attr(attrs, $v, $p);
                    part
                },)+
            ];
            assert!(attrs.is_empty());
            arr
        };
        let mut parts = parse_init(&$s);
        parts.attr_parts = &ATTRS;
        parts
    }};
}

pub static TEST_VECTOR: &[Parts] = &[
    attr_array!(SAMPLE_REQUEST, (16, 0), (4, 0), (8, 0), (9, 3), (20, 0), (4, 0)),
    attr_array!(SAMPLE_IPV4_RESPONSE, (11, 1), (8, 0), (20, 0), (4, 0),),
    attr_array!(SAMPLE_IPV6_RESPONSE, (11, 1), (20, 0), (20, 0), (4, 0),),
    attr_array!(SAMPLE_REQUEST_LONG_TERM_AUTH, (18, 2), (28, 0), (11, 1), (20, 0),),
    attr_array!(SAMPLE_REQUEST_LONG_TERM_AUTH_SHA256, (32, 0), (41, 3), (11, 1), (4, 0), (32, 0),),
];

#[cfg(test)]
macro_rules! assert_ok {
    ($res:expr, $info:literal $(,)?) => {{
        match $res {
            Ok(ok) => ok,
            Err(err) => panic!(concat!($info, ": {err} ({err:?})"), err = err),
        }
    }};
}
#[cfg(test)]
pub(crate) use assert_ok;

use crate::util::split_array_ref;

pub struct Parts {
    pub message: &'static [u8],
    pub header: &'static [u8; 20],
    pub attributes: &'static [u8],
    pub header_parts: HeaderParts,
    pub attr_parts: &'static [AttributeParts],
}

const fn parse_init(message: &'static [u8]) -> Parts {
    let (header, attributes) = split_array_ref(message);
    let header_parts = parse_header(header);
    Parts { message, header, attributes, header_parts, attr_parts: &[] }
}

#[derive(Copy, Clone)]
pub struct HeaderParts {
    pub t: &'static [u8; 2],
    pub l: &'static [u8; 2],
    pub c: &'static [u8; 4],
    pub i: &'static [u8; 12],
}

const fn parse_header(s: &'static [u8; 20]) -> HeaderParts {
    let (t, s) = split_array_ref(s);
    let (l, s) = split_array_ref(s);
    let (c, s) = split_array_ref(s);
    let (i, _) = split_array_ref(s);
    HeaderParts { t, l, c, i }
}

pub struct AttributeParts {
    pub t: &'static [u8; 2],
    pub l: &'static [u8; 2],
    pub v: &'static [u8],
    pub p: &'static [u8],
    pub a: &'static [u8],
}

const fn process_attr(s: &'static [u8], len: usize, pad: usize) -> (AttributeParts, &'static [u8]) {
    let (a, rest) = s.split_at(4 + len + pad);
    let (t, s) = split_array_ref(a);
    let (l, s) = split_array_ref(s);
    let (v, p) = s.split_at(len);
    (AttributeParts { t, l, v, p, a }, rest)
}
