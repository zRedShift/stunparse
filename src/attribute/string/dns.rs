pub(crate) const fn validate_domain_name(b: &[u8]) -> Result<&str, InvalidDnsName> {
    if !matches!(b.len(), 1..=MAX_NAME_LENGTH) {
        return Err(InvalidDnsName);
    }
    let (mut index, mut curr, len) = (0, 0, b.len());
    use State::*;
    let mut state = Next;
    while index < len {
        (state, curr) = match b[index] {
            b'-' => match state {
                Subsequent | NumericOnly | Hyphen => (Hyphen, curr + 1),
                _ => return Err(InvalidDnsName),
            },
            b'.' => match state {
                Subsequent => (Next, 0),
                NumericOnly => (NextAfterNumericOnly, 0),
                _ => return Err(InvalidDnsName),
            },
            b'0'..=b'9' => (
                match state {
                    Next | NextAfterNumericOnly | NumericOnly => NumericOnly,
                    Subsequent | Hyphen => Subsequent,
                },
                curr + 1,
            ),
            b'A'..=b'Z' | b'a'..=b'z' => (Subsequent, curr + 1),
            _ => return Err(InvalidDnsName),
        };
        if curr > MAX_LABEL_LENGTH {
            return Err(InvalidDnsName);
        }
        index += 1;
    }
    match state {
        Next | Subsequent => Ok(unsafe { core::str::from_utf8_unchecked(b) }),
        NumericOnly | Hyphen | NextAfterNumericOnly => Err(InvalidDnsName),
    }
}

enum State {
    Next,
    Subsequent,
    NumericOnly,
    Hyphen,
    NextAfterNumericOnly,
}

const MAX_LABEL_LENGTH: usize = 63;
pub const MAX_NAME_LENGTH: usize = 253;

crate::error::new_error!(InvalidDnsName, InvalidParameter, "invalid dns name");

#[cfg(test)]
mod test {
    use super::*;

    const fn len_gen<const N: usize>(dots: &[u8]) -> [u8; N] {
        let (mut x, mut i, mut j) = ([b'a'; N], 0, 0);
        while i < dots.len() {
            j += dots[i] as usize;
            x[j] = b'.';
            i += 1;
            j += 1;
        }
        x
    }
    static VALID: [&[u8]; 21] = [
        b"example.com",
        b"subdomain.example.com",
        b"www.subdomain.example.com",
        b"xn--h1alffa9f.xn--p1ai",      // Punycode for россия.рф
        b"xn--kxae4bafwg.xn--pxaix.gr", // Punycode for ουτοπία.δπθ.gr
        b"xn--clchc0ea0b2g2a9gcd.xn--vermgensberatung-pwb", // Punycode for சிங்கப்பூர்.vermögensberatung
        b"a.label.with.dashes.com",
        b"a--label--with--double--dashes.com",
        b"label123.abc",
        b"a123.label.with.numbers.com",
        b"a-b-c-d-e-f-g-h-i-j-k-l-m-n-o-p-q-r-s-t-u-v-w-x-y-z.com",
        b"localhost",
        b"localhost.",
        b"localhost.com.",
        b"mdns-name.local.",
        b"mailserver.example",
        b"666mydomain.com",
        b"666.mydomain.com",
        b"mydomain666",
        &len_gen::<192>(&[63, 63, 63]),
        &len_gen::<253>(&[63, 63, 63]),
    ];

    static INVALID: [&[u8]; 30] = [
        b"label_underscore.com",
        b"1.2.3.4",
        b"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        b"2001:db8::1",
        &len_gen::<64>(&[]),
        &len_gen::<254>(&[]),
        &len_gen::<254>(&[63, 63, 63]),
        "россия.рф".as_bytes(),
        "ουτοπία.δπθ.gr".as_bytes(),
        "சிங்கப்பூர்.vermögensberatung".as_bytes(),
        b"~",
        b"\x80",
        "\u{80}".as_bytes(),
        b"",
        b".",
        b"..",
        b".localhost",
        b"..localhost",
        b"localhost..",
        b"example..com",
        b"example.-com",
        b"example.com-",
        b"example.-.com",
        b"ex_ample.com",
        b"example.com_",
        b"example.com-",
        b"example._.com",
        b"example..com",
        b".example.com",
        b"mydomain.666",
    ];

    #[test]
    fn test_dns_validation() {
        for &valid in VALID.iter().filter(|s| s.is_ascii()) {
            assert!(
                validate_domain_name(valid).is_ok(),
                "\"{:?}\" should be valid domain name",
                core::str::from_utf8(valid),
            );
        }

        for &invalid in VALID.iter().filter(|s| !s.is_ascii()).chain(&INVALID) {
            assert!(
                validate_domain_name(invalid).is_err(),
                "\"{:?}\" should not be valid domain name",
                core::str::from_utf8(invalid),
            );
        }
    }
}
