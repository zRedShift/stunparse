pub(crate) fn is_quoted_text(s: &str) -> bool {
    let mut state = State::Normal;
    for c in s.chars() {
        match state {
            State::Normal => match c {
                '\t' | ' '..='!' | '#'..='[' | ']'..='~' => {}
                '\r' => state = State::CarriageReturn,
                '\\' => state = State::QuotedPair,
                _ => {
                    if c.is_ascii() {
                        return false; // '\0'..='\x08' | '\n'..='\x0C' | '\x0E'..='\x1F' | '"' | '\x7F'
                    }
                }
            },
            State::CarriageReturn => match c {
                '\n' => state = State::WhiteSpace,
                _ => return false, // LF must appear after CR
            },
            State::WhiteSpace => match c {
                '\t' | ' ' => state = State::Normal,
                _ => return false, // WS must appear after LF
            },
            State::QuotedPair => {
                if c.is_ascii() && !matches!(c, '\n' | '\r') {
                    state = State::Normal;
                } else {
                    return false; // non-ascii utf-8 and CR/LF are not allowed
                }
            }
        }
    }
    matches!(state, State::Normal)
}

pub(crate) const fn is_quoted_text_ascii(s: &str) -> bool {
    let b = s.as_bytes();
    if !b.is_ascii() {
        return false;
    }
    let (mut index, len) = (0, b.len());
    let mut state = State::Normal;
    while index < len {
        let c = b[index];
        match state {
            State::Normal => match c {
                b'\t' | b' '..=b'!' | b'#'..=b'[' | b']'..=b'~' => {}
                b'\r' => state = State::CarriageReturn,
                b'\\' => state = State::QuotedPair,
                _ => return false, // '\0'..='\x08' | '\n'..='\x0C' | '\x0E'..='\x1F' | '"' | '\x7F'
            },
            State::CarriageReturn => match c {
                b'\n' => state = State::WhiteSpace,
                _ => return false, // LF must appear after CR
            },
            State::WhiteSpace => match c {
                b'\t' | b' ' => state = State::Normal,
                _ => return false, // WS must appear after LF
            },
            State::QuotedPair => match c {
                b'\n' | b'\r' => return false,
                _ => state = State::Normal,
            },
        }
        index += 1;
    }
    matches!(state, State::Normal)
}

enum State {
    Normal,
    CarriageReturn,
    WhiteSpace,
    QuotedPair,
}

#[cfg(test)]
mod test {
    use super::{is_quoted_text, is_quoted_text_ascii};

    static VALID: [&str; 20] = [
        "",
        "\u{21}",
        "\u{23}",
        "\u{5b}",
        "\u{5d}",
        "\u{7e}",
        "\u{80}",
        "\u{7ff}",
        "\u{f03f}",
        "\u{10ffff}",
        "\\\u{00}",
        "\\\u{09}",
        "\\\u{0b}",
        "\\\u{0c}",
        "\\\u{0e}",
        "\\\u{7f}",
        "\\abcdfg\\h",
        "\\abfg\\h\u{10ffff}",
        "hello world",
        " \u{0d}\u{0a}   hello",
    ];

    static INVALID: [&str; 4] = ["\\\u{0a}", "\\\u{0d}", "\\\u{8a}", " \u{0d} hello"];

    #[test]
    fn test_quoted_text() {
        for &valid in &VALID {
            assert!(is_quoted_text(valid), "\"{valid}\" should be valid quoted text");
        }

        for &invalid in &INVALID {
            assert!(!is_quoted_text(invalid), "\"{invalid}\" should not be valid quoted text");
        }
    }

    #[test]
    fn test_quoted_text_ascii() {
        for &valid in VALID.iter().filter(|s| s.is_ascii()) {
            assert!(is_quoted_text_ascii(valid), "\"{valid}\" should be valid quoted ascii text");
        }

        for &invalid in VALID.iter().filter(|s| !s.is_ascii()).chain(&INVALID) {
            assert!(
                !is_quoted_text_ascii(invalid),
                "\"{invalid}\" should not be valid quoted ascii text"
            );
        }
    }
}
