use crate::{
    attribute::{
        addr, ensure_space, total_len, AsStr, Attribute, DecodeAttribute, EncodeAttribute, Type,
        Validated as GenericValidated,
    },
    error::{new_error, ErrorKind, StunError},
    parse::RawAttribute,
    util, TransactionId,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressErrorCode<T = Validated<&'static str, true, true>> {
    family: addr::AddressFamily,
    code: ErrorCode<T>,
}

impl<T> AddressErrorCode<T> {
    pub const TYPE: Type = Type::ADDRESS_ERROR_CODE;

    #[inline]
    pub const fn new(family: addr::AddressFamily, code: ErrorCode<T>) -> Self {
        Self { family, code }
    }

    #[inline]
    pub fn family(&self) -> addr::AddressFamily {
        self.family
    }

    #[inline]
    pub fn code(&self) -> u16 {
        self.code.code
    }

    #[inline]
    pub fn reason_phrase(&self) -> &str
    where
        T: AsStr,
    {
        self.code.reason_phrase()
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.code.into_inner()
    }
}

impl<T> Attribute for AddressErrorCode<T> {
    #[inline]
    fn attribute_type(&self) -> Type {
        Self::TYPE
    }
}

impl<T: AsRef<str>, const Q: bool, const O: bool> EncodeAttribute
    for AddressErrorCode<Validated<T, Q, O>>
{
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        (CODE_LEN + self.reason_phrase().len()) as u16
    }

    #[inline]
    fn encode<'a>(&self, dst: &'a mut [u8], _: &TransactionId) -> Result<&'a mut [u8], StunError> {
        encode_error_code(
            Self::TYPE,
            self.code(),
            self.code.reason_phrase.as_validated_str(),
            |x| x | ((addr::from_family(self.family) as u32) << ADDR_SHIFT),
            dst,
        )
    }
}

impl<T: AsRef<str>> EncodeAttribute for AddressErrorCode<T> {
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        (CODE_LEN + self.reason_phrase().len()) as u16
    }

    #[inline]
    fn encode<'a>(&self, dst: &'a mut [u8], t: &TransactionId) -> Result<&'a mut [u8], StunError> {
        self.code
            .validate_reason()
            .and_then(|code| AddressErrorCode::new(self.family, code).encode(dst, t))
    }
}

impl<'d> DecodeAttribute<'d> for AddressErrorCode<Validated<&'d str, false, false>> {
    #[inline]
    fn decode(_: Type, src: &'d [u8], _: &TransactionId) -> Result<Self, StunError> {
        decode_error_code(src, |x| addr::into_family((x >> ADDR_SHIFT) as u8))
            .map(|(code, family)| Self::new(family, code))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ErrorCode<T = Validated<&'static str, true, true>> {
    code: u16,
    reason_phrase: T,
}

impl<T> ErrorCode<T> {
    pub const TYPE: Type = Type::ERROR_CODE;

    #[inline]
    pub fn new(code: u16, reason_phrase: T) -> Result<Self, StunError> {
        if (300..700).contains(&code) {
            return Ok(Self { code, reason_phrase });
        }
        let (class, number) = (code / 100, code % 100);
        Err(InvalidErrorCode { class: class as _, number: number as _ }.into())
    }

    #[inline]
    pub fn code(&self) -> u16 {
        self.code
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.reason_phrase
    }

    #[inline]
    pub fn reason_phrase(&self) -> &str
    where
        T: AsStr,
    {
        self.reason_phrase.as_str()
    }

    #[inline]
    pub fn validate_reason(&self) -> Result<ErrorCode<Validated<&str, false, false>>, StunError>
    where
        T: AsRef<str>,
    {
        let reason_phrase = self.reason_phrase().try_into()?;
        Ok(ErrorCode { code: self.code, reason_phrase })
    }
}

impl<'a, const Q: bool, const O: bool> ErrorCode<Validated<&'a str, Q, O>> {
    #[inline]
    pub const fn const_new(
        code: u16,
        reason_phrase: Validated<&'a str, Q, O>,
    ) -> Result<Self, impl ErrorKind> {
        if code >= 300 && code < 700 {
            return Ok(Self { code, reason_phrase });
        }
        let (class, number) = (code / 100, code % 100);
        Err(InvalidErrorCode { class: class as _, number: number as _ })
    }
}

impl<T> Attribute for ErrorCode<T> {
    #[inline]
    fn attribute_type(&self) -> Type {
        Self::TYPE
    }
}

impl<T: AsRef<str>, const Q: bool, const O: bool> EncodeAttribute
    for ErrorCode<Validated<T, Q, O>>
{
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        (CODE_LEN + self.reason_phrase().len()) as u16
    }

    #[inline]
    fn encode<'a>(&self, dst: &'a mut [u8], _: &TransactionId) -> Result<&'a mut [u8], StunError> {
        encode_error_code(
            Self::TYPE,
            self.code,
            self.reason_phrase.as_validated_str(),
            core::convert::identity,
            dst,
        )
    }
}

impl<T: AsRef<str>> EncodeAttribute for ErrorCode<T> {
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        (CODE_LEN + self.reason_phrase().len()) as u16
    }

    #[inline]
    fn encode<'a>(&self, dst: &'a mut [u8], t: &TransactionId) -> Result<&'a mut [u8], StunError> {
        self.validate_reason().and_then(|this| this.encode(dst, t))
    }
}

impl<'d> DecodeAttribute<'d> for ErrorCode<Validated<&'d str, false, false>> {
    #[inline]
    fn decode(_: Type, src: &'d [u8], _: &TransactionId) -> Result<Self, StunError> {
        enum Infallible {}
        impl From<Infallible> for StunError {
            fn from(value: Infallible) -> Self {
                match value {}
            }
        }
        decode_error_code(src, |_| Ok::<_, Infallible>(())).map(|(code, _)| code)
    }
}

fn encode_error_code<'a, F: FnOnce(u32) -> u32, const Q: bool, const O: bool>(
    t: Type,
    error_code: u16,
    reason_phrase: Validated<&str, Q, O>,
    f: F,
    dst: &'a mut [u8],
) -> Result<&'a mut [u8], StunError> {
    let reason_phrase = reason_phrase.as_str();
    let len = (CODE_LEN + reason_phrase.len()) as u16;
    let total_len = total_len(len);
    ensure_space(total_len, len, dst.len())?;
    let (attr, rest) = dst.split_at_mut(total_len);
    let (headers, vp) = util::split_array_mut::<_, { RawAttribute::TL_LEN + CODE_LEN }>(attr);
    let (tl, code) = util::split_array_exact_mut(headers);
    RawAttribute::encode_type_length(t, len, tl);
    let (class, number) = (error_code / 100, error_code % 100);
    *code = f(((class as u32) << 8) | number as u32).to_be_bytes();
    let (reason_buf, pad) = vp.split_at_mut(reason_phrase.len());
    reason_buf.copy_from_slice(reason_phrase.as_bytes());
    pad.fill(0);
    Ok(rest)
}

fn decode_error_code<T, E: Into<StunError>, F: FnOnce(u32) -> Result<T, E>>(
    src: &[u8],
    f: F,
) -> Result<(ErrorCode<Validated<&str, false, false>>, T), StunError> {
    if src.len() < CODE_LEN {
        new_error!(ErrorCodeTooBig, BufferTooSmall, "buffer too small for an error code");
        return Err(ErrorCodeTooBig.into());
    }
    let (&code, reason_phrase) = util::split_array_ref(src);
    let code = u32::from_be_bytes(code);
    let class = (code >> 8) & 0b111;
    let number = code & 0xFF;
    if !(3..6).contains(&class) || number > 99 {
        return Err(InvalidErrorCode { class: class as _, number: number as _ }.into());
    }
    let val = f(code).map_err(Into::into)?;
    let code = (class * 100 + number) as u16;
    let reason_phrase = Validated::try_from(reason_phrase)?;
    Ok((ErrorCode { code, reason_phrase }, val))
}

type Validated<T, const Q: bool, const O: bool> = GenericValidated<T, false, Q, O>;

const CODE_LEN: usize = 4;
const ADDR_SHIFT: u32 = u32::BITS - u8::BITS;

new_error!(
    InvalidErrorCode { class: u8, number: u8 },
    InvalidParameter,
    "error code invalid: class ({class}) must be between 3 and 6 and number ({number}) less than 100",
);

macro_rules! error_codes {
    ($(($num:literal, $konst:ident, $phrase:expr),)+) => {
        impl ErrorCode {
            $(pub const $konst: Self = Self { code: $num, reason_phrase: GenericValidated($phrase) };)+

            pub fn from_status_code(code: u16) -> Option<Self> {
                match code {
                    $($num => Some(Self::$konst),)+
                    _ => None,
                }
            }
        }
    };
}

// https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml#stun-parameters-6
error_codes! {
    (300, TRY_ALTERNATE, "Try Alternate"),
    (400, BAD_REQUEST, "Bad Request"),
    (401, UNAUTHENTICATED, "Unauthenticated"),
    (403, FORBIDDEN, "Forbidden"),
    (405, MOBILITY_FORBIDDEN, "Mobility Forbidden"),
    (420, UNKNOWN_ATTRIBUTE, "Unknown Attribute"),
    (437, ALLOCATION_MISMATCH, "Allocation Mismatch"),
    (438, STALE_NONCE, "Stale Nonce"),
    (440, UNSUPPORTED_ADDRESS_FAMILY, "Address Family not Supported"),
    (441, WRONG_CREDENTIALS, "Wrong Credentials"),
    (442, UNSUPPORTED_PROTOCOL, "Unsupported Transport Protocol"),
    (443, ADDRESS_FAMILY_MISMATCH, "Peer Address Family Mismatch"),
    (446, CONNECTION_EXISTS, "Connection Already Exists"),
    (447, CONNECTION_TIMEOUT, "Connection Timeout or Failure"),
    (486, QUOTA_REACHED, "Allocation Quota Reached"),
    (487, ROLE_CONFLICT, "Role Conflict"),
    (500, SERVER_ERROR, "Server Error"),
    (508, INSUFFICIENT_CAPACITY, "Insufficient Capacity"),
}
