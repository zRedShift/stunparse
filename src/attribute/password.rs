use super::{
    new_error, util, Attribute, DecodeAttribute, EncodeAttribute, RawAttribute, StunError,
    TransactionId, Type,
};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PasswordAlgorithms<T, U = ()> {
    inner: T,
    _p: core::marker::PhantomData<U>,
}

impl<T, U> PasswordAlgorithms<T, U> {
    pub const TYPE: Type = Type::PASSWORD_ALGORITHMS;

    #[inline]
    pub const fn new(inner: T) -> Self {
        Self { inner, _p: core::marker::PhantomData }
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Parsed<'a>(&'a [u8]);

impl<'a> PasswordAlgorithms<Parsed<'a>> {
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.inner.0
    }

    #[inline]
    pub fn iter(&self) -> PasswordAlgorithmIter {
        PasswordAlgorithmIter(self.inner.0)
    }
}

#[derive(Clone)]
pub struct PasswordAlgorithmIter<'a>(&'a [u8]);

impl<'a> Iterator for PasswordAlgorithmIter<'a> {
    type Item = PasswordAlgorithm<&'a [u8]>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        next_alg(&mut self.0).unwrap_or_default()
    }
}

impl<T, U> Attribute for PasswordAlgorithms<T, U> {
    fn attribute_type(&self) -> Type {
        Self::TYPE
    }
}

impl<'d> DecodeAttribute<'d> for PasswordAlgorithms<Parsed<'d>> {
    fn decode(_: Type, src: &'d [u8], _: &TransactionId) -> Result<Self, StunError> {
        let mut slice = src;
        new_error!(PassAlgoBadHeader, InvalidParameter, "bad password algorithm header");
        new_error!(PassAlgoBadLen, InvalidParameter, "bad password algorithm parameter length");
        loop {
            return match next_alg(&mut slice) {
                Ok(Some(_)) => continue,
                Ok(None) => Ok(Self::new(Parsed(src))),
                Err(false) => Err(PassAlgoBadHeader.into()),
                Err(true) => Err(PassAlgoBadLen.into()),
            };
        }
    }
}

impl<'b> EncodeAttribute for PasswordAlgorithms<Parsed<'b>> {
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        self.as_bytes().len() as u16
    }

    #[inline]
    fn encode<'a>(&self, dst: &'a mut [u8], _: &TransactionId) -> Result<&'a mut [u8], StunError> {
        super::encode_variable_len(Self::TYPE, self.as_bytes(), dst)
    }
}

impl<U: AsRef<[u8]>, T: AsRef<[PasswordAlgorithm<U>]>> EncodeAttribute
    for PasswordAlgorithms<T, U>
{
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        value_len(self.inner.as_ref())
    }

    fn encode<'a>(&self, dst: &'a mut [u8], t: &TransactionId) -> Result<&'a mut [u8], StunError> {
        let algorithms = self.inner.as_ref();
        let len = value_len(algorithms);
        let total_len = super::total_len(len);
        super::ensure_space(total_len, len, dst.len())?;
        let (tlvp, rest) = dst.split_at_mut(total_len);
        let (tl, mut vp) = util::split_array_mut(tlvp);
        RawAttribute::encode_type_length(Self::TYPE, len, tl);
        for alg in algorithms {
            vp = alg.encode(vp, t)?;
        }
        new_error!(
            PassAlgoLenMismatch,
            InvalidParameter,
            "something went wrong encoding password algorithms",
        );
        if !vp.is_empty() {
            return Err(PassAlgoLenMismatch.into());
        }
        Ok(rest)
    }
}

#[inline]
fn next_alg<'a>(slice: &mut &'a [u8]) -> Result<Option<PasswordAlgorithm<&'a [u8]>>, bool> {
    let (slc, src) = match slice.len() {
        0 => return Ok(None),
        HEADER_LEN.. => util::split_array_ref(slice),
        _ => return Err(false),
    };
    let (t, len) = RawAttribute::decode_type_length(slc);
    let (padding, len) = (RawAttribute::padding(len) as usize, len as usize);
    *slice = src.get(len + padding..).unwrap_or_default();
    src.get(..len).map(|params| Some(PasswordAlgorithm::new(Algorithm(t.0), params))).ok_or(true)
}

fn value_len<T: AsRef<[u8]>>(slice: &[PasswordAlgorithm<T>]) -> u16 {
    let [rest @ .., last] = slice else {
        return 0;
    };
    let rest_len: u16 = rest.iter().map(|a| RawAttribute::padded_len(a.encoded_value_len())).sum();
    rest_len + last.encoded_value_len()
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PasswordAlgorithm<T> {
    algorithm: Algorithm,
    parameters: T,
}

impl<T> PasswordAlgorithm<T> {
    pub const TYPE: Type = Type::PASSWORD_ALGORITHM;

    #[inline]
    pub const fn new(algorithm: Algorithm, parameters: T) -> Self {
        Self { algorithm, parameters }
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.parameters
    }

    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    #[inline]
    pub fn parameters(&self) -> &[u8]
    where
        T: AsRef<[u8]>,
    {
        self.parameters.as_ref()
    }
}

impl<T> Attribute for PasswordAlgorithm<T> {
    #[inline]
    fn attribute_type(&self) -> Type {
        Self::TYPE
    }
}

impl<T: AsRef<[u8]>> EncodeAttribute for PasswordAlgorithm<T> {
    #[inline]
    fn encoded_value_len(&self) -> u16 {
        (HEADER_LEN + self.parameters().len()) as u16
    }

    fn encode<'a>(&self, dst: &'a mut [u8], _: &TransactionId) -> Result<&'a mut [u8], StunError> {
        let parameters = self.parameters();
        if parameters.len() > super::MAX_VALUE_LEN - HEADER_LEN {
            new_error!(ParamsTooLong, ValueTooLong, "algorithm parameters are absurdly long");
            return Err(ParamsTooLong.into());
        }
        let param_len = parameters.len() as u16;
        let len = HEADER_LEN as u16 + param_len;
        let total_len = super::total_len(len);
        super::ensure_space(total_len, len, dst.len())?;
        let (attr, rest) = dst.split_at_mut(total_len);
        let (headers, vp) = util::split_array_mut::<_, { RawAttribute::TL_LEN + HEADER_LEN }>(attr);
        let (tl, header): (_, &mut [u8; HEADER_LEN]) = util::split_array_exact_mut(headers);
        let (alg, pl) = util::split_array_exact_mut(header);
        RawAttribute::encode_type_length(Self::TYPE, len, tl);
        *alg = self.algorithm.0.to_be_bytes();
        *pl = param_len.to_be_bytes();
        let (parameters_buf, pad) = vp.split_at_mut(parameters.len());
        parameters_buf.copy_from_slice(parameters);
        pad.fill(0);
        Ok(rest)
    }
}

impl<'d> DecodeAttribute<'d> for PasswordAlgorithm<&'d [u8]> {
    #[inline]
    fn decode(_: Type, src: &'d [u8], _: &TransactionId) -> Result<Self, StunError> {
        if src.len() < HEADER_LEN {
            new_error!(
                PasswordAlgorithmTooBig,
                BufferTooSmall,
                "buffer too small for a password algorithm"
            );
            return Err(PasswordAlgorithmTooBig.into());
        }
        let (header, parameters) = util::split_array_ref::<_, HEADER_LEN>(src);
        let (algorithm, len) = util::split_array_exact_ref(header);
        let algorithm = Algorithm::new(u16::from_be_bytes(*algorithm));
        let len = u16::from_be_bytes(*len);
        if len as usize != parameters.len() {
            new_error!(
                LenMismatch { expected: u16, actual: u16 },
                InvalidParameter,
                "password algorithm params size was declared to be {expected}, at least {actual} provided",
            );
            let at_least = parameters.len().try_into().unwrap_or(u16::MAX);
            return Err(LenMismatch::new(len, at_least).into());
        }
        Ok(Self::new(algorithm, parameters))
    }
}

const PARAM_LEN: usize = core::mem::size_of::<u16>();
const HEADER_LEN: usize = Algorithm::LEN + PARAM_LEN;

#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct Algorithm(pub(crate) u16);

impl Algorithm {
    pub const LEN: usize = 2;

    #[inline]
    pub const fn new(codepoint: u16) -> Self {
        Self(codepoint)
    }

    #[inline]
    pub const fn codepoint(self) -> u16 {
        self.0
    }
}

macro_rules! codepoints {
    ($(($num:literal, $konst:ident, $phrase:expr),)+) => {
        impl Algorithm {
            $(pub const $konst: Self = Self($num);)+
        }

        impl core::fmt::Display for Algorithm {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str(match *self {
                    Self(0x0000) => "RESERVED",
                    $(Self::$konst => $phrase,)+
                    Self(code) => return write!(f, "Unassigned Algorithm ({code:#06X})"),
                })
            }
        }
    }
}

// https://datatracker.ietf.org/doc/html/rfc8489#section-18.5
codepoints! {
    (0x0001, MD5, "MD5"),
    (0x0002, SHA256, "SHA-256"),
}
