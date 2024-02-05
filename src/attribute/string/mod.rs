mod dns;
mod error;
mod length;
mod opaque;
mod quoted;
mod text_attr;
mod validated;

pub use text_attr::{AlternateDomain, Nonce, Realm, Software, Username};
pub use validated::Validated;

pub trait AsStr: private::Sealed {
    fn as_str(&self) -> &str;
}

impl<T: AsRef<str>> AsStr for T {
    #[inline]
    fn as_str(&self) -> &str {
        self.as_ref()
    }
}

impl<T: AsRef<str>, const D: bool, const Q: bool, const O: bool> AsStr for Validated<T, D, Q, O> {
    #[inline]
    fn as_str(&self) -> &str {
        self.as_str()
    }
}

mod private {
    use super::Validated;

    pub trait Sealed {}

    impl<T: AsRef<str>> Sealed for T {}
    impl<T: AsRef<str>, const D: bool, const Q: bool, const O: bool> Sealed for Validated<T, D, Q, O> {}
}
