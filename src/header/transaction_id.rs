use core::fmt::{Debug, Formatter, Result};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct TransactionId(pub(crate) [u8; Self::LEN]);

impl TransactionId {
    pub const LEN: usize = 12;

    pub const fn new(id: [u8; Self::LEN]) -> Self {
        Self(id)
    }

    pub fn get(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl Debug for TransactionId {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result {
        struct UpperHex<'a>(&'a [u8; TransactionId::LEN]);

        impl<'a> Debug for UpperHex<'a> {
            #[inline]
            fn fmt(&self, f: &mut Formatter) -> Result {
                write!(f, "0x")?;
                for b in self.0 {
                    write!(f, "{:02X}", b)?;
                }
                Ok(())
            }
        }

        f.debug_tuple("TransactionId").field(&UpperHex(&self.0)).finish()
    }
}
