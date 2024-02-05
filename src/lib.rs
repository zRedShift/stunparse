#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(
    feature = "ip_in_core",
    feature(cfg_version),
    cfg_attr(not(version("1.77")), feature(ip_in_core))
)]
#![cfg_attr(feature = "error_in_core", feature(error_in_core))]
#![cfg_attr(feature = "type_alias_impl_trait", feature(type_alias_impl_trait))]

#[cfg(feature = "alloc")]
extern crate alloc;

cfg_if::cfg_if! {
    if #[cfg(feature = "no-std-net")] {
        use no_std_net as net;
    } else if #[cfg(feature = "std")] {
        use std::net;
    } else {
        use core::net;
    }
}

pub mod attribute;
pub mod error;
pub mod header;
pub mod parse;
mod util;

pub use attribute::Type as AttributeType;
pub use error::StunError;
pub use header::{Class, Header, Method, TransactionId};
pub use parse::MessageParser;

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
const MAGIC_COOKIE_BYTES: [u8; 4] = MAGIC_COOKIE.to_be_bytes();

#[cfg(test)]
pub(crate) mod test_data;
