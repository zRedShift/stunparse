#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Method(pub(crate) u16);

impl Method {
    #[inline]
    pub const fn from_msg_type(msg_type: u16) -> Self {
        Self((msg_type & 0x00F) | ((msg_type >> 1) & 0x070) | ((msg_type >> 2) & 0xF80))
    }

    #[inline]
    pub const fn into_msg_type(self) -> u16 {
        (self.0 & 0x00F) | ((self.0 & 0x070) << 1) | ((self.0 & 0xF80) << 2)
    }
}

macro_rules! methods {
    ($(($num:literal, $konst:ident, $phrase:expr),)+) => {
        impl Method {
            $(pub const $konst: Self = Self($num);)+
        }

        impl core::fmt::Display for Method {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str(match *self {
                    $(Self::$konst => $phrase,)+
                    Self(code) => return write!(f, "Unknown Method ({code:#06X})"),
                })
            }
        }
    }
}

// https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml#stun-parameters-2
methods! {
    (0x001, BINDING, "Binding"),
    (0x003, ALLOCATE, "Allocate"),
    (0x004, REFRESH, "Refresh"),
    (0x006, SEND, "Send"),
    (0x007, DATA, "Data"),
    (0x008, CREATE_PERMISSION, "CreatePermission"),
    (0x009, CHANNEL_BIND, "ChannelBind"),
    (0x00A, CONNECT, "Connect"),
    (0x00B, CONNECTION_BIND, "ConnectionBind"),
    (0x00C, CONNECTION_ATTEMPT, "ConnectionAttempt"),
    (0x080, GOOG_PING, "GOOG-PING"),
}
