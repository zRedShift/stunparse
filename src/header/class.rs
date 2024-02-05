#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl Class {
    #[inline]
    pub const fn from_msg_type(msg_type: u16) -> Self {
        match ((msg_type >> 4) & 0b01) | ((msg_type >> 7) & 0b10) {
            0b00 => Self::Request,
            0b01 => Self::Indication,
            0b10 => Self::SuccessResponse,
            0b11 => Self::ErrorResponse,
            _ => unreachable!(),
        }
    }

    #[inline]
    pub const fn into_msg_type(self) -> u16 {
        match self {
            Self::Request => 0x0000,
            Self::Indication => 0x0010,
            Self::SuccessResponse => 0x0100,
            Self::ErrorResponse => 0x0110,
        }
    }

    pub fn is_request(self) -> bool {
        matches!(self, Self::Request)
    }

    pub fn is_response(self) -> bool {
        matches!(self, Self::SuccessResponse | Self::ErrorResponse)
    }

    pub fn is_success(self) -> bool {
        matches!(self, Self::SuccessResponse)
    }

    pub fn is_indication(self) -> bool {
        matches!(self, Self::Indication)
    }

    pub fn is_error(self) -> bool {
        matches!(self, Self::ErrorResponse)
    }
}

impl core::fmt::Display for Class {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}
