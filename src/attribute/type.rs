#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct Type(pub(crate) u16);

impl Type {
    pub const LEN: usize = 2;

    #[inline]
    pub const fn new(codepoint: u16) -> Self {
        Self(codepoint)
    }

    #[inline]
    pub const fn codepoint(self) -> u16 {
        self.0
    }

    #[inline]
    pub const fn is_comprehension_required(self) -> bool {
        self.0 < Self::ADDITIONAL_ADDRESS_FAMILY.0
    }
}

macro_rules! codepoints {
    ($(($num:literal, $konst:ident, $phrase:expr),)+) => {
        impl Type {
            $(pub const $konst: Self = Self($num);)+
        }

        impl core::fmt::Display for Type {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str(match *self {
                    $(Self::$konst => $phrase,)+
                    Self(code) => return write!(f, "Unknown Attribute ({code:#06X})"),
                })
            }
        }
    }
}

// https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml#stun-parameters-4
codepoints! {
    (0x0001, MAPPED_ADDRESS, "MAPPED-ADDRESS"),
    (0x0003, CHANGE_REQUEST, "CHANGE-REQUEST"),
    (0x0006, USERNAME, "USERNAME"),
    (0x0008, MESSAGE_INTEGRITY, "MESSAGE-INTEGRITY"),
    (0x0009, ERROR_CODE, "ERROR-CODE"),
    (0x000A, UNKNOWN_ATTRIBUTES, "UNKNOWN-ATTRIBUTES"),
    (0x000C, CHANNEL_NUMBER, "CHANNEL-NUMBER"),
    (0x000D, LIFETIME, "LIFETIME"),
    (0x0012, XOR_PEER_ADDRESS, "XOR-PEER-ADDRESS"),
    (0x0013, DATA, "DATA"),
    (0x0014, REALM, "REALM"),
    (0x0015, NONCE, "NONCE"),
    (0x0016, XOR_RELAYED_ADDRESS, "XOR-RELAYED-ADDRESS"),
    (0x0017, REQUESTED_ADDRESS_FAMILY, "REQUESTED-ADDRESS-FAMILY"),
    (0x0018, EVEN_PORT, "EVEN-PORT"),
    (0x0019, REQUESTED_TRANSPORT, "REQUESTED-TRANSPORT"),
    (0x001A, DONT_FRAGMENT, "DONT-FRAGMENT"),
    (0x001B, ACCESS_TOKEN, "ACCESS-TOKEN"),
    (0x001C, MESSAGE_INTEGRITY_SHA256, "MESSAGE-INTEGRITY-SHA256"),
    (0x001D, PASSWORD_ALGORITHM, "PASSWORD-ALGORITHM"),
    (0x001E, USERHASH, "USERHASH"),
    (0x0020, XOR_MAPPED_ADDRESS, "XOR-MAPPED-ADDRESS"),
    (0x0022, RESERVATION_TOKEN, "RESERVATION-TOKEN"),
    (0x0024, PRIORITY, "PRIORITY"),
    (0x0025, USE_CANDIDATE, "USE-CANDIDATE"),
    (0x0026, PADDING, "PADDING"),
    (0x0027, RESPONSE_PORT, "RESPONSE-PORT"),
    (0x002A, CONNECTION_ID, "CONNECTION-ID"),
    (0x8000, ADDITIONAL_ADDRESS_FAMILY, "ADDITIONAL-ADDRESS-FAMILY"),
    (0x8001, ADDRESS_ERROR_CODE, "ADDRESS-ERROR-CODE"),
    (0x8002, PASSWORD_ALGORITHMS, "PASSWORD-ALGORITHMS"),
    (0x8003, ALTERNATE_DOMAIN, "ALTERNATE-DOMAIN"),
    (0x8004, ICMP, "ICMP"),
    (0x8022, SOFTWARE, "SOFTWARE"),
    (0x8023, ALTERNATE_SERVER, "ALTERNATE-SERVER"),
    (0x8025, TRANSACTION_TRANSMIT_COUNTER, "TRANSACTION-TRANSMIT-COUNTER"),
    (0x8027, CACHE_TIMEOUT, "CACHE-TIMEOUT"),
    (0x8028, FINGERPRINT, "FINGERPRINT"),
    (0x8029, ICE_CONTROLLED, "ICE-CONTROLLED"),
    (0x802A, ICE_CONTROLLING, "ICE-CONTROLLING"),
    (0x802B, RESPONSE_ORIGIN, "RESPONSE-ORIGIN"),
    (0x802C, OTHER_ADDRESS, "OTHER-ADDRESS"),
    (0x802D, ECN_CHECK_STUN, "ECN-CHECK-STUN"),
    (0x802E, THIRD_PARTY_AUTHORIZATION, "THIRD-PARTY-AUTHORIZATION"),
    (0x8030, MOBILITY_TICKET, "MOBILITY-TICKET"),
    (0xC000, CISCO_STUN_FLOWDATA, "CISCO-STUN-FLOWDATA"),
    (0xC001, ENF_FLOW_DESCRIPTION, "ENF-FLOW-DESCRIPTION"),
    (0xC002, ENF_NETWORK_STATUS, "ENF-NETWORK-STATUS"),
    (0xC003, CISCO_WEBEX_FLOW_INFO, "CISCO-WEBEX-FLOW-INFO"),
    (0xC056, CITRIX_TRANSACTION_ID, "CITRIX-TRANSACTION-ID"),
    (0xC057, GOOG_NETWORK_INFO, "GOOG-NETWORK-INFO"),
    (0xC058, GOOG_LAST_ICE_CHECK_RECEIVED, "GOOG-LAST-ICE-CHECK-RECEIVED"),
    (0xC059, GOOG_MISC_INFO, "GOOG-MISC-INFO"),
    (0xC05A, GOOG_OBSOLETE_1, "GOOG-OBSOLETE-1"),
    (0xC05B, GOOG_CONNECTION_ID, "GOOG-CONNECTION-ID"),
    (0xC05C, GOOG_DELTA, "GOOG-DELTA"),
    (0xC05D, GOOG_DELTA_ACK, "GOOG-DELTA-ACK"),
    (0xC05E, GOOG_DELTA_SYNC_REQ, "GOOG-DELTA-SYNC-REQ"),
    (0xC060, GOOG_MESSAGE_INTEGRITY_32, "GOOG-MESSAGE-INTEGRITY-32"),
}
