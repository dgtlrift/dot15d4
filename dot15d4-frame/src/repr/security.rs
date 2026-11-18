#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SecurityLevelRepr {
    Mic32,
    Mic64,
    Mic128,
    EncMic32,
    EncMic64,
    EncMic128,
} // 1 byte

impl SecurityLevelRepr {
    /// The security level of a Security Level field value (IEEE 802.15.4-2020,
    /// table 9-6).
    ///
    /// Returns [`None`] for level 0, which has no MIC and is not represented,
    /// and for the reserved level 4.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0b111 {
            1 => Some(SecurityLevelRepr::Mic32),
            2 => Some(SecurityLevelRepr::Mic64),
            3 => Some(SecurityLevelRepr::Mic128),
            5 => Some(SecurityLevelRepr::EncMic32),
            6 => Some(SecurityLevelRepr::EncMic64),
            7 => Some(SecurityLevelRepr::EncMic128),
            _ => None,
        }
    }

    /// Whether the security level encrypts the MAC payload, payload IEs
    /// included.
    pub const fn is_encrypted(&self) -> bool {
        matches!(
            self,
            SecurityLevelRepr::EncMic32
                | SecurityLevelRepr::EncMic64
                | SecurityLevelRepr::EncMic128
        )
    }

    /// MIC length in bytes.
    pub const fn mic_length(&self) -> u16 {
        match self {
            SecurityLevelRepr::Mic32 | SecurityLevelRepr::EncMic32 => 4, // 32 bits
            SecurityLevelRepr::Mic64 | SecurityLevelRepr::EncMic64 => 8, // 64 bits
            SecurityLevelRepr::Mic128 | SecurityLevelRepr::EncMic128 => 16, // 128 bits
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum KeyIdRepr {
    Implicit,
    SourceNone,
    Source4Byte,
    Source8Byte,
} // 1 byte

impl KeyIdRepr {
    /// The key identifier mode of a Key Identifier Mode field value (IEEE
    /// 802.15.4-2020, table 9-7).
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => KeyIdRepr::Implicit,
            1 => KeyIdRepr::SourceNone,
            2 => KeyIdRepr::Source4Byte,
            _ => KeyIdRepr::Source8Byte,
        }
    }

    pub const fn key_id_length(&self) -> u16 {
        match self {
            KeyIdRepr::Implicit => 0,
            KeyIdRepr::SourceNone => 1,
            KeyIdRepr::Source4Byte => 5,
            KeyIdRepr::Source8Byte => 9,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SecurityRepr {
    tsch_mode: bool,
    security_level: SecurityLevelRepr,
    key_id: KeyIdRepr,
} // 3 bytes

impl SecurityRepr {
    pub const fn new(
        tsch_mode: bool,
        security_level: SecurityLevelRepr,
        key_id: KeyIdRepr,
    ) -> Self {
        Self {
            tsch_mode,
            security_level,
            key_id,
        }
    }

    /// The security configuration of a Security Control field (IEEE
    /// 802.15.4-2020, section 9.4.2, figure 9-6).
    ///
    /// Returns [`None`] for a security level that is not represented, see
    /// [`SecurityLevelRepr::from_bits()`].
    pub const fn from_security_control(security_control: u8) -> Option<Self> {
        let Some(security_level) = SecurityLevelRepr::from_bits(security_control) else {
            return None;
        };
        Some(Self {
            tsch_mode: security_control & 0x20 != 0,
            security_level,
            key_id: KeyIdRepr::from_bits(security_control >> 3),
        })
    }

    pub const fn security_level(&self) -> SecurityLevelRepr {
        self.security_level
    }

    pub const fn aux_sec_header_length(&self) -> u16 {
        const SECURITY_CONTROL_LENGTH: u16 = 1;

        let frame_counter_len = if self.tsch_mode { 0 } else { 4 };
        SECURITY_CONTROL_LENGTH + frame_counter_len + self.key_id.key_id_length()
    }

    pub const fn mic_length(&self) -> u16 {
        self.security_level.mic_length()
    }
}
