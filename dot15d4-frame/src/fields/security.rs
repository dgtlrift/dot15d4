/// Auxiliary Security Header (IEEE 802.15.4-2020, section 9.4).
///
/// Format (figures 9-5 and 9-6):
/// - Byte 0: Security Control
///   - Bits 0-2: Security Level (table 9-6)
///   - Bits 3-4: Key Identifier Mode (table 9-7)
///   - Bit 5: Frame Counter Suppression
///   - Bit 6: ASN in Nonce
/// - Bytes 1-4: Frame Counter, unless suppressed
/// - Key Identifier, 0, 1, 5 or 9 bytes as the Key Identifier Mode says: a
///   Key Source of 0, 4 or 8 bytes, then a Key Index
#[derive(Clone, Copy, Debug)]
pub struct AuxSecurityHeader<Bytes> {
    bytes: Bytes,
}

impl<Bytes: AsRef<[u8]>> AuxSecurityHeader<Bytes> {
    /// Returns [`None`] if the bytes are shorter than the header that their
    /// Security Control field describes.
    #[inline]
    pub fn new(bytes: Bytes) -> Option<Self> {
        let header = Self { bytes };
        let b = header.bytes.as_ref();
        if b.is_empty() || b.len() < header.length() {
            return None;
        }
        Some(header)
    }

    #[inline]
    pub const fn new_unchecked(bytes: Bytes) -> Self {
        Self { bytes }
    }

    /// The length of the header, as its Security Control field describes.
    #[inline]
    pub fn length(&self) -> usize {
        1 + self.frame_counter_length() + self.key_identifier_length()
    }

    #[inline]
    pub fn security_control(&self) -> u8 {
        self.bytes.as_ref()[0]
    }

    /// Security Level, 0 to 7 (table 9-6).
    #[inline]
    pub fn security_level(&self) -> u8 {
        self.security_control() & 0b111
    }

    /// Key Identifier Mode, 0 to 3 (table 9-7).
    #[inline]
    pub fn key_identifier_mode(&self) -> u8 {
        (self.security_control() >> 3) & 0b11
    }

    #[inline]
    pub fn frame_counter_suppression(&self) -> bool {
        self.security_control() & 0x20 != 0
    }

    #[inline]
    pub fn asn_in_nonce(&self) -> bool {
        self.security_control() & 0x40 != 0
    }

    #[inline]
    fn frame_counter_length(&self) -> usize {
        if self.frame_counter_suppression() {
            0
        } else {
            4
        }
    }

    #[inline]
    fn key_identifier_length(&self) -> usize {
        match self.key_identifier_mode() {
            0 => 0,
            1 => 1,
            2 => 5,
            _ => 9,
        }
    }

    /// Frame Counter, unless suppressed.
    #[inline]
    pub fn frame_counter(&self) -> Option<u32> {
        if self.frame_counter_suppression() {
            return None;
        }
        let b = self.bytes.as_ref();
        Some(u32::from_le_bytes([b[1], b[2], b[3], b[4]]))
    }

    /// Key Source, if the Key Identifier Mode includes one: 4 or 8 bytes.
    #[inline]
    pub fn key_source(&self) -> Option<&[u8]> {
        let start = 1 + self.frame_counter_length();
        let len = match self.key_identifier_mode() {
            2 => 4,
            3 => 8,
            _ => return None,
        };
        Some(&self.bytes.as_ref()[start..start + len])
    }

    /// Key Index, unless the key is determined implicitly.
    #[inline]
    pub fn key_index(&self) -> Option<u8> {
        if self.key_identifier_mode() == 0 {
            return None;
        }
        Some(self.bytes.as_ref()[self.length() - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aux_security_header() {
        // ENC-MIC-32, Key Index only, Frame Counter 0x04030201.
        let header = AuxSecurityHeader::new(&[0x0d, 0x01, 0x02, 0x03, 0x04, 0x07][..]).unwrap();
        assert_eq!(header.length(), 6);
        assert_eq!(header.security_level(), 5);
        assert_eq!(header.key_identifier_mode(), 1);
        assert!(!header.frame_counter_suppression());
        assert!(!header.asn_in_nonce());
        assert_eq!(header.frame_counter(), Some(0x0403_0201));
        assert_eq!(header.key_source(), None);
        assert_eq!(header.key_index(), Some(7));

        // MIC-64, 4-byte Key Source, Frame Counter suppressed, ASN in Nonce.
        let header = AuxSecurityHeader::new(&[0x72, 0xa1, 0xa2, 0xa3, 0xa4, 0x09][..]).unwrap();
        assert_eq!(header.length(), 6);
        assert_eq!(header.security_level(), 2);
        assert_eq!(header.key_identifier_mode(), 2);
        assert!(header.frame_counter_suppression());
        assert!(header.asn_in_nonce());
        assert_eq!(header.frame_counter(), None);
        assert_eq!(header.key_source(), Some(&[0xa1, 0xa2, 0xa3, 0xa4][..]));
        assert_eq!(header.key_index(), Some(9));

        // MIC-128, implicit key: the Security Control and Frame Counter only.
        let header = AuxSecurityHeader::new(&[0x03, 0, 0, 0, 0][..]).unwrap();
        assert_eq!(header.length(), 5);
        assert_eq!(header.key_index(), None);

        // 8-byte Key Source.
        let header = AuxSecurityHeader::new(&[0x39, 1, 2, 3, 4, 5, 6, 7, 8, 9][..]).unwrap();
        assert_eq!(header.length(), 10);
        assert_eq!(header.key_source(), Some(&[1, 2, 3, 4, 5, 6, 7, 8][..]));
        assert_eq!(header.key_index(), Some(9));
    }

    #[test]
    fn test_aux_security_header_truncated() {
        let bytes = [0x0d, 0x01, 0x02, 0x03, 0x04, 0x07];
        for len in 0..bytes.len() {
            assert!(AuxSecurityHeader::new(&bytes[..len]).is_none(), "{len}");
        }
    }
}
