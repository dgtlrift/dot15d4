use core::{num::NonZero, ops::Range};

use dot15d4_driver::radio::{
    frame::{FrameControl, RadioFrame, RadioFrameSized},
    DriverConfig,
};
use dot15d4_util::{
    allocator::{BufferToken, IntoBuffer},
    frame::FramePdu,
};

use crate::{fields::MpduParser, repr::SeqNrRepr, MpduWithFrameControl};

/// An unparsed MPDU.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "Must recover the contained buffer after use."]
pub struct MpduFrame {
    pub(crate) buffer: BufferToken,
    /// Contains the buffer offset at which the MPDU starts.
    pub(crate) offset: u8,
    /// Contains the length of the MPDU excluding the FCS.
    pub(crate) length_wo_fcs: NonZero<u16>,
}

impl MpduFrame {
    /// Creates a new unparsed MPDU frame.
    ///
    /// # Safety
    ///
    /// 1. Incoming frames must always be backed by a `buffer` that is at least
    ///    [`RadioFrameRepr::max_buffer_length()`] bytes long. This is because we don't know
    ///    the length of the MPDU at this point, so we assume the maximum length.
    /// 2. Outgoing frames must always be backed by a `buffer` that can at least hold the smallest
    ///    MPDU, which is the immediate acknowledgment (ACK) frame.
    ///
    /// These conditions are not checked at runtime, so it is the caller's
    /// responsibility to ensure that the buffer is large enough.
    ///
    /// [`RadioFrameRepr::max_buffer_length()`]:
    /// dot15d4_driver::radio::frame::RadioFrameRepr::max_buffer_length
    pub unsafe fn new(buffer: BufferToken, offset: u8, length_wo_fcs: NonZero<u16>) -> Self {
        Self {
            buffer,
            offset,
            length_wo_fcs,
        }
    }

    /// Returns the MPDU length of the frame including the FCS if the FCS is not
    /// offloaded to the driver or hardware, otherwise including the FCS length.
    ///
    /// This number depends on the driver configuration.
    pub fn pdu_length<Config: DriverConfig>(&self) -> u16 {
        self.length_wo_fcs.get() + size_of::<<Config as DriverConfig>::Fcs>() as u16
    }

    /// Calculates the MPDU length of the frame without any FCS.
    ///
    /// This number is independent of the driver configuration.
    pub fn pdu_length_wo_fcs(&self) -> u16 {
        self.length_wo_fcs.get()
    }

    fn pdu_range_wo_fcs(&self) -> Range<usize> {
        self.offset as usize..(self.offset as usize + self.pdu_length_wo_fcs() as usize)
    }

    fn pdu_ref_wo_fcs(&self) -> &[u8] {
        &self.buffer[self.pdu_range_wo_fcs()]
    }

    pub fn pdu_mut_wo_fcs(&mut self) -> &mut [u8] {
        let pdu_range = self.pdu_range_wo_fcs();
        &mut self.buffer[pdu_range]
    }

    /// Produces an unparsed MPDU from a radio frame.
    pub fn from_radio_frame(radio_frame: RadioFrame<RadioFrameSized>) -> Self {
        let offset = radio_frame.headroom_length();
        let length_wo_fcs = radio_frame.sdu_wo_fcs_length();
        MpduFrame {
            buffer: radio_frame.into_buffer(),
            offset,
            length_wo_fcs,
        }
    }

    /// Converts an MPDU into a radio frame.
    ///
    /// Calculates the driver-specific FCS if required.
    pub fn into_radio_frame<Config: DriverConfig>(self) -> RadioFrame<RadioFrameSized> {
        debug_assert_eq!(self.offset, Config::HEADROOM);

        // TODO: Calculate the FCS if required.
        // Safety: The length must be set for a sized MPDU.
        RadioFrame::new::<Config>(self.buffer).with_size(self.length_wo_fcs)
    }
}

impl AsRef<Self> for MpduFrame {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsMut<Self> for MpduFrame {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl IntoBuffer for MpduFrame {
    fn into_buffer(self) -> BufferToken {
        self.buffer
    }
}

impl FramePdu for MpduFrame {
    type Pdu = Self;

    fn pdu_ref(&self) -> &Self {
        self
    }

    fn pdu_mut(&mut self) -> &mut Self {
        self
    }
}

/// Read access to the bytes of an unparsed MPDU.
///
/// [`MpduParser`] reads frames through this trait, so it parses both an
/// [`MpduFrame`] in a radio buffer and an [`MpduSlice`] in a plain byte slice.
pub trait MpduBytes {
    /// The bytes that hold the MPDU, which may begin with headroom.
    fn mpdu_buffer(&self) -> &[u8];

    /// The offset in [`Self::mpdu_buffer()`] at which the MPDU begins.
    fn mpdu_offset(&self) -> u8;

    /// The length of the MPDU without its FCS.
    fn mpdu_length_wo_fcs(&self) -> u16;

    /// Provides read-only access to the [`FrameControl`] field.
    fn mpdu_frame_control(&self) -> FrameControl<&[u8]> {
        let offset = self.mpdu_offset() as usize;
        FrameControl::new_unchecked(&self.mpdu_buffer()[offset..offset + 2])
    }

    /// Reads the sequence number field.
    ///
    /// Returns [`None`] if the sequence number is suppressed or if the MPDU
    /// is too short to hold it.
    fn mpdu_sequence_number(&self) -> Option<u8> {
        const OFFSET_SEQ_NR: u16 = 2;
        if self.mpdu_frame_control().sequence_number_suppression()
            || self.mpdu_length_wo_fcs() <= OFFSET_SEQ_NR
        {
            return None;
        }
        Some(self.mpdu_buffer()[self.mpdu_offset() as usize + OFFSET_SEQ_NR as usize])
    }
}

impl MpduBytes for MpduFrame {
    fn mpdu_buffer(&self) -> &[u8] {
        &self.buffer
    }

    fn mpdu_offset(&self) -> u8 {
        self.offset
    }

    fn mpdu_length_wo_fcs(&self) -> u16 {
        self.length_wo_fcs.get()
    }
}

impl MpduBytes for &MpduFrame {
    fn mpdu_buffer(&self) -> &[u8] {
        &self.buffer
    }

    fn mpdu_offset(&self) -> u8 {
        self.offset
    }

    fn mpdu_length_wo_fcs(&self) -> u16 {
        self.length_wo_fcs.get()
    }
}

impl MpduBytes for &mut MpduFrame {
    fn mpdu_buffer(&self) -> &[u8] {
        &self.buffer
    }

    fn mpdu_offset(&self) -> u8 {
        self.offset
    }

    fn mpdu_length_wo_fcs(&self) -> u16 {
        self.length_wo_fcs.get()
    }
}

/// An unparsed MPDU in a byte slice.
///
/// Parses frames that were not received into a radio buffer, for example
/// from a capture file, a trace or a test, without a buffer allocator:
///
/// ```
/// # use dot15d4_frame::mpdu::MpduSlice;
/// // A data frame with short addresses and a 2-byte FCS.
/// let psdu = [
///     0x41, 0x88, 0x01, 0xcd, 0xab, 0xff, 0xff, 0x01, 0x00, 0x2a, 0x00, 0x00,
/// ];
/// let mpdu = MpduSlice::new(&psdu, 2).unwrap();
/// let reader = mpdu.reader().parse_addressing().unwrap();
/// let addressing = reader.try_addressing_fields().unwrap();
/// assert_eq!(addressing.try_dst_pan_id().unwrap().into_u16(), 0xabcd);
/// let reader = reader
///     .parse_security()
///     .unwrap()
///     .parse_ies_with_fcs_length(mpdu.fcs_length())
///     .unwrap();
/// assert_eq!(reader.try_frame_payload(), Some(&[0x2a][..]));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpduSlice<'a> {
    bytes: &'a [u8],
    length_wo_fcs: NonZero<u16>,
    fcs_length: u8,
}

impl<'a> MpduSlice<'a> {
    /// Wraps a PSDU: an MPDU followed by its FCS of `fcs_length` bytes (0, 2
    /// or 4, as the PHY and the driver dictate).
    ///
    /// Returns [`None`] if the MPDU is too short to hold a frame control
    /// field, or longer than [`u16::MAX`] bytes.
    pub fn new(psdu: &'a [u8], fcs_length: u8) -> Option<Self> {
        const FRAME_CONTROL_LEN: usize = 2;
        let length_wo_fcs = psdu.len().checked_sub(fcs_length as usize)?;
        if length_wo_fcs < FRAME_CONTROL_LEN {
            return None;
        }
        Some(Self {
            bytes: psdu,
            length_wo_fcs: NonZero::new(u16::try_from(length_wo_fcs).ok()?)?,
            fcs_length,
        })
    }

    /// The length of the FCS that follows the MPDU.
    pub fn fcs_length(&self) -> u8 {
        self.fcs_length
    }

    /// Starts parsing the MPDU.
    pub fn reader(self) -> MpduParser<Self, MpduWithFrameControl> {
        MpduParser::new(
            self,
            if self.mpdu_frame_control().sequence_number_suppression() {
                SeqNrRepr::No
            } else {
                SeqNrRepr::Yes
            },
        )
    }
}

impl MpduBytes for MpduSlice<'_> {
    fn mpdu_buffer(&self) -> &[u8] {
        self.bytes
    }

    fn mpdu_offset(&self) -> u8 {
        0
    }

    fn mpdu_length_wo_fcs(&self) -> u16 {
        self.length_wo_fcs.get()
    }
}

#[cfg(test)]
mod tests {
    use dot15d4_driver::radio::frame::{AddressingMode, FrameType, FrameVersion};

    use super::*;

    /// An Enhanced Beacon without its FCS: short broadcast destination, PAN ID
    /// 0xabcd, extended source, sequence number suppressed, HT1 and an MLME
    /// payload IE with TSCH Synchronization, Timeslot, Channel Hopping and
    /// Slotframe and Link nested IEs.
    const ENHANCED_BEACON: [u8; 35] = [
        0x40, 0xeb, 0xcd, 0xab, 0xff, 0xff, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x3f, 0x11, 0x88, 0x06, 0x1a, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x1c, 0x00, 0x01,
        0xc8, 0x00, 0x01, 0x1b, 0x00,
    ];

    #[test]
    fn test_mpdu_slice_new() {
        assert!(MpduSlice::new(&[], 0).is_none());
        assert!(MpduSlice::new(&[0x41], 0).is_none());
        assert!(MpduSlice::new(&[0x41, 0x88], 1).is_none());
        assert!(MpduSlice::new(&[0x41, 0x88, 0x00], 4).is_none());
        let mpdu = MpduSlice::new(&[0x41, 0x88, 0x00, 0x00], 2).unwrap();
        assert_eq!(mpdu.mpdu_length_wo_fcs(), 2);
        assert_eq!(mpdu.fcs_length(), 2);
    }

    #[test]
    fn test_mpdu_slice_enhanced_beacon() {
        let mpdu = MpduSlice::new(&ENHANCED_BEACON, 0).unwrap();
        let reader = mpdu.reader();
        let fc = reader.frame_control();
        assert_eq!(fc.frame_type(), FrameType::Beacon);
        assert_eq!(fc.frame_version(), FrameVersion::Ieee802154);
        assert_eq!(fc.dst_addressing_mode(), AddressingMode::Short);
        assert_eq!(fc.src_addressing_mode(), AddressingMode::Extended);
        assert!(fc.information_elements_present());
        assert_eq!(reader.sequence_number(), None);

        let reader = reader.parse_addressing().unwrap();
        let addressing = reader.try_addressing_fields().unwrap();
        assert_eq!(addressing.try_dst_pan_id().unwrap().into_u16(), 0xabcd);
        assert!(addressing.try_dst_address().unwrap().is_broadcast());
        assert!(addressing.try_src_address().unwrap().is_extended());

        let reader = reader
            .parse_security()
            .unwrap()
            .parse_ies_with_fcs_length(0)
            .unwrap();
        assert_eq!(reader.try_frame_payload(), None);
        assert_eq!(reader.try_fcs(), None);

        #[cfg(feature = "ies")]
        {
            let ies = reader.try_ies_fields().unwrap();
            assert_eq!(ies.tsch_sync().unwrap().asn(), 14);
            assert_eq!(ies.nested_ies().unwrap().count(), 4);
        }
    }

    #[test]
    fn test_mpdu_slice_fcs() {
        // A data frame with short addresses, a payload and a 4-byte FCS.
        let psdu = [
            0x41, 0x88, 0x01, 0xcd, 0xab, 0xff, 0xff, 0x01, 0x00, 0x2a, 0x2b, 0x01, 0x02, 0x03,
            0x04,
        ];
        let mpdu = MpduSlice::new(&psdu, 4).unwrap();
        let reader = mpdu
            .reader()
            .parse_addressing()
            .unwrap()
            .parse_security()
            .unwrap()
            .parse_ies_with_fcs_length(mpdu.fcs_length())
            .unwrap();
        assert_eq!(reader.sequence_number(), Some(1));
        assert_eq!(reader.try_frame_payload(), Some(&[0x2a, 0x2b][..]));
        assert_eq!(reader.try_fcs(), Some(&[0x01, 0x02, 0x03, 0x04][..]));
    }

    /// Parses a secured PSDU with a 2-byte FCS up to all its fields.
    #[cfg(feature = "security")]
    fn parse_secured(psdu: &[u8]) -> Option<MpduParser<MpduSlice<'_>, crate::MpduWithAllFields>> {
        MpduSlice::new(psdu, 2)?
            .reader()
            .parse_addressing()
            .ok()?
            .parse_security()
            .ok()?
            .parse_ies_with_fcs_length(2)
            .ok()
    }

    /// A data frame, version 2, Security Enabled, PAN ID Compression, short
    /// addresses (IEEE 802.15.4-2020, figure 7-2 and table 7-2), sequence
    /// number 1; ENC-MIC-32 with a Key Index (section 9.4); an encrypted
    /// payload, the MIC and the FCS.
    #[cfg(feature = "security")]
    const SECURED_DATA: [u8; 23] = [
        0x49, 0xa8, 0x01, 0xcd, 0xab, 0x01, 0x00, 0x02, 0x00, // MHR
        0x0d, 0x04, 0x03, 0x02, 0x01, 0x07, // Auxiliary Security Header
        0xaa, 0xbb, // encrypted payload
        0x11, 0x22, 0x33, 0x44, // MIC
        0xf1, 0xf2, // FCS
    ];

    #[cfg(feature = "security")]
    #[test]
    fn test_mpdu_slice_secured() {
        let reader = parse_secured(&SECURED_DATA).unwrap();
        assert!(reader.frame_control().security_enabled());
        assert!(reader.is_encrypted());
        let header = reader.try_aux_sec_header().unwrap();
        assert_eq!(header.security_level(), 5);
        assert_eq!(header.frame_counter(), Some(0x0102_0304));
        assert_eq!(header.key_index(), Some(7));
        assert_eq!(reader.try_frame_payload(), Some(&[0xaa, 0xbb][..]));
        assert_eq!(reader.try_mic(), Some(&[0x11, 0x22, 0x33, 0x44][..]));
        assert_eq!(reader.try_fcs(), Some(&[0xf1, 0xf2][..]));

        // The MPDU must hold the MHR, the Auxiliary Security Header (to byte
        // 15) and the MIC (4 bytes); whatever is left is the payload.
        for len in 11..SECURED_DATA.len() {
            let mpdu_len = len - 2;
            let security = MpduSlice::new(&SECURED_DATA[..len], 2)
                .unwrap()
                .reader()
                .parse_addressing()
                .unwrap()
                .parse_security();
            let Ok(security) = security else {
                assert!(mpdu_len < 19, "{len}");
                continue;
            };
            assert!(mpdu_len >= 19, "{len}");
            let reader = security.parse_ies_with_fcs_length(2).unwrap();
            assert_eq!(
                reader.try_frame_payload().map_or(0, <[u8]>::len),
                mpdu_len - 19
            );
        }

        // Security levels 0 and the reserved 4 aren't represented.
        let mut psdu = SECURED_DATA;
        for security_control in [0x08, 0x0c] {
            psdu[9] = security_control;
            assert!(MpduSlice::new(&psdu, 2)
                .unwrap()
                .reader()
                .parse_addressing()
                .unwrap()
                .parse_security()
                .is_err());
        }

        // An unsecured frame has no Auxiliary Security Header and no MIC.
        let reader = MpduSlice::new(&ENHANCED_BEACON, 0)
            .unwrap()
            .reader()
            .parse_addressing()
            .unwrap()
            .parse_security()
            .unwrap()
            .parse_ies_with_fcs_length(0)
            .unwrap();
        assert!(reader.try_aux_sec_header().is_none());
        assert!(!reader.is_encrypted());
        assert_eq!(reader.try_mic(), None);
    }

    #[cfg(all(feature = "security", feature = "ies"))]
    #[test]
    fn test_mpdu_slice_secured_ies() {
        // A data frame, version 2, Security Enabled, IE Present, PAN ID
        // Compression, short addresses, sequence number 1; then a header IE
        // (Element ID 0x2a, 1 byte) and HT1; then payload IEs and payload.
        let mhr = [
            0x49, 0xaa, 0x01, 0xcd, 0xab, 0x01, 0x00, 0x02, 0x00, // MHR
        ];
        let header_ies = [0x01, 0x15, 0x5a, 0x00, 0x3f];
        // An MLME payload IE with one 1-byte short nested IE, then a payload
        // termination IE and one byte of payload.
        let payload = [0x03, 0x88, 0x01, 0x40, 0x77, 0x00, 0xf8, 0x99];

        // MIC-32: payload IEs in the clear.
        let mut psdu = [0u8; 9 + 6 + 5 + 8 + 4 + 2];
        psdu[..9].copy_from_slice(&mhr);
        psdu[9..15].copy_from_slice(&[0x09, 0x04, 0x03, 0x02, 0x01, 0x07]);
        psdu[15..20].copy_from_slice(&header_ies);
        psdu[20..28].copy_from_slice(&payload);
        psdu[28..32].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let reader = parse_secured(&psdu).unwrap();
        assert!(!reader.is_encrypted());
        let ies = reader.try_ies_slice().unwrap();
        assert_eq!(ies.len(), 5 + 7);
        assert_eq!(
            reader
                .try_ies_fields()
                .unwrap()
                .nested_ies()
                .unwrap()
                .count(),
            1
        );
        assert_eq!(reader.try_frame_payload(), Some(&[0x99][..]));
        assert_eq!(reader.try_mic(), Some(&[0x11, 0x22, 0x33, 0x44][..]));

        // ENC-MIC-32: the payload IEs are encrypted with the payload.
        psdu[9] = 0x0d;
        let reader = parse_secured(&psdu).unwrap();
        assert!(reader.is_encrypted());
        assert_eq!(reader.try_ies_slice(), Some(&header_ies[..]));
        assert_eq!(reader.try_frame_payload(), Some(&payload[..]));
        assert_eq!(reader.try_mic(), Some(&[0x11, 0x22, 0x33, 0x44][..]));
    }

    #[test]
    fn test_mpdu_slice_truncated() {
        // Every prefix either parses or fails, without reading past the MPDU.
        for len in 2..ENHANCED_BEACON.len() {
            let mpdu = MpduSlice::new(&ENHANCED_BEACON[..len], 0).unwrap();
            let reader = mpdu.reader();
            let _ = reader.sequence_number();
            let Ok(reader) = reader.parse_addressing() else {
                assert!(len < 14, "{len}");
                continue;
            };
            assert!(len >= 14, "{len}");
            let _ = reader.try_addressing_fields();
            if let Ok(reader) = reader
                .parse_security()
                .unwrap()
                .parse_ies_with_fcs_length(0)
            {
                let _ = reader.try_frame_payload();
                #[cfg(feature = "ies")]
                if let Some(ies) = reader.try_ies_fields() {
                    let _ = ies.header_ies().count();
                    let _ = ies.nested_ies().map(Iterator::count);
                }
            }
        }

        // A sequence number that doesn't fit is absent.
        let mpdu = MpduSlice::new(&[0x41, 0x88], 0).unwrap();
        assert_eq!(mpdu.reader().sequence_number(), None);
        assert!(mpdu.reader().parse_addressing().is_err());
    }
}
