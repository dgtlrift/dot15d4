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

/// Write access to the bytes of an MPDU being built or edited.
///
/// [`MpduParser`]'s setters write through this trait, so a frame is built
/// alike in an [`MpduFrame`] in a radio buffer and in an [`MpduSliceMut`] over
/// a plain byte slice.
pub trait MpduBytesMut: MpduBytes {
    /// The bytes that hold the MPDU, which may begin with headroom.
    fn mpdu_buffer_mut(&mut self) -> &mut [u8];

    /// Provides mutable access to the [`FrameControl`] field.
    fn mpdu_frame_control_mut(&mut self) -> FrameControl<&mut [u8]> {
        let offset = self.mpdu_offset() as usize;
        FrameControl::new_unchecked(&mut self.mpdu_buffer_mut()[offset..offset + 2])
    }

    /// Writes the sequence number field.
    ///
    /// Returns an error if the sequence number is suppressed, or if the MPDU
    /// is too short to hold it.
    fn mpdu_try_set_sequence_number(&mut self, seq_nr: u8) -> Result<(), ()> {
        const OFFSET_SEQ_NR: u16 = 2;
        if self.mpdu_frame_control().sequence_number_suppression()
            || self.mpdu_length_wo_fcs() <= OFFSET_SEQ_NR
        {
            return Err(());
        }
        let offset = self.mpdu_offset() as usize + OFFSET_SEQ_NR as usize;
        self.mpdu_buffer_mut()[offset] = seq_nr;
        Ok(())
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

impl MpduBytesMut for MpduFrame {
    fn mpdu_buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

impl MpduBytesMut for &mut MpduFrame {
    fn mpdu_buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
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

/// An MPDU being built in a byte slice, from its first byte.
///
/// Made by [`MpduRepr::into_slice_writer()`], which builds frames without a
/// buffer allocator, for example in a test or a tool, or in firmware that
/// sends from a buffer of its own:
///
/// ```
/// # use dot15d4_driver::radio::frame::{
/// #     Address, AddressingMode, AddressingRepr, FrameType, FrameVersion, PanId, ShortAddress,
/// # };
/// # use dot15d4_frame::repr::{MpduRepr, SeqNrRepr};
/// let repr = MpduRepr::new()
///     .with_frame_control(SeqNrRepr::Yes)
///     .with_addressing(AddressingRepr::new_legacy_addressing(
///         AddressingMode::Short,
///         AddressingMode::Short,
///         true,
///     ))
///     .without_security()
///     .without_ies();
/// let mut psdu = [0u8; 12];
/// let mut writer = repr
///     .into_slice_writer(FrameVersion::Ieee802154_2006, FrameType::Data, 1, 2, &mut psdu)
///     .unwrap();
/// writer.set_sequence_number(1);
/// let mut addressing = writer.addressing_fields_mut();
/// addressing.dst_pan_id_mut().set(&PanId::new_owned([0xcd, 0xab]));
/// addressing
///     .dst_address_mut()
///     .set(&Address::Short(ShortAddress::new_owned([0xff, 0xff])));
/// addressing
///     .src_address_mut()
///     .set(&Address::Short(ShortAddress::new_owned([0x01, 0x00])));
/// writer.frame_payload_mut()[0] = 0x2a;
/// // The FCS's two bytes are left to the radio.
/// assert_eq!(
///     psdu,
///     [0x41, 0x98, 0x01, 0xcd, 0xab, 0xff, 0xff, 0x01, 0x00, 0x2a, 0x00, 0x00]
/// );
/// ```
///
/// [`MpduRepr::into_slice_writer()`]: crate::repr::MpduRepr::into_slice_writer
#[derive(Debug, PartialEq, Eq)]
pub struct MpduSliceMut<'a> {
    bytes: &'a mut [u8],
    length_wo_fcs: NonZero<u16>,
    fcs_length: u8,
}

impl<'a> MpduSliceMut<'a> {
    /// Wraps a buffer for an MPDU of `length_wo_fcs` bytes and an FCS of
    /// `fcs_length` bytes.
    ///
    /// Returns [`None`] if the buffer can't hold them, or if the MPDU is too
    /// short to hold a frame control field.
    pub(crate) fn new(
        bytes: &'a mut [u8],
        length_wo_fcs: NonZero<u16>,
        fcs_length: u8,
    ) -> Option<Self> {
        const FRAME_CONTROL_LEN: u16 = 2;
        if length_wo_fcs.get() < FRAME_CONTROL_LEN
            || bytes.len() < length_wo_fcs.get() as usize + fcs_length as usize
        {
            return None;
        }
        Some(Self {
            bytes,
            length_wo_fcs,
            fcs_length,
        })
    }

    /// The length of the FCS that follows the MPDU.
    pub fn fcs_length(&self) -> u8 {
        self.fcs_length
    }

    /// The length of the PSDU: the MPDU and its FCS.
    pub fn psdu_length(&self) -> usize {
        self.length_wo_fcs.get() as usize + self.fcs_length as usize
    }
}

impl MpduBytes for MpduSliceMut<'_> {
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

impl MpduBytesMut for MpduSliceMut<'_> {
    fn mpdu_buffer_mut(&mut self) -> &mut [u8] {
        self.bytes
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
            if let Ok(reader) = reader.parse_security().unwrap().parse_ies_with_fcs_length(0) {
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
