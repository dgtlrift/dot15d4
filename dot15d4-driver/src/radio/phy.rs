use core::marker::PhantomData;

use fugit::Duration;

use crate::timer::NsDuration;

use super::constants::{A_MAX_SIFS_FRAME_SIZE, A_NUM_SUPERFRAME_SLOTS};

const PHY_MAX_PACKET_SIZE_2047: u16 = 2047; // SUN, TVWS, RCC, LECIM FSK, and MSK with a 2000 kb/s data rate
const PHY_MAX_PACKET_SIZE_127: u16 = 127; // all other PHYs

/// PHY-dependent constants and PIB attributes.
///
/// Note: We currently use local clock durations even for values defined in
///       terms of symbol periods. This allows us to benefit from their
///       "const-ness" and interoperability. For PHYs that produce ns-fractions
///       this won't work.
pub trait PhyConfig {
    const SYMBOL_RATE: u32;

    /// symbol period
    type SymbolPeriods;

    /// Rx-to-tx or tx-to-rx turnaround time (in symbol periods), as defined in
    /// 10.2.2 and 10.2.3.
    const A_TURNAROUND_TIME: NsDuration;

    // Constants from section 11.3, Table 11-1, PHY constants

    /// The maximum PSDU size (in octets) the PHY shall be able to receive.
    const PHY_MAX_PACKET_SIZE: u16;

    /// The time required to perform CCA detection in symbol periods.
    const PHY_CCA_DURATION: NsDuration;

    /// The number of symbols forming a superframe slot when the superframe
    /// order is equal to zero, as described in 6.2.1.
    const A_BASE_SLOT_DURATION: NsDuration;

    /// The number of symbols forming a superframe when the superframe order is
    /// equal to zero.
    const A_BASE_SUPERFRAME_DURATION: NsDuration;

    // Constants of IEEE 802.15.4-2024, section 8.4.2, Table 8-35, MAC constants

    /// The minimum number of symbols forming the CAP. This ensures that MAC
    /// commands can still be transferred to devices when GTSs are being used.
    ///
    /// An exception to this minimum shall be allowed for the accommodation of
    /// the temporary increase in the beacon frame length needed to perform GTS
    /// maintenance, as described in 7.3.1.5. Additional restrictions apply when
    /// PCA is enabled, as described in 6.2.5.4.
    const A_MIN_CAP_LENGTH: NsDuration;

    // MAC PIB attributes of IEEE 802.15.4-2024, section 8.4.3.1, Table 8-36

    /// The type of the FCS, as defined in 7.2.11. A value of zero indicates a
    /// 4-octet FCS. A value of one indicates a 2-octet FCS. This attribute is
    /// only valid for LECIM, TVWS, SUN PHYs, and the HRP UWB PHY in HPRF mode.
    const MAC_FCS_TYPE: u8;

    /// The number of symbols forming the basic time period used by the CSMA-CA
    /// algorithm.
    const MAC_UNIT_BACKOFF_PERIOD: NsDuration;

    /// SIFS: 12 symbols = 192µs
    const MAC_SIFS_PERIOD: NsDuration;

    /// LIFS: 40 symbols = 480µs
    const MAC_LIFS_PERIOD: NsDuration;

    /// AIFS=1ms, for SUN PHY, LECIM PHY, TVWS PHY, SIFS otherwise.
    ///
    /// Note: For some reason this is defined ad-hoc in section 6.6.3.3 rather
    ///       than being a MAC PIB property as the other IFS types. This
    ///       also explains the distinct nomenclature.
    const AIFS: NsDuration;

    /// This is the time it takes for a frame to be received up to the beginning
    /// of the first symbol after the frame's start-of-frame (SFD) marker. This
    /// offset does not take the propagation time from/to the antenna into
    /// account, i.e. it is the offset measured at a fixed point on the signal
    /// propagation path.
    ///
    /// To calculate an offset from the antenna, the phyTxRmarkerOffset or
    /// phyRxRmarkerOffset PIB attributes must be added, see IEEE 802.15.4-2024,
    /// sections 10.29.1.1 and 12.3.2, table 12-2.
    const RMARKER_OFFSET: NsDuration;

}

/// O-QPSK 250kBit PHY
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OQpsk250KBit;

impl OQpsk250KBit {
    /// O-QPSK Start of Frame Delimiter
    pub const DEFAULT_SFD: u8 = 0xA7;

    /// O-QPSK PHY header length
    pub const PHY_HDR_LEN: usize = 1;

    // SHR duration: preamble (8 symbols) + SFD (2 symbols)
    pub const T_SHR: NsDuration =
        <Phy<OQpsk250KBit> as PhyConfig>::SymbolPeriods::from_ticks(10).convert();

    // PHR duration: one byte (2 symbols)
    pub const T_PHR: NsDuration =
        <Phy<OQpsk250KBit> as PhyConfig>::SymbolPeriods::from_ticks(Self::PHY_HDR_LEN as u64 * 2)
            .convert();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Phy<PhyName> {
    _phy: PhantomData<PhyName>,
}

impl<PhyName> Phy<PhyName>
where
    Self: PhyConfig,
{
    pub const fn fcs_length() -> u8 {
        match Self::MAC_FCS_TYPE {
            0 => 4,
            1 => 2,
            _ => panic!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ifs<PhyImpl: PhyConfig> {
    Aifs(PhantomData<PhyImpl>),
    Sifs(PhantomData<PhyImpl>),
    Lifs(PhantomData<PhyImpl>),
    /// Spacing the MAC states outright.
    Exact(NsDuration),
}

impl<PhyImpl: PhyConfig> Ifs<PhyImpl> {
    pub const fn ack() -> Self {
        Self::Aifs(PhantomData)
    }

    pub const fn short() -> Self {
        Self::Sifs(PhantomData)
    }

    pub const fn long() -> Self {
        Self::Lifs(PhantomData)
    }

    /// Spacing given as a duration by the MAC.
    pub const fn exact(spacing: NsDuration) -> Self {
        Self::Exact(spacing)
    }

    pub const fn from_mpdu_length(mpdu_length: u16) -> Self {
        if mpdu_length <= A_MAX_SIFS_FRAME_SIZE {
            Self::short()
        } else {
            Self::long()
        }
    }
}

/// O-QPSK 250kB/s = 31.25kb/s = 62.5ksymbol/s
///
/// Note: 1 byte = 2 symbols
const O_QPSK_SYMBOL_RATE: u32 = 62_500;

impl PhyConfig for Phy<OQpsk250KBit> {
    const SYMBOL_RATE: u32 = O_QPSK_SYMBOL_RATE;

    /// O-QPSK symbol period: 1 / symbol rate, i.e. 16µs.
    type SymbolPeriods = Duration<u64, 1, { O_QPSK_SYMBOL_RATE }>;

    const A_TURNAROUND_TIME: NsDuration = Self::SymbolPeriods::from_ticks(12).convert();

    const PHY_MAX_PACKET_SIZE: u16 = PHY_MAX_PACKET_SIZE_127;
    const PHY_CCA_DURATION: NsDuration = Self::SymbolPeriods::from_ticks(8).convert();

    const A_BASE_SLOT_DURATION: NsDuration = Self::SymbolPeriods::from_ticks(60).convert();
    const A_BASE_SUPERFRAME_DURATION: NsDuration = Self::SymbolPeriods::from_ticks(
        Self::A_BASE_SLOT_DURATION.ticks() * A_NUM_SUPERFRAME_SLOTS as u64,
    )
    .convert();
    const A_MIN_CAP_LENGTH: NsDuration = Self::SymbolPeriods::from_ticks(440).convert();

    const MAC_FCS_TYPE: u8 = 1;
    const MAC_UNIT_BACKOFF_PERIOD: NsDuration = 
        Self::A_TURNAROUND_TIME.checked_add(Self::PHY_CCA_DURATION).unwrap();
    const MAC_SIFS_PERIOD: NsDuration = Self::SymbolPeriods::from_ticks(12).convert();
    const MAC_LIFS_PERIOD: NsDuration = Self::SymbolPeriods::from_ticks(40).convert();
    const AIFS: NsDuration = Self::MAC_SIFS_PERIOD;
    const RMARKER_OFFSET: NsDuration = OQpsk250KBit::T_SHR;
}

const _: () =
    assert!(<Phy<OQpsk250KBit> as PhyConfig>::SymbolPeriods::from_ticks(1).to_micros() == 16);

impl<PhyImpl: PhyConfig> Ifs<PhyImpl> {
    pub const fn into_local_clock_duration(self) -> NsDuration {
        match self {
            Ifs::Aifs(_) => PhyImpl::AIFS,
            Ifs::Sifs(_) => PhyImpl::MAC_SIFS_PERIOD,
            Ifs::Lifs(_) => PhyImpl::MAC_LIFS_PERIOD,
            Ifs::Exact(spacing) => spacing,
        }
    }
}

impl<PhyImpl: PhyConfig> From<Ifs<PhyImpl>> for NsDuration {
    fn from(value: Ifs<PhyImpl>) -> Self {
        value.into_local_clock_duration()
    }
}

/// SUN FSK, 2-FSK at 50 ksymbol/s with a preamble of `PREAMBLE_OCTETS`
/// octets (`phyFskPreambleLength`, 4 to 64; section 19.2.3.1).
///
/// This is operating mode #1 in the bands whose MAC and PHY timing use a
/// 20 µs symbol period (IEEE 802.15.4-2020, Table 19-1), for example the
/// 863-870 MHz band, where Wi-SUN calls it mode 1a.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SunFsk50KSym<const PREAMBLE_OCTETS: u16 = 8>;

/// The SUN FSK symbol rate of operating mode #1 in the bands of Table 19-1
/// with a 20 µs symbol period.
const SUN_FSK_MODE_1_SYMBOL_RATE: u32 = 50_000;

impl<const PREAMBLE_OCTETS: u16> SunFsk50KSym<PREAMBLE_OCTETS> {
    /// SUN FSK PHY header length (section 19.2.4).
    pub const PHY_HDR_LEN: usize = 2;

    /// SFD length for 2-FSK (section 19.2.3.2).
    pub const SFD_LEN: usize = 2;

    // SHR duration: preamble and SFD, 8 symbols per octet.
    pub const T_SHR: NsDuration = <Phy<Self> as PhyConfig>::SymbolPeriods::from_ticks(
        (PREAMBLE_OCTETS as u64 + Self::SFD_LEN as u64) * 8,
    )
    .convert();

    // PHR duration: two octets, 8 symbols each.
    pub const T_PHR: NsDuration =
        <Phy<Self> as PhyConfig>::SymbolPeriods::from_ticks(Self::PHY_HDR_LEN as u64 * 8).convert();
}

impl<const PREAMBLE_OCTETS: u16> PhyConfig for Phy<SunFsk50KSym<PREAMBLE_OCTETS>> {
    const SYMBOL_RATE: u32 = SUN_FSK_MODE_1_SYMBOL_RATE;

    /// 20 µs.
    type SymbolPeriods = Duration<u64, 1, { SUN_FSK_MODE_1_SYMBOL_RATE }>;

    // 1 ms, rounded up to whole symbol periods (Table 11-1).
    const A_TURNAROUND_TIME: NsDuration = Self::SymbolPeriods::from_ticks(50).convert();

    const PHY_MAX_PACKET_SIZE: u16 = PHY_MAX_PACKET_SIZE_2047;
    // aCcaTime: 8 symbol periods (Table 11-1).
    const PHY_CCA_DURATION: NsDuration = Self::SymbolPeriods::from_ticks(8).convert();

    const A_BASE_SLOT_DURATION: NsDuration = Self::SymbolPeriods::from_ticks(60).convert();
    const A_BASE_SUPERFRAME_DURATION: NsDuration =
        Self::SymbolPeriods::from_ticks(60 * A_NUM_SUPERFRAME_SLOTS as u64).convert();
    const A_MIN_CAP_LENGTH: NsDuration = Self::SymbolPeriods::from_ticks(440).convert();

    // macFcsType's default: a 4-octet FCS.
    const MAC_FCS_TYPE: u8 = 0;
    const MAC_UNIT_BACKOFF_PERIOD: NsDuration = Self::A_TURNAROUND_TIME
        .checked_add(Self::PHY_CCA_DURATION)
        .unwrap();
    // Section 10.1.4.
    const MAC_SIFS_PERIOD: NsDuration = Self::SymbolPeriods::from_ticks(12).convert();
    const MAC_LIFS_PERIOD: NsDuration = Self::SymbolPeriods::from_ticks(40).convert();
    // 1 ms for the SUN PHYs (section 6.7.4.3).
    const AIFS: NsDuration = NsDuration::millis(1);
    const RMARKER_OFFSET: NsDuration = SunFsk50KSym::<PREAMBLE_OCTETS>::T_SHR;
}

/// SUN OFDM, any option and MCS, in the bands whose SUN FSK operating mode
/// #1 has a 20 µs symbol period (IEEE 802.15.4-2020, Table 19-1).
///
/// Its symbol period is 120 µs (section 20.1), used for `aTurnaroundTime` and
/// `aCcaTime`; SIFS and LIFS use the 20 µs symbol period of SUN FSK operating
/// mode #1 instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SunOfdm;

impl SunOfdm {
    // SHR duration: the STF's four OFDM symbols (section 20.2.2.3) and the
    // LTF's two, a half-symbol cyclic prefix and two base symbols
    // (section 20.2.3.2).
    pub const T_SHR: NsDuration =
        <Phy<SunOfdm> as PhyConfig>::SymbolPeriods::from_ticks(6).convert();
}

impl PhyConfig for Phy<SunOfdm> {
    /// 8-1/3 ksymbol/s, rounded down.
    const SYMBOL_RATE: u32 = 8_333;

    /// 120 µs.
    type SymbolPeriods = Duration<u64, 3, 25_000>;

    // 1 ms, rounded up to whole symbol periods (Table 11-1).
    const A_TURNAROUND_TIME: NsDuration = Self::SymbolPeriods::from_ticks(9).convert();

    const PHY_MAX_PACKET_SIZE: u16 = PHY_MAX_PACKET_SIZE_2047;
    // aCcaTime: 8 symbol periods (Table 11-1).
    const PHY_CCA_DURATION: NsDuration = Self::SymbolPeriods::from_ticks(8).convert();

    const A_BASE_SLOT_DURATION: NsDuration = Self::SymbolPeriods::from_ticks(60).convert();
    const A_BASE_SUPERFRAME_DURATION: NsDuration =
        Self::SymbolPeriods::from_ticks(60 * A_NUM_SUPERFRAME_SLOTS as u64).convert();
    const A_MIN_CAP_LENGTH: NsDuration = Self::SymbolPeriods::from_ticks(440).convert();

    // macFcsType's default: a 4-octet FCS.
    const MAC_FCS_TYPE: u8 = 0;
    const MAC_UNIT_BACKOFF_PERIOD: NsDuration = Self::A_TURNAROUND_TIME
        .checked_add(Self::PHY_CCA_DURATION)
        .unwrap();
    // SUN FSK operating mode #1's symbol period (section 20.1).
    const MAC_SIFS_PERIOD: NsDuration = <Phy<SunFsk50KSym> as PhyConfig>::MAC_SIFS_PERIOD;
    const MAC_LIFS_PERIOD: NsDuration = <Phy<SunFsk50KSym> as PhyConfig>::MAC_LIFS_PERIOD;
    // 1 ms for the SUN PHYs (section 6.7.4.3).
    const AIFS: NsDuration = NsDuration::millis(1);
    const RMARKER_OFFSET: NsDuration = SunOfdm::T_SHR;
}

#[cfg(test)]
mod ifs_tests {
    use super::*;

    #[test]
    fn sun_fsk_timing() {
        type P = Phy<SunFsk50KSym>;
        assert_eq!(
            <P as PhyConfig>::SymbolPeriods::from_ticks(1).to_micros(),
            20
        );
        assert_eq!(<P as PhyConfig>::A_TURNAROUND_TIME, NsDuration::millis(1));
        assert_eq!(<P as PhyConfig>::PHY_CCA_DURATION, NsDuration::micros(160));
        assert_eq!(
            <P as PhyConfig>::MAC_UNIT_BACKOFF_PERIOD,
            NsDuration::micros(1160)
        );
        assert_eq!(<P as PhyConfig>::MAC_SIFS_PERIOD, NsDuration::micros(240));
        assert_eq!(<P as PhyConfig>::MAC_LIFS_PERIOD, NsDuration::micros(800));
        assert_eq!(<P as PhyConfig>::PHY_MAX_PACKET_SIZE, 2047);
        assert_eq!(P::fcs_length(), 4);
        // An 8-octet preamble and a 2-octet SFD: 80 symbols.
        assert_eq!(<P as PhyConfig>::RMARKER_OFFSET, NsDuration::micros(1600));
        assert_eq!(SunFsk50KSym::<8>::T_PHR, NsDuration::micros(320));
        assert_eq!(
            <Phy<SunFsk50KSym<4>> as PhyConfig>::RMARKER_OFFSET,
            NsDuration::micros(960)
        );
        assert_eq!(
            Ifs::<P>::ack().into_local_clock_duration(),
            NsDuration::millis(1)
        );
    }

    #[test]
    fn sun_ofdm_timing() {
        type P = Phy<SunOfdm>;
        assert_eq!(
            <P as PhyConfig>::SymbolPeriods::from_ticks(1).to_micros(),
            120
        );
        // 1 ms is 8-1/3 symbols, rounded up to 9.
        assert_eq!(
            <P as PhyConfig>::A_TURNAROUND_TIME,
            NsDuration::micros(1080)
        );
        assert_eq!(<P as PhyConfig>::PHY_CCA_DURATION, NsDuration::micros(960));
        assert_eq!(
            <P as PhyConfig>::MAC_UNIT_BACKOFF_PERIOD,
            NsDuration::micros(2040)
        );
        assert_eq!(<P as PhyConfig>::MAC_SIFS_PERIOD, NsDuration::micros(240));
        assert_eq!(<P as PhyConfig>::MAC_LIFS_PERIOD, NsDuration::micros(800));
        assert_eq!(<P as PhyConfig>::RMARKER_OFFSET, NsDuration::micros(720));
        assert_eq!(
            Ifs::<P>::long().into_local_clock_duration(),
            NsDuration::micros(800)
        );
    }

    #[test]
    fn exact_spacing_is_passed_through() {
        let spacing = NsDuration::micros(450);
        assert_eq!(
            Ifs::<Phy<OQpsk250KBit>>::exact(spacing).into_local_clock_duration(),
            spacing
        );
        assert_ne!(spacing, <Phy<OQpsk250KBit> as PhyConfig>::AIFS);
    }
}
