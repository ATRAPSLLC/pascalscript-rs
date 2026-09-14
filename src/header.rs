//! `TPSHeader` - the fixed 28-byte preamble of every IFPS blob.
//!
//! Wire layout (`uPSRuntime.pas:1204-1212`):
//!
//! ```text
//! TPSHeader = packed record
//!     HDR: Cardinal;              { 'IFPS' magic = 0x53504649 LE }
//!     PSBuildNo: Cardinal;        { format build, [12, 23] }
//!     TypeCount: Cardinal;
//!     ProcCount: Cardinal;
//!     VarCount: Cardinal;
//!     MainProcNo: Cardinal;       { entry point, or InvalidVal = u32::MAX }
//!     ImportTableSize: Cardinal;  { unused-since-build-21 placeholder }
//! end;
//! ```
//!
//! The `ImportTableSize` field is included for forward parity with
//! the upstream layout but `LoadData` (`uPSRuntime.pas:3030`) does
//! not actually walk an import table - externals are stored
//! inline on the proc table, with their `Flags & 1` bit set.

use crate::{error::Error, reader::Reader};

/// Canonical magic byte sequence - first 4 bytes of every IFPS
/// blob. Mirrors [`PS_VALID_HEADER`].
pub const IFPS_MAGIC: [u8; 4] = *b"IFPS";

/// Magic value as a `u32` (little-endian read of [`IFPS_MAGIC`]).
/// Source: `uPSUtils.pas:20` (`PSValidHeader = 1397769801`).
pub const PS_VALID_HEADER: u32 = 0x5350_4649;

/// Lowest `PSBuildNo` the upstream deserializer accepts.
/// Source: `uPSUtils.pas:14` (`PSLowBuildSupport = 12`).
pub const PS_LOW_BUILD_SUPPORT: u32 = 12;

/// Highest `PSBuildNo` the upstream deserializer accepts at the
/// pinned `Components/UniPs/rev.txt` revision.
/// Source: `uPSUtils.pas:16` (`PSCurrentBuildNo = 23`).
pub const PS_CURRENT_BUILD_NO: u32 = 23;

/// Sentinel value [`Header::main_proc_no`] uses when the blob has
/// no entry point. Source: `uPSRuntime.pas:3024` (`HDR.MainProcNo
/// <> InvalidVal`).
pub const INVALID_VAL: u32 = u32::MAX;

/// Total header size in bytes - `SizeOf(TPSHeader)` in upstream.
pub const HEADER_SIZE: usize = 28;

/// Parsed [`TPSHeader`](https://github.com/remobjects/pascalscript)
/// fields.
///
/// Construct via [`Header::parse`]; instances are pure value
/// types (no buffer borrow).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// PascalScript serializer build number (12..=23 supported).
    pub build_no: u32,
    /// Number of entries in the type table.
    pub type_count: u32,
    /// Number of entries in the proc table.
    pub proc_count: u32,
    /// Number of entries in the global-variable table.
    pub var_count: u32,
    /// Index of the main entry-point procedure, or
    /// [`INVALID_VAL`] when the blob has no main proc.
    pub main_proc_no: u32,
    /// Trailing `ImportTableSize` field. Retained for layout
    /// parity but has no functional role at the supported build
    /// range - the proc table carries import data inline.
    pub import_table_size: u32,
}

impl Header {
    /// Parses the 28-byte fixed header at the start of `bytes`.
    ///
    /// # Errors
    ///
    /// - [`Error::Truncated`] when `bytes.len() < 28`.
    /// - [`Error::BadMagic`] when the leading 4 bytes are not
    ///   [`IFPS_MAGIC`].
    /// - [`Error::UnsupportedBuild`] when `PSBuildNo` falls
    ///   outside `[PS_LOW_BUILD_SUPPORT, PS_CURRENT_BUILD_NO]`.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let magic = reader.array::<4>("IFPS magic")?;
        if magic != IFPS_MAGIC {
            return Err(Error::BadMagic { got: magic });
        }
        let build_no = reader.u32_le("PSBuildNo")?;
        if !(PS_LOW_BUILD_SUPPORT..=PS_CURRENT_BUILD_NO).contains(&build_no) {
            return Err(Error::UnsupportedBuild { build_no });
        }
        let type_count = reader.u32_le("TypeCount")?;
        let proc_count = reader.u32_le("ProcCount")?;
        let var_count = reader.u32_le("VarCount")?;
        let main_proc_no = reader.u32_le("MainProcNo")?;
        let import_table_size = reader.u32_le("ImportTableSize")?;
        Ok(Self {
            build_no,
            type_count,
            proc_count,
            var_count,
            main_proc_no,
            import_table_size,
        })
    }

    /// Returns `true` when [`Self::main_proc_no`] is the sentinel
    /// [`INVALID_VAL`] (no entry point).
    pub fn has_no_main_proc(&self) -> bool {
        self.main_proc_no == INVALID_VAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth(magic: [u8; 4], build: u32) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_SIZE);
        v.extend_from_slice(&magic);
        v.extend_from_slice(&build.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // TypeCount
        v.extend_from_slice(&0u32.to_le_bytes()); // ProcCount
        v.extend_from_slice(&0u32.to_le_bytes()); // VarCount
        v.extend_from_slice(&INVALID_VAL.to_le_bytes()); // MainProcNo
        v.extend_from_slice(&0u32.to_le_bytes()); // ImportTableSize
        v
    }

    #[test]
    fn rejects_short_input() {
        let err = Header::parse(b"IFPS").unwrap_err();
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn rejects_bad_magic() {
        let err = Header::parse(&synth(*b"XXXX", 23)).unwrap_err();
        assert!(matches!(err, Error::BadMagic { got } if got == *b"XXXX"));
    }

    #[test]
    fn rejects_too_old_build() {
        let err = Header::parse(&synth(IFPS_MAGIC, 11)).unwrap_err();
        assert!(matches!(err, Error::UnsupportedBuild { build_no: 11 }));
    }

    #[test]
    fn rejects_too_new_build() {
        let err = Header::parse(&synth(IFPS_MAGIC, 99)).unwrap_err();
        assert!(matches!(err, Error::UnsupportedBuild { build_no: 99 }));
    }

    #[test]
    fn accepts_valid_header() {
        let header = Header::parse(&synth(IFPS_MAGIC, 23)).unwrap();
        assert_eq!(header.build_no, 23);
        assert_eq!(header.type_count, 0);
        assert!(header.has_no_main_proc());
    }
}
