//! Error type for the [`pascal_script`](crate)
//! parser.
//!
//! Self-contained: no transitive dependency on `crate::error` so
//! the module remains lift-and-shift portable.

use std::fmt;

/// Failure modes of the IFPS parser.
///
/// Every variant either describes a wire-level malformation
/// (truncation, bad magic, version out of range) or a semantic
/// invariant the upstream RemObjects deserializer also enforces
/// (out-of-range type ref, infinite type cycle, etc.).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// `bytes` were too short to contain the field named by
    /// `what` - typically the 28-byte header, or a fixed payload
    /// past the header.
    Truncated {
        /// Static label for the truncated structure.
        what: &'static str,
    },
    /// Leading 4 bytes were not the canonical
    /// [`PS_VALID_HEADER`](crate::header::PS_VALID_HEADER)
    /// magic. Either the blob isn't IFPS or it's been corrupted.
    BadMagic {
        /// The 4 bytes actually read.
        got: [u8; 4],
    },
    /// `PSBuildNo` falls outside the
    /// `[PSLowBuildSupport, PSCurrentBuildNo]` window the
    /// reference deserializer accepts.
    UnsupportedBuild {
        /// The build number read from the header.
        build_no: u32,
    },
    /// A `BaseType` byte was outside the documented range
    /// (`uPSUtils.pas:46-118`). Forward-compatible parsers may
    /// promote this to `Unknown`; we surface it explicitly so the
    /// caller can decide.
    UnknownBaseType {
        /// Raw byte read from the type record.
        byte: u8,
    },
    /// A type-table entry referenced an index outside the table.
    TypeIndexOutOfRange {
        /// Index that overflowed.
        index: u32,
        /// Number of types declared in the header.
        count: u32,
    },
    /// An internal proc declared a `(offset, length)` pair into
    /// the bytecode pool that fell outside the input buffer.
    BytecodeOutOfRange {
        /// Bytecode offset claimed by the proc.
        offset: u32,
        /// Bytecode length claimed by the proc.
        length: u32,
    },
    /// An integer overflow occurred while computing a buffer
    /// offset or size - the input contains a value too large to
    /// represent on this platform.
    Overflow {
        /// Static label identifying the overflowing computation.
        what: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { what } => {
                write!(f, "truncated input: {what} runs past end of buffer")
            }
            Self::BadMagic { got } => {
                write!(f, "bad IFPS magic: expected `IFPS`, got {got:02x?}")
            }
            Self::UnsupportedBuild { build_no } => {
                write!(f, "unsupported PSBuildNo: {build_no}")
            }
            Self::UnknownBaseType { byte } => {
                write!(f, "unknown PascalScript BaseType: 0x{byte:02x}")
            }
            Self::TypeIndexOutOfRange { index, count } => {
                write!(f, "type index {index} out of range (count={count})")
            }
            Self::BytecodeOutOfRange { offset, length } => {
                write!(
                    f,
                    "bytecode pointer ({offset}, {length}) falls outside the input",
                )
            }
            Self::Overflow { what } => write!(f, "integer overflow computing {what}"),
        }
    }
}

impl std::error::Error for Error {}
