//! Proc-table walker - `LoadProcs` in
//! `uPSRuntime.pas:2802-2933`.
//!
//! Each `ProcCount` slot starts with `TPSProc = packed record
//! Flags: Byte end;` (`uPSRuntime.pas:1223-1225`). The flag bits
//! are:
//!
//! - `Flags & 1` - external proc (name + optional decl).
//! - `Flags & 2` - exported (per-kind: internal procs gain
//!   export-name + decl; external procs aren't gated by this bit).
//! - `Flags & 3 == 3` (external + exported) - external procs add
//!   a 4-byte-prefixed decl after the name.
//! - `Flags & 4` - has a build-21+ attribute block.
//!
//! External procs serialize as `(name_len: u8, name, [decl_len:
//! u32, decl])`. Internal procs serialize as
//! `(bytecode_offset: u32, bytecode_len: u32, [export_name_len:
//! u32, export_name, decl_len: u32, decl])`. Both flavors may be
//! followed by an attribute block when `Flags & 4` is set.

use crate::{attribute::Attribute, error::Error, header::INVALID_VAL, reader::Reader};

const FLAG_EXTERNAL: u8 = 0x01;
const FLAG_EXPORTED: u8 = 0x02;
const FLAG_HAS_ATTRIBUTES: u8 = 0x04;

/// Address-space sentinel from upstream (`uPSUtils.pas:24`).
/// `PSAddrNegativeStackStart = 0x40000000` - name/decl lengths
/// must stay below this to be addressable.
const MAX_NAME_LEN: u32 = 0x4000_0000;

/// One entry in the proc table.
#[derive(Clone, Debug)]
pub struct Proc<'a> {
    /// Raw flag byte (preserves bits beyond the documented set
    /// for forward compatibility).
    pub flags_raw: u8,
    /// Variant-specific data - external import vs. internal
    /// script-defined proc.
    pub kind: ProcKind<'a>,
    /// Build-21+ attributes attached to this proc, populated
    /// when `Flags & 4` is set.
    pub attributes: Vec<Attribute<'a>>,
}

/// External vs. internal split mirroring upstream's
/// `TPSExternalProcRec` / `TPSInternalProcRec`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ProcKind<'a> {
    /// Imported from the host application's API. The compiled
    /// script references the host by `name`; the host's runtime
    /// resolves and dispatches.
    External(ExternalProc<'a>),
    /// Script-defined procedure - has bytecode at
    /// `(bytecode_offset, bytecode_len)` inside the IFPS blob.
    Internal(InternalProc<'a>),
}

/// External (imported) proc.
#[derive(Clone, Debug)]
pub struct ExternalProc<'a> {
    /// Imported function name as written by the host
    /// (e.g. `"ExpandConstant"`, `"RegSetValueEx"`).
    pub name: &'a [u8],
    /// Pascal type-signature declaration. Present only when
    /// `Flags & 3 == 3` upstream (`uPSRuntime.pas:2834-2846`).
    pub decl: Option<&'a [u8]>,
}

/// Internal (script-defined) proc.
#[derive(Clone, Debug)]
pub struct InternalProc<'a> {
    /// Byte offset of the proc's bytecode within the IFPS blob.
    /// 1-based in upstream - `Move(s[L2 + 1], …)` - but we
    /// surface it as the 0-based offset that's actually useful.
    pub bytecode_offset: u32,
    /// Length of the bytecode body in bytes.
    pub bytecode_len: u32,
    /// Export name when the proc is `Flags & 2` (exported).
    pub export_name: Option<&'a [u8]>,
    /// Pascal-style type signature for exported procs.
    pub export_decl: Option<&'a [u8]>,
}

/// Parses one proc-table entry's body (no attribute block),
/// advancing `reader`. The caller is expected to push the
/// resulting [`Proc`] onto the proc table and **then** invoke
/// [`crate::attribute::parse_block`] when the
/// returned `flags_raw` has [`FLAG_HAS_ATTRIBUTES`] set -
/// matching upstream's `LoadProcs` push-then-attr order
/// (`uPSRuntime.pas:2922-2932`).
pub(crate) fn parse_proc<'a>(reader: &mut Reader<'a>, blob_len: usize) -> Result<Proc<'a>, Error> {
    let flags = reader.u8("proc Flags")?;
    let kind = if (flags & FLAG_EXTERNAL) != 0 {
        let name_len = reader.u8("external proc name length")?;
        let name = reader.take(name_len as usize, "external proc name")?;
        let decl = if (flags & FLAG_EXPORTED) != 0 {
            let len = reader.u32_le("external proc decl length")?;
            if len > MAX_NAME_LEN {
                return Err(Error::Overflow {
                    what: "external proc decl length",
                });
            }
            Some(reader.take(len as usize, "external proc decl bytes")?)
        } else {
            None
        };
        ProcKind::External(ExternalProc { name, decl })
    } else {
        let bytecode_offset = reader.u32_le("internal proc bytecode offset")?;
        let bytecode_len = reader.u32_le("internal proc bytecode length")?;
        check_bytecode_range(bytecode_offset, bytecode_len, blob_len)?;
        let (export_name, export_decl) = if (flags & FLAG_EXPORTED) != 0 {
            let name_len = reader.u32_le("internal proc export-name length")?;
            if name_len > MAX_NAME_LEN {
                return Err(Error::Overflow {
                    what: "internal proc export-name length",
                });
            }
            let name = reader.take(name_len as usize, "internal proc export-name")?;
            let decl_len = reader.u32_le("internal proc export-decl length")?;
            if decl_len > MAX_NAME_LEN {
                return Err(Error::Overflow {
                    what: "internal proc export-decl length",
                });
            }
            let decl = reader.take(decl_len as usize, "internal proc export-decl")?;
            (Some(name), Some(decl))
        } else {
            (None, None)
        };
        ProcKind::Internal(InternalProc {
            bytecode_offset,
            bytecode_len,
            export_name,
            export_decl,
        })
    };
    Ok(Proc {
        flags_raw: flags,
        kind,
        attributes: Vec::new(),
    })
}

/// Returns `true` when `flags_raw` has the build-21+
/// "has attributes" bit set (`Flags & 4`).
pub(crate) fn has_attributes(flags_raw: u8) -> bool {
    (flags_raw & FLAG_HAS_ATTRIBUTES) != 0
}

fn check_bytecode_range(offset: u32, length: u32, blob_len: usize) -> Result<(), Error> {
    // Upstream guards: L2 < 0 (impossible for u32), L2 >= len,
    // L2 + L3 > len, L3 == 0. We mirror the L3 == 0 check too.
    if length == 0 || offset == INVALID_VAL {
        return Err(Error::BytecodeOutOfRange { offset, length });
    }
    let end = u64::from(offset)
        .checked_add(u64::from(length))
        .ok_or(Error::Overflow {
            what: "internal proc bytecode end offset",
        })?;
    if end > blob_len as u64 {
        return Err(Error::BytecodeOutOfRange { offset, length });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_le32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn parses_external_proc_without_decl() {
        // Flags=1, name="MsgBox" (no decl).
        let mut buf = vec![0x01, 6];
        buf.extend_from_slice(b"MsgBox");
        let mut r = Reader::new(&buf);
        let p = parse_proc(&mut r, buf.len()).unwrap();
        match p.kind {
            ProcKind::External(ext) => {
                assert_eq!(ext.name, b"MsgBox");
                assert!(ext.decl.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn parses_external_proc_with_decl() {
        // Flags=3 (external | exported), name="Foo", decl="(): Integer".
        let mut buf = vec![0x03, 3];
        buf.extend_from_slice(b"Foo");
        put_le32(&mut buf, 11);
        buf.extend_from_slice(b"(): Integer");
        let mut r = Reader::new(&buf);
        let p = parse_proc(&mut r, buf.len()).unwrap();
        match p.kind {
            ProcKind::External(ext) => {
                assert_eq!(ext.name, b"Foo");
                assert_eq!(ext.decl, Some(&b"(): Integer"[..]));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn parses_internal_proc_minimal() {
        // Flags=0, offset=0x10, length=0x20.
        let mut buf = vec![0x00];
        put_le32(&mut buf, 0x10);
        put_le32(&mut buf, 0x20);
        // Pad blob to 0x40 bytes so the bytecode-range check passes.
        buf.resize(0x40, 0);
        let mut r = Reader::new(&buf);
        let p = parse_proc(&mut r, buf.len()).unwrap();
        match p.kind {
            ProcKind::Internal(int) => {
                assert_eq!(int.bytecode_offset, 0x10);
                assert_eq!(int.bytecode_len, 0x20);
                assert!(int.export_name.is_none());
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn rejects_internal_proc_past_blob() {
        // offset=0x10, length=0x100 - exceeds 0x40-byte blob.
        let mut buf = vec![0x00];
        put_le32(&mut buf, 0x10);
        put_le32(&mut buf, 0x100);
        let mut r = Reader::new(&buf);
        let err = parse_proc(&mut r, 0x40).unwrap_err();
        assert!(matches!(err, Error::BytecodeOutOfRange { .. }));
    }
}
