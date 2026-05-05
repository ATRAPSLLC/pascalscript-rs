//! Top-level driver: parse an entire IFPS blob into typed views.
//!
//! Walk order matches `TPSExec.LoadData`
//! (`uPSRuntime.pas:2991-3033`): header, then types, then procs,
//! then vars, then validate `MainProcNo`. Build-21+ attribute
//! blocks are recorded as opaque byte slices on each entry and
//! decoded structurally via [`crate::attribute`].

use crate::{
    attribute,
    bytecode::{ProcDisasm, disassemble_proc},
    disasm::{ContainerSummary, DisasmDisplay},
    error::Error,
    header::{HEADER_SIZE, Header},
    proc::{Proc, ProcKind, has_attributes, parse_proc},
    reader::Reader,
    ty::{Type, parse_type},
    var::{Var, parse_var},
};

/// Parsed IFPS blob.
///
/// Borrows from the original byte slice — names, decls, and
/// bytecode regions all reference the original buffer rather
/// than allocating.
#[derive(Clone, Debug)]
pub struct Container<'a> {
    bytes: &'a [u8],
    header: Header,
    types: Vec<Type<'a>>,
    procs: Vec<Proc<'a>>,
    vars: Vec<Var<'a>>,
}

impl<'a> Container<'a> {
    /// Parses an IFPS blob from `bytes`.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Header::parse`] or any of the per-table
    /// walkers (types, procs, vars) surface — see [`Error`] for
    /// the full set.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let header = Header::parse(bytes)?;
        let mut reader = Reader::new(bytes);
        // Position the cursor past the fixed header.
        reader.skip(HEADER_SIZE, "header skip")?;

        let mut types: Vec<Type<'a>> = Vec::with_capacity(header.type_count as usize);
        for _ in 0..header.type_count {
            let so_far = u32::try_from(types.len()).unwrap_or(u32::MAX);
            // Match upstream `LoadTypes` push-then-attr order:
            // the type goes onto the table BEFORE its attribute
            // block reads, so the block can reference any type
            // 0..=N (including itself).
            types.push(parse_type(&mut reader, so_far)?);
            if header.build_no >= 21 {
                let attrs = attribute::parse_block(&mut reader, &types)?;
                if let Some(last) = types.last_mut() {
                    last.attributes = attrs;
                }
            }
        }

        let mut procs: Vec<Proc<'a>> = Vec::with_capacity(header.proc_count as usize);
        for _ in 0..header.proc_count {
            let proc = parse_proc(&mut reader, bytes.len())?;
            let needs_attrs = has_attributes(proc.flags_raw);
            procs.push(proc);
            if needs_attrs {
                let attrs = attribute::parse_block(&mut reader, &types)?;
                if let Some(last) = procs.last_mut() {
                    last.attributes = attrs;
                }
            }
        }

        let mut vars: Vec<Var<'a>> = Vec::with_capacity(header.var_count as usize);
        for _ in 0..header.var_count {
            vars.push(parse_var(&mut reader, header.type_count)?);
        }

        // Mirror upstream: MainProcNo must be either InvalidVal
        // or a valid proc index.
        if !header.has_no_main_proc() && (header.main_proc_no as usize) >= procs.len() {
            return Err(Error::Overflow {
                what: "MainProcNo references missing proc",
            });
        }

        Ok(Self {
            bytes,
            header,
            types,
            procs,
            vars,
        })
    }

    /// Returns the parsed fixed header.
    pub fn header(&self) -> Header {
        self.header
    }

    /// Returns the original blob bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the parsed type table in declaration order.
    pub fn types(&self) -> &[Type<'a>] {
        &self.types
    }

    /// Returns the parsed proc table in declaration order.
    pub fn procs(&self) -> &[Proc<'a>] {
        &self.procs
    }

    /// Returns the number of parsed procedures.
    pub fn proc_count(&self) -> u32 {
        u32::try_from(self.procs.len()).unwrap_or(u32::MAX)
    }

    /// Returns the procedure at `idx`, or `None` when out of range.
    pub fn proc(&self, idx: u32) -> Option<&Proc<'a>> {
        usize::try_from(idx)
            .ok()
            .and_then(|idx| self.procs.get(idx))
    }

    /// Returns the parsed var table in declaration order.
    pub fn vars(&self) -> &[Var<'a>] {
        &self.vars
    }

    /// Returns the entry-point proc, or `None` when the blob has
    /// no main proc (`MainProcNo == u32::MAX`).
    pub fn main_proc(&self) -> Option<&Proc<'a>> {
        if self.header.has_no_main_proc() {
            return None;
        }
        self.procs.get(self.header.main_proc_no as usize)
    }

    /// Wraps `disasm` in a [`DisasmDisplay`] bound to this
    /// container's symbol tables, ready for `format!` /
    /// `println!`. Convenience over constructing the wrapper
    /// manually via [`DisasmDisplay::new`].
    pub fn display<'c>(&'c self, disasm: &'c ProcDisasm<'a>) -> DisasmDisplay<'a, 'c> {
        DisasmDisplay::new(self, disasm)
    }

    /// Returns a [`ContainerSummary`] — single-line
    /// `fmt::Display`-ready triage view (`IFPS build N — A
    /// types, B procs (X internal / Y external), C vars, main=…`).
    pub fn display_summary(&self) -> ContainerSummary<'a, '_> {
        ContainerSummary::new(self)
    }

    /// Disassembles the bytecode body of the proc at
    /// `proc_index`.
    ///
    /// Returns `Ok(None)` when the requested proc is external
    /// (no bytecode body to walk). Returns `Ok(Some(_))` with the
    /// fully decoded instruction stream when the proc is
    /// internal. The returned [`ProcDisasm`] borrows from the
    /// container's IFPS blob.
    ///
    /// # Errors
    ///
    /// - [`Error::TypeIndexOutOfRange`] when `proc_index >=
    ///   procs.len()`.
    /// - [`Error::BytecodeOutOfRange`] /
    ///   [`Error::UnknownBaseType`] / [`Error::Truncated`] when
    ///   an instruction can't be decoded.
    pub fn disassemble(&self, proc_index: u32) -> Result<Option<ProcDisasm<'a>>, Error> {
        let proc = self.proc(proc_index).ok_or(Error::TypeIndexOutOfRange {
            index: proc_index,
            count: self.proc_count(),
        })?;
        let internal = match &proc.kind {
            ProcKind::Internal(int) => int,
            ProcKind::External(_) => return Ok(None),
        };
        let disasm = disassemble_proc(
            self.bytes,
            proc_index,
            internal.bytecode_offset,
            internal.bytecode_len,
            &self.types,
        )?;
        Ok(Some(disasm))
    }
}
