//! Procedure signatures, and what each of a procedure's stack slots holds.
//!
//! An internal procedure's declaration is text the compiler writes with
//! `MakeExportDecl` (`uPSCompiler.pas:13924-13939`): the result's type number
//! (`-1` for a procedure), then one ` @<type>` per in-parameter or ` !<type>`
//! per `var` parameter. An external one is the bit string `DeclToBits` writes
//! (`uPSCompiler.pas:1864-1880`): a byte saying whether there is a result, then
//! one byte per parameter, `1` for `var`. A DLL import prefixes that with
//! `dll:<library>\0<function>\0`, a calling convention, and its delay-load and
//! altered-search-path flags (`uPSC_dll.pas:139`).
//!
//! The declaration also decides the frame. A caller pushes the parameters last
//! to first, then a reference to the result, then calls; the callee's frame
//! base is the return address it pushes (`uPSRuntime.pas:8327-8342`). So inside
//! the body `s-1` is the result, `s-2` the first parameter and so on - or, for
//! a procedure with no result, `s-1` the first parameter - and `s+1` upward
//! are the locals and temporaries the body pushes. [`Signature::slot`] says
//! which.

use std::str;

use crate::error::Error;

/// A procedure's parameters and result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Whether the procedure returns a value (a Pascal function).
    pub returns: bool,
    /// The result's type number, when the declaration states it. An internal
    /// procedure's does; an external one's bit string does not.
    pub result_type: Option<u32>,
    /// The parameters, first to last.
    pub params: Vec<Param>,
}

/// One parameter of a [`Signature`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Param {
    /// A `var` parameter: the caller passes a reference, and a write through
    /// it is a write to the caller's variable.
    pub by_ref: bool,
    /// The parameter's type number, when the declaration states it.
    pub type_no: Option<u32>,
}

/// What a stack slot, addressed relative to a procedure's frame base, holds
/// inside that procedure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameSlot {
    /// `s+0`: the return address the call pushed.
    ReturnAddress,
    /// The reference to the caller's result variable.
    Result,
    /// Parameter `n`, first to last.
    Param(u32),
    /// `s+n`: a local or temporary the body pushed, counted from 1.
    Local(u32),
    /// Below the parameters: nothing this procedure's declaration accounts for.
    Beyond,
}

/// A DLL function an external procedure imports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DllImport<'a> {
    /// The library, as written (`user32.dll`).
    pub library: &'a [u8],
    /// The exported function (`MessageBeep`).
    pub function: &'a [u8],
    /// The calling convention byte: `0` register, `1` pascal, `2` cdecl,
    /// `3` stdcall, `4` safecall (`TPSCallingConvention`).
    pub calling_convention: u8,
    /// Whether the library loads on first call rather than at startup.
    pub delay_load: bool,
    /// Whether it loads with `LOAD_WITH_ALTERED_SEARCH_PATH`.
    pub altered_search_path: bool,
}

/// An external procedure's declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalDecl<'a> {
    /// The DLL function, for a `dll:` import; `None` for a host function.
    pub dll: Option<DllImport<'a>>,
    /// The parameters and result, without types.
    pub signature: Signature,
}

impl Signature {
    /// Parses an internal procedure's `MakeExportDecl` text.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedDecl`] when the text is not a result type followed by
    /// `@`/`!`-marked parameter types.
    pub fn of_internal(decl: &[u8]) -> Result<Self, Error> {
        let malformed = || Error::MalformedDecl {
            what: "internal proc declaration",
        };
        let text = str::from_utf8(decl).map_err(|_| malformed())?;
        let mut words = text.split(' ').filter(|word| !word.is_empty());
        let result = words.next().ok_or_else(malformed)?;
        let result_type = match result {
            "-1" => None,
            number => Some(number.parse::<u32>().map_err(|_| malformed())?),
        };
        let params = words
            .map(|word| {
                let (by_ref, number) = if let Some(number) = word.strip_prefix('!') {
                    (true, number)
                } else if let Some(number) = word.strip_prefix('@') {
                    (false, number)
                } else {
                    return Err(malformed());
                };
                let type_no = number.parse::<u32>().map_err(|_| malformed())?;
                Ok(Param {
                    by_ref,
                    type_no: Some(type_no),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            returns: result_type.is_some(),
            result_type,
            params,
        })
    }

    /// Parses a `DeclToBits` string: a result byte, then one byte per
    /// parameter.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedDecl`] when it is empty or a byte is neither `0` nor
    /// `1`.
    pub fn of_bits(bits: &[u8]) -> Result<Self, Error> {
        let flag = |byte: &u8| match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::MalformedDecl {
                what: "external proc declaration bit",
            }),
        };
        let (result, params) = bits.split_first().ok_or(Error::MalformedDecl {
            what: "external proc declaration",
        })?;
        Ok(Self {
            returns: flag(result)?,
            result_type: None,
            params: params
                .iter()
                .map(|byte| {
                    Ok(Param {
                        by_ref: flag(byte)?,
                        type_no: None,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?,
        })
    }

    /// The number of stack slots a call to this procedure consumes: every
    /// parameter, and the result reference when there is one.
    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.params.len().saturating_add(usize::from(self.returns))
    }

    /// What stack slot `s+offset` holds inside this procedure's body.
    #[must_use]
    pub fn slot(&self, offset: i64) -> FrameSlot {
        if offset == 0 {
            return FrameSlot::ReturnAddress;
        }
        if offset > 0 {
            return u32::try_from(offset).map_or(FrameSlot::Beyond, FrameSlot::Local);
        }
        // `s-1` first: the result when there is one, else the first parameter.
        let below = offset.unsigned_abs();
        let param = if self.returns {
            if below == 1 {
                return FrameSlot::Result;
            }
            below.saturating_sub(2)
        } else {
            below.saturating_sub(1)
        };
        match u32::try_from(param) {
            Ok(index) if (index as usize) < self.params.len() => FrameSlot::Param(index),
            _ => FrameSlot::Beyond,
        }
    }
}

impl<'a> ExternalDecl<'a> {
    /// Parses an external procedure's declaration: a `dll:` import or a host
    /// function's `DeclToBits`.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedDecl`] when a `dll:` import is missing a field, or the
    /// bit string is malformed.
    pub fn parse(decl: &'a [u8]) -> Result<Self, Error> {
        let Some(rest) = decl.strip_prefix(b"dll:") else {
            return Ok(Self {
                dll: None,
                signature: Signature::of_bits(decl)?,
            });
        };
        let malformed = || Error::MalformedDecl {
            what: "dll import declaration",
        };
        let mut fields = rest.splitn(3, |byte| *byte == 0);
        let library = fields.next().ok_or_else(malformed)?;
        let function = fields.next().ok_or_else(malformed)?;
        let tail = fields.next().ok_or_else(malformed)?;
        let [
            calling_convention,
            delay_load,
            altered_search_path,
            bits @ ..,
        ] = tail
        else {
            return Err(malformed());
        };
        Ok(Self {
            dll: Some(DllImport {
                library,
                function,
                calling_convention: *calling_convention,
                delay_load: *delay_load != 0,
                altered_search_path: *altered_search_path != 0,
            }),
            signature: Signature::of_bits(bits)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A function's result is `s-1` and its parameters follow below it; a
    /// procedure's first parameter is `s-1`. Declarations from the compiled
    /// `code.iss` fixture: `SCALE(Value, Factor: Integer): Integer` and
    /// `BUMP(var Target: Integer; Step: Integer)`.
    #[test]
    fn a_declaration_places_the_result_and_parameters() {
        let scale = Signature::of_internal(b"11 @11 @11").unwrap();
        assert!(scale.returns);
        assert_eq!(scale.result_type, Some(11));
        assert_eq!(scale.slot_count(), 3);
        assert_eq!(scale.slot(0), FrameSlot::ReturnAddress);
        assert_eq!(scale.slot(-1), FrameSlot::Result);
        assert_eq!(scale.slot(-2), FrameSlot::Param(0));
        assert_eq!(scale.slot(-3), FrameSlot::Param(1));
        assert_eq!(scale.slot(-4), FrameSlot::Beyond);
        assert_eq!(scale.slot(2), FrameSlot::Local(2));

        let bump = Signature::of_internal(b"-1 !11 @11").unwrap();
        assert!(!bump.returns);
        assert_eq!(
            bump.params,
            [
                Param {
                    by_ref: true,
                    type_no: Some(11)
                },
                Param {
                    by_ref: false,
                    type_no: Some(11)
                },
            ]
        );
        assert_eq!(bump.slot(-1), FrameSlot::Param(0));
        assert_eq!(bump.slot(-2), FrameSlot::Param(1));
        assert_eq!(bump.slot_count(), 2);
    }

    /// A host function states only whether it returns and which parameters
    /// are `var`; a DLL import adds the library, function and loading flags.
    /// `MessageBeep@user32.dll stdcall` as the fixture compiled it.
    #[test]
    fn an_external_declaration_reads_both_forms() {
        let host = ExternalDecl::parse(&[1, 0]).unwrap();
        assert_eq!(host.dll, None);
        assert!(host.signature.returns);
        assert_eq!(host.signature.params.len(), 1);

        let decl = b"dll:user32.dll\0MessageBeep\0\x03\x00\x00\x01\x00";
        let import = ExternalDecl::parse(decl).unwrap();
        assert_eq!(
            import.dll,
            Some(DllImport {
                library: b"user32.dll",
                function: b"MessageBeep",
                calling_convention: 3,
                delay_load: false,
                altered_search_path: false,
            })
        );
        assert!(import.signature.returns);
        assert_eq!(
            import.signature.params,
            [Param {
                by_ref: false,
                type_no: None
            }]
        );
    }

    /// Malformed declarations are errors, never a guessed signature.
    #[test]
    fn a_malformed_declaration_is_refused() {
        assert!(Signature::of_internal(b"").is_err());
        assert!(Signature::of_internal(b"11 #11").is_err());
        assert!(Signature::of_internal(b"x").is_err());
        assert!(Signature::of_bits(&[]).is_err());
        assert!(Signature::of_bits(&[1, 2]).is_err());
        assert!(ExternalDecl::parse(b"dll:user32.dll\0MessageBeep\0\x03").is_err());
    }
}
