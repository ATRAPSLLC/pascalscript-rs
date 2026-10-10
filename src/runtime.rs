//! The functions the PascalScript runtime registers itself, and what each
//! does beyond computing its result.
//!
//! A script calls these like any external procedure, by name, and an
//! embedding host adds its own beside them. The runtime's own are listed in
//! `TPSExec.RegisterStandardProcs` (`uPSRuntime.pas:9905-9975`); what each does
//! is its handler's (`DefProc`, `Length_`, `SetLength_`, `GetArrayLength`,
//! `SetArrayLength`, ...). A name here is matched as the runtime matches it,
//! without regard to case: the compiler writes it upper-cased.
//!
//! Which argument a call passes by reference is visible where it is called -
//! the caller pushes a pointer for it - so what is stated here is only what the
//! declaration cannot say: whether the function writes through those
//! references, whether it can raise, and whether it reads the exception being
//! handled.

/// What a runtime function does beyond computing its result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Builtin {
    /// Computes its result from its arguments and nothing else.
    Pure,
    /// Like [`Self::Pure`], but may raise: a conversion of text that is not a
    /// number, an overflowing rounding.
    MayRaise,
    /// Updates a variable passed by reference (`Delete`, `Insert`, `Inc`,
    /// `SetLength`, `SetArrayLength`, ...).
    UpdatesReference,
    /// Reads the exception being handled (`ExceptionType`, `ExceptionParam`,
    /// ...).
    ReadsException,
    /// Raises, and never returns (`RaiseException`, `RaiseLastException`).
    Raises,
}

/// Every function the runtime registers, by name, and what it does.
const BUILTINS: [(&str, Builtin); 59] = [
    ("IntToStr", Builtin::Pure),
    ("StrToInt", Builtin::MayRaise),
    ("StrToIntDef", Builtin::Pure),
    ("Pos", Builtin::Pure),
    ("Copy", Builtin::Pure),
    ("Delete", Builtin::UpdatesReference),
    ("Insert", Builtin::UpdatesReference),
    ("StrGet", Builtin::MayRaise),
    ("StrSet", Builtin::UpdatesReference),
    ("UpperCase", Builtin::Pure),
    ("LowerCase", Builtin::Pure),
    ("Trim", Builtin::Pure),
    ("Length", Builtin::Pure),
    ("SetLength", Builtin::UpdatesReference),
    ("Low", Builtin::Pure),
    ("High", Builtin::Pure),
    ("Dec", Builtin::UpdatesReference),
    ("Inc", Builtin::UpdatesReference),
    ("Include", Builtin::UpdatesReference),
    ("Exclude", Builtin::UpdatesReference),
    ("Sin", Builtin::Pure),
    ("Cos", Builtin::Pure),
    ("Sqrt", Builtin::MayRaise),
    ("Round", Builtin::MayRaise),
    ("Trunc", Builtin::MayRaise),
    ("Int", Builtin::Pure),
    ("Pi", Builtin::Pure),
    ("Abs", Builtin::Pure),
    ("StrToFloat", Builtin::MayRaise),
    ("FloatToStr", Builtin::Pure),
    ("PadL", Builtin::Pure),
    ("PadR", Builtin::Pure),
    ("PadZ", Builtin::Pure),
    ("Replicate", Builtin::Pure),
    ("StringOfChar", Builtin::Pure),
    ("!ASSIGNED", Builtin::Pure),
    ("Unassigned", Builtin::Pure),
    ("VarIsEmpty", Builtin::Pure),
    ("VarIsClear", Builtin::Pure),
    ("Null", Builtin::Pure),
    ("VarIsNull", Builtin::Pure),
    ("VarType", Builtin::Pure),
    ("GetArrayLength", Builtin::Pure),
    ("SetArrayLength", Builtin::UpdatesReference),
    ("RaiseLastException", Builtin::Raises),
    ("RaiseException", Builtin::Raises),
    ("ExceptionType", Builtin::ReadsException),
    ("ExceptionParam", Builtin::ReadsException),
    ("ExceptionProc", Builtin::ReadsException),
    ("ExceptionPos", Builtin::ReadsException),
    ("ExceptionToString", Builtin::Pure),
    ("AnsiUpperCase", Builtin::Pure),
    ("AnsiLowerCase", Builtin::Pure),
    ("StrToInt64", Builtin::MayRaise),
    ("Int64ToStr", Builtin::Pure),
    ("StrToInt64Def", Builtin::Pure),
    ("SizeOf", Builtin::Pure),
    ("WStrGet", Builtin::MayRaise),
    ("WStrSet", Builtin::UpdatesReference),
];

impl Builtin {
    /// What the runtime function `name` does, or `None` when the runtime does
    /// not register one by that name - a host's function, or a DLL import.
    ///
    /// # Arguments
    ///
    /// * `name` - The external procedure's name, in any case.
    #[must_use]
    pub fn of(name: &[u8]) -> Option<Self> {
        BUILTINS
            .iter()
            .find(|(builtin, _)| builtin.as_bytes().eq_ignore_ascii_case(name))
            .map(|(_, behaviour)| *behaviour)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name matches whatever its case, as the compiler writes it; a host's
    /// function is not the runtime's.
    #[test]
    fn a_runtime_function_is_found_by_its_upper_cased_name() {
        assert_eq!(
            Builtin::of(b"SETARRAYLENGTH"),
            Some(Builtin::UpdatesReference)
        );
        assert_eq!(Builtin::of(b"IntToStr"), Some(Builtin::Pure));
        assert_eq!(Builtin::of(b"RAISEEXCEPTION"), Some(Builtin::Raises));
        assert_eq!(
            Builtin::of(b"FILEEXISTS"),
            None,
            "Inno's, not the runtime's"
        );
    }
}
