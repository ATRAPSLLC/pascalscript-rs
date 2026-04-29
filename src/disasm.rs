//! Symbolic disassembly — render a [`ProcDisasm`] as text with
//! operand indices resolved against the container's symbol
//! tables.
//!
//! Output is a per-instruction listing: 4-digit hex offset,
//! mnemonic, operand list. Names come from the type / proc / var
//! tables when available, with `g#N`, `s+N`, `proc#N`, `type#N`
//! fallbacks for unnamed entries. PC-relative branch targets
//! (`Goto`, `PopAndGoto`, `Pop2AndGoto`) are resolved to absolute
//! offsets via [`Instruction::next_offset`]; absolute branches
//! (`FlagGoto`) print verbatim.
//!
//! Control-flow reconstruction (loop / if-else detection from
//! goto patterns) is deferred — the raw target offsets in the
//! output are sufficient for tracing manually, and the
//! basic-block analysis required for structural recovery is its
//! own substantial layer.

use std::fmt;

use crate::{
    bytecode::{Instruction, ProcDisasm},
    container::Container,
    literal::Literal,
    opcode::{CalcOp, CompareOp, ExceptionHandlerEnd, Opcode},
    operand::{Operand, VarRef},
    proc::{Proc, ProcKind},
};

/// One-line summary of a [`Container`] — counts of types, procs
/// (split into internal vs. external), vars, plus the wire build
/// number. Suitable for triage / log output.
///
/// Returned by [`Container::display_summary`]; implements
/// [`fmt::Display`].
#[derive(Clone, Copy)]
pub struct ContainerSummary<'a, 'c> {
    container: &'c Container<'a>,
}

impl<'a, 'c> ContainerSummary<'a, 'c> {
    /// Wraps `container` for printing.
    pub fn new(container: &'c Container<'a>) -> Self {
        Self { container }
    }
}

impl fmt::Display for ContainerSummary<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header = self.container.header();
        let (internal, external) =
            self.container
                .procs()
                .iter()
                .fold((0usize, 0usize), |(int, ext), proc| match &proc.kind {
                    ProcKind::Internal(_) => (int.saturating_add(1), ext),
                    ProcKind::External(_) => (int, ext.saturating_add(1)),
                });
        let main_proc = match self.container.main_proc() {
            Some(proc) => match &proc.kind {
                ProcKind::Internal(int) => match int.export_name {
                    Some(name) => format!("main={}", DisplayBytes(name)),
                    None => format!("main=#{}", header.main_proc_no),
                },
                ProcKind::External(_) => format!("main=#{}", header.main_proc_no),
            },
            None => "no-main".to_string(),
        };
        write!(
            f,
            "IFPS build {} — {} types, {} procs ({} internal / {} external), {} vars, {main_proc}",
            header.build_no,
            header.type_count,
            header.proc_count,
            internal,
            external,
            header.var_count,
        )
    }
}

/// Renderable view that pairs a [`ProcDisasm`] with the
/// [`Container`] it came from for symbol resolution.
///
/// Construct via [`Container::display`] or directly via
/// [`Self::new`]. Implements [`fmt::Display`] — drop into
/// `println!`, `format!`, or any other formatting context.
#[derive(Clone, Copy)]
pub struct DisasmDisplay<'a, 'c> {
    container: &'c Container<'a>,
    disasm: &'c ProcDisasm<'a>,
}

impl<'a, 'c> DisasmDisplay<'a, 'c> {
    /// Wraps `container` + `disasm` for printing.
    pub fn new(container: &'c Container<'a>, disasm: &'c ProcDisasm<'a>) -> Self {
        Self { container, disasm }
    }
}

impl fmt::Display for DisasmDisplay<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proc_index = self.disasm.proc_index;
        let proc_label = self
            .container
            .procs()
            .get(proc_index as usize)
            .map(format_proc_self_label)
            .unwrap_or_else(|| format!("proc#{proc_index}"));
        writeln!(
            f,
            "{proc_label}  bytecode @{:#06x} ({} bytes, {} instructions)",
            self.disasm.bytecode_offset,
            // bytecode_len isn't stored on ProcDisasm directly;
            // reconstruct from the last instruction's
            // next_offset minus bytecode_offset.
            self.disasm
                .instructions
                .last()
                .map(|inst| inst.next_offset.saturating_sub(self.disasm.bytecode_offset))
                .unwrap_or(0),
            self.disasm.instructions.len(),
        )?;
        for inst in &self.disasm.instructions {
            write_instruction(f, self.container, inst)?;
        }
        Ok(())
    }
}

fn format_proc_self_label(proc: &Proc<'_>) -> String {
    match &proc.kind {
        ProcKind::Internal(int) => match int.export_name {
            Some(name) => format!("{}", DisplayBytes(name)),
            None => "proc#?".to_string(),
        },
        ProcKind::External(_) => "proc#?".to_string(), // disasm shouldn't be called on externals
    }
}

fn write_instruction(
    f: &mut fmt::Formatter<'_>,
    container: &Container<'_>,
    inst: &Instruction<'_>,
) -> fmt::Result {
    write!(f, "  {:#06x}  ", inst.offset)?;
    match &inst.opcode {
        Opcode::Assign { dest, src } => writeln!(
            f,
            "assign      {}, {}",
            FormatOperand::new(container, dest),
            FormatOperand::new(container, src),
        ),
        Opcode::CalculateAssign { op, dest, src } => writeln!(
            f,
            "calc.{:<5} {}, {}",
            calc_op_name(*op),
            FormatOperand::new(container, dest),
            FormatOperand::new(container, src),
        ),
        Opcode::Push { var } => {
            writeln!(f, "push        {}", FormatOperand::new(container, var))
        }
        Opcode::PushVar { var } => {
            writeln!(f, "push-ref    {}", FormatOperand::new(container, var))
        }
        Opcode::Pop => writeln!(f, "pop"),
        Opcode::Call { proc_no } => {
            writeln!(f, "call        {}", format_proc_ref(container, *proc_no),)
        }
        Opcode::Goto { offset } => writeln!(
            f,
            "goto        {:#06x}",
            absolute_target(inst.next_offset, *offset),
        ),
        Opcode::CondGoto { offset, cond } => writeln!(
            f,
            "if          {} goto {:#06x}",
            FormatOperand::new(container, cond),
            absolute_target_unsigned(inst.next_offset, *offset),
        ),
        Opcode::CondNotGoto { offset, cond } => writeln!(
            f,
            "if not      {} goto {:#06x}",
            FormatOperand::new(container, cond),
            absolute_target_unsigned(inst.next_offset, *offset),
        ),
        Opcode::Return => writeln!(f, "ret"),
        Opcode::SetStackType {
            new_type,
            offset_from_base,
        } => writeln!(
            f,
            "set-stack-type {} at +{offset_from_base}",
            format_type_ref(container, *new_type),
        ),
        Opcode::PushType { type_no } => {
            writeln!(f, "push-temp   {}", format_type_ref(container, *type_no),)
        }
        Opcode::Compare { op, into, lhs, rhs } => writeln!(
            f,
            "cmp.{:<5}  {} := {} {} {}",
            compare_op_name(*op),
            FormatOperand::new(container, into),
            FormatOperand::new(container, lhs),
            compare_op_symbol(*op),
            FormatOperand::new(container, rhs),
        ),
        Opcode::CallVar { var } => {
            writeln!(f, "call-var    {}", FormatOperand::new(container, var),)
        }
        Opcode::SetPointer { dest, src } => writeln!(
            f,
            "set-ptr     {} := @{}",
            FormatOperand::new(container, dest),
            FormatOperand::new(container, src),
        ),
        Opcode::BoolNot { var } => {
            writeln!(f, "bool-not    {}", FormatOperand::new(container, var))
        }
        Opcode::Negate { var } => {
            writeln!(f, "neg         {}", FormatOperand::new(container, var))
        }
        Opcode::SetFlag { var, invert } => writeln!(
            f,
            "set-flag    {}{}",
            if *invert { "not " } else { "" },
            FormatOperand::new(container, var),
        ),
        Opcode::FlagGoto { target } => writeln!(f, "flag-goto   {target:#06x}"),
        Opcode::PushExceptionHandler {
            finally_offset,
            exception_offset,
            finally2_offset,
            end_of_block,
        } => writeln!(
            f,
            "try         finally={finally_offset:#06x} except={exception_offset:#06x} \
             finally2={finally2_offset:#06x} end={end_of_block:#06x}",
        ),
        Opcode::PopExceptionHandler { position } => {
            writeln!(f, "end-try     ({})", handler_end_name(*position),)
        }
        Opcode::IntegerNot { var } => {
            writeln!(f, "int-not     {}", FormatOperand::new(container, var))
        }
        Opcode::SetStackPointerToCopy { target } => {
            writeln!(f, "stack-copy  {target:#06x}")
        }
        Opcode::Inc { var } => {
            writeln!(f, "inc         {}", FormatOperand::new(container, var))
        }
        Opcode::Dec { var } => {
            writeln!(f, "dec         {}", FormatOperand::new(container, var))
        }
        Opcode::PopAndGoto { offset } => writeln!(
            f,
            "pop+goto    {:#06x}",
            absolute_target(inst.next_offset, *offset),
        ),
        Opcode::Pop2AndGoto { offset } => writeln!(
            f,
            "pop2+goto   {:#06x}",
            absolute_target(inst.next_offset, *offset),
        ),
        Opcode::Nop => writeln!(f, "nop"),
    }
}

fn absolute_target(next_offset: u32, signed_offset: i32) -> u32 {
    let signed = i64::from(next_offset).wrapping_add(i64::from(signed_offset));
    if signed < 0 {
        0
    } else {
        u32::try_from(signed).unwrap_or(u32::MAX)
    }
}

fn absolute_target_unsigned(next_offset: u32, unsigned_offset: u32) -> u32 {
    next_offset.saturating_add(unsigned_offset)
}

fn calc_op_name(op: CalcOp) -> &'static str {
    match op {
        CalcOp::Add => "add",
        CalcOp::Sub => "sub",
        CalcOp::Mul => "mul",
        CalcOp::Div => "div",
        CalcOp::Mod => "mod",
        CalcOp::Shl => "shl",
        CalcOp::Shr => "shr",
        CalcOp::And => "and",
        CalcOp::Or => "or",
        CalcOp::Xor => "xor",
    }
}

fn compare_op_name(op: CompareOp) -> &'static str {
    match op {
        CompareOp::GreaterEq => "ge",
        CompareOp::LessEq => "le",
        CompareOp::Greater => "gt",
        CompareOp::Less => "lt",
        CompareOp::NotEqual => "ne",
        CompareOp::Equal => "eq",
    }
}

fn compare_op_symbol(op: CompareOp) -> &'static str {
    match op {
        CompareOp::GreaterEq => ">=",
        CompareOp::LessEq => "<=",
        CompareOp::Greater => ">",
        CompareOp::Less => "<",
        CompareOp::NotEqual => "<>",
        CompareOp::Equal => "=",
    }
}

fn handler_end_name(p: ExceptionHandlerEnd) -> &'static str {
    match p {
        ExceptionHandlerEnd::EndOfBlock => "end",
        ExceptionHandlerEnd::EndOfFirstFinally => "finally",
        ExceptionHandlerEnd::EndOfExcept => "except",
        ExceptionHandlerEnd::EndOfSecondFinally => "finally2",
    }
}

fn format_proc_ref(container: &Container<'_>, proc_no: u32) -> String {
    let Some(proc) = container.procs().get(proc_no as usize) else {
        return format!("proc#{proc_no}?");
    };
    match &proc.kind {
        ProcKind::External(ext) => {
            if !ext.name.is_empty() {
                return format!("{}", DisplayBytes(ext.name));
            }
            // Class-method imports leave `name` empty and pack
            // the binding into `decl` as e.g.
            // "class:TCONTROL|CREATE|...". Show the
            // class:method-prefix portion of the decl when name
            // is missing.
            match ext.decl {
                Some(decl) => {
                    let visible: &[u8] = decl
                        .iter()
                        .position(|&b| b == 0 || b == b'\x01')
                        .and_then(|end| decl.get(..end))
                        .unwrap_or(decl);
                    format!("{}", DisplayBytes(visible))
                }
                None => format!("proc#{proc_no}"),
            }
        }
        ProcKind::Internal(int) => match int.export_name {
            Some(name) => format!("{}", DisplayBytes(name)),
            None => format!("proc#{proc_no}"),
        },
    }
}

fn format_type_ref(container: &Container<'_>, type_no: u32) -> String {
    let Some(ty) = container.types().get(type_no as usize) else {
        return format!("type#{type_no}?");
    };
    match ty.export_name {
        Some(name) => format!("{}", DisplayBytes(name)),
        None => format!("type#{type_no}({:?})", ty.base_type),
    }
}

fn format_var_ref(container: &Container<'_>, vr: VarRef) -> String {
    match vr {
        VarRef::Global(idx) => match container.vars().get(idx as usize) {
            Some(v) => match v.export_name {
                Some(name) => format!("{}", DisplayBytes(name)),
                None => format!("g#{idx}"),
            },
            None => format!("g#{idx}?"),
        },
        VarRef::Stack(off) if off >= 0 => format!("s+{off}"),
        VarRef::Stack(off) => format!("s{off}"),
    }
}

/// Wraps an operand for in-place [`fmt::Display`] formatting
/// without intermediate allocations.
struct FormatOperand<'a, 'c> {
    container: &'c Container<'a>,
    operand: &'c Operand<'a>,
}

impl<'a, 'c> FormatOperand<'a, 'c> {
    fn new(container: &'c Container<'a>, operand: &'c Operand<'a>) -> Self {
        Self { container, operand }
    }
}

impl fmt::Display for FormatOperand<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.operand {
            Operand::Var(vr) => write!(f, "{}", format_var_ref(self.container, *vr)),
            Operand::Literal { type_no, value } => {
                write_literal(f, self.container, *type_no, value)
            }
            Operand::Indexed { base, sub_index } => {
                write!(f, "{}[{sub_index}]", format_var_ref(self.container, *base),)
            }
            Operand::DynamicIndexed { base, index_var } => write!(
                f,
                "{}[{}]",
                format_var_ref(self.container, *base),
                format_var_ref(self.container, *index_var),
            ),
        }
    }
}

fn write_literal(
    f: &mut fmt::Formatter<'_>,
    _container: &Container<'_>,
    _type_no: u32,
    value: &Literal<'_>,
) -> fmt::Result {
    match value {
        Literal::U8(v) => write!(f, "{v}u8"),
        Literal::S8(v) => write!(f, "{v}i8"),
        Literal::Char(v) => write!(f, "char({v})"),
        Literal::U16(v) => write!(f, "{v}u16"),
        Literal::S16(v) => write!(f, "{v}i16"),
        Literal::WideChar(v) => write!(f, "wchar({v})"),
        Literal::U32(v) => write!(f, "{v}u32"),
        Literal::S32(v) => write!(f, "{v}i32"),
        Literal::ProcPtr(v) => write!(f, "procptr#{v}"),
        Literal::Single(_) => write!(f, "f32(...)"),
        Literal::U64(v) => write!(f, "{v}u64"),
        Literal::S64(v) => write!(f, "{v}i64"),
        Literal::Double(_) => write!(f, "f64(...)"),
        Literal::Currency(_) => write!(f, "currency(...)"),
        Literal::Extended(_) => write!(f, "f80(...)"),
        Literal::Set(bytes) => {
            write!(f, "set[")?;
            for b in bytes.iter() {
                write!(f, "{b:02x}")?;
            }
            write!(f, "]")
        }
        Literal::String(bytes) => write!(f, "{:?}", DisplayBytes(bytes)),
        Literal::WideString(bytes) | Literal::UnicodeString(bytes) => write_utf16_literal(f, bytes),
    }
}

fn write_utf16_literal(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    // Decode UTF-16LE best-effort; replacement char on lone
    // surrogates / odd-length tails.
    write!(f, "\"")?;
    let mut i: usize = 0;
    while i.saturating_add(1) < bytes.len() {
        let lo = bytes.get(i).copied().unwrap_or(0);
        let hi = bytes.get(i.saturating_add(1)).copied().unwrap_or(0);
        let unit = u16::from_le_bytes([lo, hi]);
        let ch = char::from_u32(unit.into()).unwrap_or(char::REPLACEMENT_CHARACTER);
        if ch == '"' || ch == '\\' {
            write!(f, "\\{ch}")?;
        } else if ch.is_control() {
            write!(f, "\\u{{{:04x}}}", unit)?;
        } else {
            write!(f, "{ch}")?;
        }
        i = i.saturating_add(2);
    }
    write!(f, "\"")
}

/// Helper that formats a byte slice as a quoted ASCII string,
/// rendering non-ASCII bytes as `\xNN` escapes.
struct DisplayBytes<'b>(&'b [u8]);

impl fmt::Display for DisplayBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &byte in self.0 {
            if (0x20..0x7f).contains(&byte) {
                f.write_str(byte_to_str(byte))?;
            } else {
                write!(f, "\\x{byte:02x}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for DisplayBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{self}\"")
    }
}

fn byte_to_str(byte: u8) -> &'static str {
    // Map a printable ASCII byte to its single-character &str.
    // Pre-computed lookup keeps the no-unsafe / no-indexing
    // posture happy without per-call allocation.
    const TABLE: [&str; 128] = [
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "", "", "", "", "", "", "", "", "", " ", "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*",
        "+", ",", "-", ".", "/", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<",
        "=", ">", "?", "@", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N",
        "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "[", "\\", "]", "^", "_", "`",
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r",
        "s", "t", "u", "v", "w", "x", "y", "z", "{", "|", "}", "~", "",
    ];
    TABLE.get(byte as usize).copied().unwrap_or("")
}
