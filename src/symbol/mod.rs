// Copyright 2017 pdb Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt;

use scroll::{ctx::TryFromCtx, Endian, Pread, LE};

use crate::common::*;
use crate::msf::*;
use crate::FallibleIterator;

mod annotations;
mod constants;

use self::constants::*;
pub use self::constants::{CPUType, SourceLanguage};

pub use self::annotations::*;

/// The raw type discriminator for `Symbols`.
pub type SymbolKind = u16;

/// Represents a symbol from the symbol table.
///
/// A `Symbol` is represented internally as a `&[u8]`, and in general the bytes inside are not
/// inspected in any way before calling any of the accessor methods.
///
/// To avoid copying, `Symbol`s exist as references to data owned by the parent `SymbolTable`.
/// Therefore, a `Symbol` may not outlive its parent `SymbolTable`.
#[derive(Copy, Clone, PartialEq)]
pub struct Symbol<'t> {
    index: SymbolIndex,
    data: &'t [u8],
}

impl<'t> Symbol<'t> {
    /// The index of this symbol in the containing symbol stream.
    #[inline]
    pub fn index(&self) -> SymbolIndex {
        self.index
    }

    /// Returns the kind of symbol identified by this Symbol.
    #[inline]
    pub fn raw_kind(&self) -> SymbolKind {
        debug_assert!(self.data.len() >= 2);
        self.data.pread_with(0, LE).unwrap_or_default()
    }

    /// Returns the raw bytes of this symbol record, including the symbol type and extra data, but
    /// not including the preceding symbol length indicator.
    #[inline]
    pub fn raw_bytes(&self) -> &'t [u8] {
        self.data
    }

    /// Parse the symbol into the `SymbolData` it contains.
    #[inline]
    pub fn parse(&self) -> Result<SymbolData<'t>> {
        self.raw_bytes().pread_with(0, ())
    }

    /// Returns whether this symbol starts a scope.
    ///
    /// If `true`, this symbol has a `parent` and an `end` field, which contains the offset of the
    /// corrsponding end symbol.
    pub fn starts_scope(&self) -> bool {
        matches!(
            self.raw_kind(),
            S_GPROC16
                | S_GPROC32
                | S_GPROC32_ST
                | S_GPROCMIPS
                | S_GPROCMIPS_ST
                | S_GPROCIA64
                | S_GPROCIA64_ST
                | S_LPROC16
                | S_LPROC32
                | S_LPROC32_ST
                | S_LPROC32_DPC
                | S_LPROCMIPS
                | S_LPROCMIPS_ST
                | S_LPROCIA64
                | S_LPROCIA64_ST
                | S_LPROC32_DPC_ID
                | S_GPROC32_ID
                | S_GPROCMIPS_ID
                | S_GPROCIA64_ID
                | S_BLOCK16
                | S_BLOCK32
                | S_BLOCK32_ST
                | S_WITH16
                | S_WITH32
                | S_WITH32_ST
                | S_THUNK16
                | S_THUNK32
                | S_THUNK32_ST
                | S_SEPCODE
                | S_GMANPROC
                | S_GMANPROC_ST
                | S_LMANPROC
                | S_LMANPROC_ST
                | S_INLINESITE
                | S_INLINESITE2
        )
    }

    /// Returns whether this symbol declares the end of a scope.
    pub fn ends_scope(&self) -> bool {
        matches!(self.raw_kind(), S_END | S_PROC_ID_END | S_INLINESITE_END)
    }
}

impl<'t> fmt::Debug for Symbol<'t> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Symbol{{ kind: 0x{:x} [{} bytes] }}",
            self.raw_kind(),
            self.data.len()
        )
    }
}

fn parse_symbol_name<'t>(buf: &mut ParseBuffer<'t>, kind: SymbolKind) -> Result<RawString<'t>> {
    if kind < S_ST_MAX {
        // Pascal-style name
        buf.parse_u8_pascal_string()
    } else {
        // NUL-terminated name
        buf.parse_cstring()
    }
}

fn parse_optional_name<'t>(
    buf: &mut ParseBuffer<'t>,
    kind: SymbolKind,
) -> Result<Option<RawString<'t>>> {
    if kind < S_ST_MAX {
        // ST variants do not specify a name
        Ok(None)
    } else {
        // NUL-terminated name
        buf.parse_cstring().map(Some)
    }
}

fn parse_optional_index(buf: &mut ParseBuffer<'_>) -> Result<Option<SymbolIndex>> {
    Ok(match buf.parse()? {
        SymbolIndex(0) => None,
        index => Some(index),
    })
}

// data types are defined at:
//   https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/include/cvinfo.h#L3038
// constants defined at:
//   https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/include/cvinfo.h#L2735
// decoding reference:
//   https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/cvdump/dumpsym7.cpp#L264

/// Information parsed from a [`Symbol`] record.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SymbolData<'t> {
    /// End of a scope, such as a procedure.
    ScopeEnd,
    /// Name of the object file of this module.
    ObjName(ObjNameSymbol<'t>),
    /// A Register variable.
    RegisterVariable(RegisterVariableSymbol<'t>),
    /// A constant value.
    Constant(ConstantSymbol<'t>),
    /// A user defined type.
    UserDefinedType(UserDefinedTypeSymbol<'t>),
    /// A Register variable spanning multiple registers.
    MultiRegisterVariable(MultiRegisterVariableSymbol<'t>),
    /// Static data, such as a global variable.
    Data(DataSymbol<'t>),
    /// A public symbol with a mangled name.
    Public(PublicSymbol<'t>),
    /// A procedure, such as a function or method.
    Procedure(ProcedureSymbol<'t>),
    /// A thread local variable.
    ThreadStorage(ThreadStorageSymbol<'t>),
    /// Flags used to compile a module.
    CompileFlags(CompileFlagsSymbol<'t>),
    /// A using namespace directive.
    UsingNamespace(UsingNamespaceSymbol<'t>),
    /// Reference to a [`ProcedureSymbol`].
    ProcedureReference(ProcedureReferenceSymbol<'t>),
    /// Reference to an imported variable.
    DataReference(DataReferenceSymbol<'t>),
    /// Reference to an annotation.
    AnnotationReference(AnnotationReferenceSymbol<'t>),
    /// Trampoline thunk.
    Trampoline(TrampolineSymbol),
    /// An exported symbol.
    Export(ExportSymbol<'t>),
    /// A local symbol in optimized code.
    Local(LocalSymbol<'t>),
    /// Reference to build information.
    BuildInfo(BuildInfoSymbol),
    /// The callsite of an inlined function.
    InlineSite(InlineSiteSymbol<'t>),
    /// End of an inline callsite.
    InlineSiteEnd,
    /// End of a procedure.
    ProcedureEnd,
    /// A label.
    Label(LabelSymbol<'t>),
    /// A block.
    Block(BlockSymbol<'t>),
    /// Data allocated relative to a register.
    RegisterRelative(RegisterRelativeSymbol<'t>),
    /// A thunk.
    Thunk(ThunkSymbol<'t>),
    /// A block of separated code.
    SeparatedCode(SeparatedCodeSymbol),
    /// Frame procedure information.
    FrameProc(FrameProcSymbol),
    /// Call site information.
    CallSiteInfo(CallSiteInfoSymbol),
    /// DefRange for register symbols.
    DefRangeRegister(DefRangeRegisterSymbol),
    /// DefRange for subfield register symbols.
    DefRangeSubfieldRegister(DefRangeSubfieldRegisterSymbol),
    /// DefRange for frame pointer relative symbols.
    DefRangeFramePointerRel(DefRangeFramePointerRelSymbol),
    /// DefRange for frame pointer relative symbols (full scope).
    DefRangeFramePointerRelFullScope(DefRangeFramePointerRelFullScopeSymbol),
    /// DefRange for register relative symbols.
    DefRangeRegisterRel(DefRangeRegisterRelSymbol),
    /// List of callees.
    Callees(CalleesSymbol),
    /// List of inlinees.
    Inlinees(InlineesSymbol),
    /// COFF section in a PE executable.
    Section(SectionSymbol<'t>),
    /// COFF group.
    CoffGroup(CoffGroupSymbol<'t>),
    /// Environment block.
    EnvBlock(EnvBlockSymbol<'t>),
}

impl<'t> SymbolData<'t> {
    /// Returns the name of this symbol if it has one.
    pub fn name(&self) -> Option<RawString<'t>> {
        match self {
            Self::ScopeEnd => None,
            Self::ObjName(data) => Some(data.name),
            Self::RegisterVariable(_) => None,
            Self::Constant(data) => Some(data.name),
            Self::UserDefinedType(data) => Some(data.name),
            Self::MultiRegisterVariable(_) => None,
            Self::Data(data) => Some(data.name),
            Self::Public(data) => Some(data.name),
            Self::Procedure(data) => Some(data.name),
            Self::ThreadStorage(data) => Some(data.name),
            Self::CompileFlags(_) => None,
            Self::UsingNamespace(data) => Some(data.name),
            Self::ProcedureReference(data) => data.name,
            Self::DataReference(data) => data.name,
            Self::AnnotationReference(data) => Some(data.name),
            Self::Trampoline(_) => None,
            Self::Export(data) => Some(data.name),
            Self::Local(data) => Some(data.name),
            Self::InlineSite(_) => None,
            Self::BuildInfo(_) => None,
            Self::InlineSiteEnd => None,
            Self::ProcedureEnd => None,
            Self::Label(data) => Some(data.name),
            Self::Block(data) => Some(data.name),
            Self::RegisterRelative(data) => Some(data.name),
            Self::Thunk(data) => Some(data.name),
            Self::SeparatedCode(_) => None,
            Self::FrameProc(_) => None,
            Self::CallSiteInfo(_) => None,
            Self::DefRangeRegister(_) => None,
            Self::DefRangeSubfieldRegister(_) => None,
            Self::DefRangeFramePointerRel(_) => None,
            Self::DefRangeFramePointerRelFullScope(_) => None,
            Self::DefRangeRegisterRel(_) => None,
            Self::Callees(_) => None,
            Self::Inlinees(_) => None,
            Self::Section(data) => Some(data.name),
            Self::CoffGroup(data) => Some(data.name),
            Self::EnvBlock(_) => None,
        }
    }
}

impl<'t> TryFromCtx<'t> for SymbolData<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _ctx: ()) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);
        let kind = buf.parse()?;

        let symbol = match kind {
            S_END => SymbolData::ScopeEnd,
            S_OBJNAME | S_OBJNAME_ST => SymbolData::ObjName(buf.parse_with(kind)?),
            S_REGISTER | S_REGISTER_ST => SymbolData::RegisterVariable(buf.parse_with(kind)?),
            S_CONSTANT | S_CONSTANT_ST | S_MANCONSTANT => {
                SymbolData::Constant(buf.parse_with(kind)?)
            }
            S_UDT | S_UDT_ST | S_COBOLUDT | S_COBOLUDT_ST => {
                SymbolData::UserDefinedType(buf.parse_with(kind)?)
            }
            S_MANYREG | S_MANYREG_ST | S_MANYREG2 | S_MANYREG2_ST => {
                SymbolData::MultiRegisterVariable(buf.parse_with(kind)?)
            }
            S_LDATA32 | S_LDATA32_ST | S_GDATA32 | S_GDATA32_ST | S_LMANDATA | S_LMANDATA_ST
            | S_GMANDATA | S_GMANDATA_ST => SymbolData::Data(buf.parse_with(kind)?),
            S_PUB32 | S_PUB32_ST => SymbolData::Public(buf.parse_with(kind)?),
            S_LPROC32 | S_LPROC32_ST | S_GPROC32 | S_GPROC32_ST | S_LPROC32_ID | S_GPROC32_ID
            | S_LPROC32_DPC | S_LPROC32_DPC_ID => SymbolData::Procedure(buf.parse_with(kind)?),
            S_LTHREAD32 | S_LTHREAD32_ST | S_GTHREAD32 | S_GTHREAD32_ST => {
                SymbolData::ThreadStorage(buf.parse_with(kind)?)
            }
            S_COMPILE2 | S_COMPILE2_ST | S_COMPILE3 => {
                SymbolData::CompileFlags(buf.parse_with(kind)?)
            }
            S_UNAMESPACE | S_UNAMESPACE_ST => SymbolData::UsingNamespace(buf.parse_with(kind)?),
            S_PROCREF | S_PROCREF_ST | S_LPROCREF | S_LPROCREF_ST => {
                SymbolData::ProcedureReference(buf.parse_with(kind)?)
            }
            S_TRAMPOLINE => Self::Trampoline(buf.parse_with(kind)?),
            S_DATAREF | S_DATAREF_ST => SymbolData::DataReference(buf.parse_with(kind)?),
            S_ANNOTATIONREF => SymbolData::AnnotationReference(buf.parse_with(kind)?),
            S_EXPORT => SymbolData::Export(buf.parse_with(kind)?),
            S_LOCAL => SymbolData::Local(buf.parse_with(kind)?),
            S_BUILDINFO => SymbolData::BuildInfo(buf.parse_with(kind)?),
            S_INLINESITE | S_INLINESITE2 => SymbolData::InlineSite(buf.parse_with(kind)?),
            S_INLINESITE_END => SymbolData::InlineSiteEnd,
            S_PROC_ID_END => SymbolData::ProcedureEnd,
            S_LABEL32 | S_LABEL32_ST => SymbolData::Label(buf.parse_with(kind)?),
            S_BLOCK32 | S_BLOCK32_ST => SymbolData::Block(buf.parse_with(kind)?),
            S_REGREL32 => SymbolData::RegisterRelative(buf.parse_with(kind)?),
            S_THUNK32 | S_THUNK32_ST => SymbolData::Thunk(buf.parse_with(kind)?),
            S_SEPCODE => SymbolData::SeparatedCode(buf.parse_with(kind)?),
            S_FRAMEPROC => SymbolData::FrameProc(buf.parse_with(kind)?),
            S_CALLSITEINFO => SymbolData::CallSiteInfo(buf.parse_with(kind)?),
            S_DEFRANGE_REGISTER => SymbolData::DefRangeRegister(buf.parse_with(kind)?),
            S_DEFRANGE_SUBFIELD_REGISTER => {
                SymbolData::DefRangeSubfieldRegister(buf.parse_with(kind)?)
            }
            S_DEFRANGE_FRAMEPOINTER_REL => {
                SymbolData::DefRangeFramePointerRel(buf.parse_with(kind)?)
            }
            S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE => {
                SymbolData::DefRangeFramePointerRelFullScope(buf.parse_with(kind)?)
            }
            S_DEFRANGE_REGISTER_REL => SymbolData::DefRangeRegisterRel(buf.parse_with(kind)?),
            S_CALLEES => SymbolData::Callees(buf.parse_with(kind)?),
            S_INLINEES => SymbolData::Inlinees(buf.parse_with(kind)?),
            S_SECTION => SymbolData::Section(buf.parse_with(kind)?),
            S_COFFGROUP => SymbolData::CoffGroup(buf.parse_with(kind)?),
            S_ENVBLOCK => SymbolData::EnvBlock(buf.parse_with(kind)?),
            other => return Err(Error::UnimplementedSymbolKind(other)),
        };

        Ok((symbol, buf.pos()))
    }
}

/// A Register variable.
///
/// Symbol kind `S_REGISTER`, or `S_REGISTER_ST`
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterVariableSymbol<'t> {
    /// Identifier of the variable type.
    pub type_index: TypeIndex,
    /// The register this variable is stored in.
    pub register: Register,
    /// Name of the variable.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for RegisterVariableSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = RegisterVariableSymbol {
            type_index: buf.parse()?,
            register: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// A Register variable spanning multiple registers.
///
/// Symbol kind `S_MANYREG`, `S_MANYREG_ST`, `S_MANYREG2`, or `S_MANYREG2_ST`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiRegisterVariableSymbol<'t> {
    /// Identifier of the variable type.
    pub type_index: TypeIndex,
    /// Most significant register first.
    pub registers: Vec<(Register, RawString<'t>)>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for MultiRegisterVariableSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let type_index = buf.parse()?;
        let count = match kind {
            S_MANYREG2 | S_MANYREG2_ST => buf.parse::<u16>()?,
            _ => u16::from(buf.parse::<u8>()?),
        };

        let mut registers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            registers.push((buf.parse()?, parse_symbol_name(&mut buf, kind)?));
        }

        let symbol = MultiRegisterVariableSymbol {
            type_index,
            registers,
        };

        Ok((symbol, buf.pos()))
    }
}

// CV_PUBSYMFLAGS_e
const CVPSF_CODE: u32 = 0x1;
const CVPSF_FUNCTION: u32 = 0x2;
const CVPSF_MANAGED: u32 = 0x4;
const CVPSF_MSIL: u32 = 0x8;

/// A public symbol with a mangled name.
///
/// Symbol kind `S_PUB32`, or `S_PUB32_ST`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicSymbol<'t> {
    /// The public symbol refers to executable code.
    pub code: bool,
    /// The public symbol is a function.
    pub function: bool,
    /// The symbol is in managed code (native or IL).
    pub managed: bool,
    /// The symbol is managed IL code.
    pub msil: bool,
    /// Start offset of the symbol.
    pub offset: PdbInternalSectionOffset,
    /// Mangled name of the symbol.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for PublicSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let flags = buf.parse::<u32>()?;
        let symbol = PublicSymbol {
            code: flags & CVPSF_CODE != 0,
            function: flags & CVPSF_FUNCTION != 0,
            managed: flags & CVPSF_MANAGED != 0,
            msil: flags & CVPSF_MSIL != 0,
            offset: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// Static data, such as a global variable.
///
/// Symbol kinds:
///  - `S_LDATA32` and `S_LDATA32_ST` for local unmanaged data
///  - `S_GDATA32` and `S_GDATA32_ST` for global unmanaged data
///  - `S_LMANDATA32` and `S_LMANDATA32_ST` for local managed data
///  - `S_GMANDATA32` and `S_GMANDATA32_ST` for global managed data
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataSymbol<'t> {
    /// Whether this data is global or local.
    pub global: bool,
    /// Whether this data is managed or unmanaged.
    pub managed: bool,
    /// Type identifier of the type of data.
    pub type_index: TypeIndex,
    /// Code offset of the start of the data region.
    pub offset: PdbInternalSectionOffset,
    /// Name of the data variable.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for DataSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = DataSymbol {
            global: matches!(kind, S_GDATA32 | S_GDATA32_ST | S_GMANDATA | S_GMANDATA_ST),
            managed: matches!(
                kind,
                S_LMANDATA | S_LMANDATA_ST | S_GMANDATA | S_GMANDATA_ST
            ),
            type_index: buf.parse()?,
            offset: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// Reference to an imported procedure.
///
/// Symbol kind `S_PROCREF`, `S_PROCREF_ST`, `S_LPROCREF`, or `S_LPROCREF_ST`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcedureReferenceSymbol<'t> {
    /// Whether the referenced procedure is global or local.
    pub global: bool,
    /// SUC of the name.
    pub sum_name: u32,
    /// Symbol index of the referenced [`ProcedureSymbol`].
    ///
    /// Note that this symbol might be located in a different module.
    pub symbol_index: SymbolIndex,
    /// Index of the module in [`DebugInformation::modules`](crate::DebugInformation::modules)
    /// containing the actual symbol.
    pub module: Option<usize>,
    /// Name of the procedure reference.
    pub name: Option<RawString<'t>>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for ProcedureReferenceSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = ProcedureReferenceSymbol {
            global: matches!(kind, S_PROCREF | S_PROCREF_ST),
            sum_name: buf.parse()?,
            symbol_index: buf.parse()?,
            module: buf.parse::<u16>()?.checked_sub(1).map(usize::from),
            name: parse_optional_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// Reference to an imported variable.
///
/// Symbol kind `S_DATAREF`, or `S_DATAREF_ST`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataReferenceSymbol<'t> {
    /// SUC of the name.
    pub sum_name: u32,
    /// Symbol index of the referenced [`DataSymbol`].
    ///
    /// Note that this symbol might be located in a different module.
    pub symbol_index: SymbolIndex,
    /// Index of the module in [`DebugInformation::modules`](crate::DebugInformation::modules)
    /// containing the actual symbol.
    pub module: Option<usize>,
    /// Name of the data reference.
    pub name: Option<RawString<'t>>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for DataReferenceSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = DataReferenceSymbol {
            sum_name: buf.parse()?,
            symbol_index: buf.parse()?,
            module: buf.parse::<u16>()?.checked_sub(1).map(usize::from),
            name: parse_optional_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// Reference to an annotation.
///
/// Symbol kind `S_ANNOTATIONREF`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnotationReferenceSymbol<'t> {
    /// SUC of the name.
    pub sum_name: u32,
    /// Symbol index of the referenced symbol.
    ///
    /// Note that this symbol might be located in a different module.
    pub symbol_index: SymbolIndex,
    /// Index of the module in [`DebugInformation::modules`](crate::DebugInformation::modules)
    /// containing the actual symbol.
    pub module: Option<usize>,
    /// Name of the annotation reference.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for AnnotationReferenceSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = AnnotationReferenceSymbol {
            sum_name: buf.parse()?,
            symbol_index: buf.parse()?,
            module: buf.parse::<u16>()?.checked_sub(1).map(usize::from),
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// Subtype of [`TrampolineSymbol`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrampolineType {
    /// An incremental thunk.
    Incremental,
    /// Branch island thunk.
    BranchIsland,
    /// An unknown thunk type.
    Unknown,
}

/// Trampoline thunk.
///
/// Symbol kind `S_TRAMPOLINE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrampolineSymbol {
    /// Trampoline symbol subtype.
    pub tramp_type: TrampolineType,
    /// Code size of the thunk.
    pub size: u16,
    /// Code offset of the thunk.
    pub thunk: PdbInternalSectionOffset,
    /// Code offset of the thunk target.
    pub target: PdbInternalSectionOffset,
}

impl TryFromCtx<'_, SymbolKind> for TrampolineSymbol {
    type Error = Error;

    fn try_from_ctx(this: &'_ [u8], _kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let tramp_type = match buf.parse::<u16>()? {
            0x00 => TrampolineType::Incremental,
            0x01 => TrampolineType::BranchIsland,
            _ => TrampolineType::Unknown,
        };

        let size = buf.parse()?;
        let thunk_offset = buf.parse()?;
        let target_offset = buf.parse()?;
        let thunk_section = buf.parse()?;
        let target_section = buf.parse()?;

        let symbol = Self {
            tramp_type,
            size,
            thunk: PdbInternalSectionOffset::new(thunk_section, thunk_offset),
            target: PdbInternalSectionOffset::new(target_section, target_offset),
        };

        Ok((symbol, buf.pos()))
    }
}

/// A constant value.
///
/// Symbol kind `S_CONSTANT`, or `S_CONSTANT_ST`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstantSymbol<'t> {
    /// Whether this constant has metadata type information.
    pub managed: bool,
    /// The type of this constant or metadata token.
    pub type_index: TypeIndex,
    /// The value of this constant.
    pub value: Variant,
    /// Name of the constant.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for ConstantSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = ConstantSymbol {
            managed: kind == S_MANCONSTANT,
            type_index: buf.parse()?,
            value: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// A user defined type.
///
/// Symbol kind `S_UDT`, or `S_UDT_ST`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserDefinedTypeSymbol<'t> {
    /// Identifier of the type.
    pub type_index: TypeIndex,
    /// Name of the type.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for UserDefinedTypeSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = UserDefinedTypeSymbol {
            type_index: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// A thread local variable.
///
/// Symbol kinds:
///  - `S_LTHREAD32`, `S_LTHREAD32_ST` for local thread storage.
///  - `S_GTHREAD32`, or `S_GTHREAD32_ST` for global thread storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadStorageSymbol<'t> {
    /// Whether this is a global or local thread storage.
    pub global: bool,
    /// Identifier of the stored type.
    pub type_index: TypeIndex,
    /// Code offset of the thread local.
    pub offset: PdbInternalSectionOffset,
    /// Name of the thread local.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for ThreadStorageSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = ThreadStorageSymbol {
            global: matches!(kind, S_GTHREAD32 | S_GTHREAD32_ST),
            type_index: buf.parse()?,
            offset: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

// CV_PROCFLAGS:
const CV_PFLAG_NOFPO: u8 = 0x01;
const CV_PFLAG_INT: u8 = 0x02;
const CV_PFLAG_FAR: u8 = 0x04;
const CV_PFLAG_NEVER: u8 = 0x08;
const CV_PFLAG_NOTREACHED: u8 = 0x10;
const CV_PFLAG_CUST_CALL: u8 = 0x20;
const CV_PFLAG_NOINLINE: u8 = 0x40;
const CV_PFLAG_OPTDBGINFO: u8 = 0x80;

/// Flags of a [`ProcedureSymbol`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcedureFlags {
    /// Frame pointer is present (not omitted).
    pub nofpo: bool,
    /// Interrupt return.
    pub int: bool,
    /// Far return.
    pub far: bool,
    /// Procedure does not return.
    pub never: bool,
    /// Procedure is never called.
    pub notreached: bool,
    /// Custom calling convention.
    pub cust_call: bool,
    /// Marked as `noinline`.
    pub noinline: bool,
    /// Debug information for optimized code is present.
    pub optdbginfo: bool,
}

impl<'t> TryFromCtx<'t, Endian> for ProcedureFlags {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let (value, size) = u8::try_from_ctx(this, le)?;

        let flags = Self {
            nofpo: value & CV_PFLAG_NOFPO != 0,
            int: value & CV_PFLAG_INT != 0,
            far: value & CV_PFLAG_FAR != 0,
            never: value & CV_PFLAG_NEVER != 0,
            notreached: value & CV_PFLAG_NOTREACHED != 0,
            cust_call: value & CV_PFLAG_CUST_CALL != 0,
            noinline: value & CV_PFLAG_NOINLINE != 0,
            optdbginfo: value & CV_PFLAG_OPTDBGINFO != 0,
        };

        Ok((flags, size))
    }
}

/// A procedure, such as a function or method.
///
/// Symbol kinds:
///  - `S_GPROC32`, `S_GPROC32_ST` for global procedures
///  - `S_LPROC32`, `S_LPROC32_ST` for local procedures
///  - `S_LPROC32_DPC` for DPC procedures
///  - `S_GPROC32_ID`, `S_LPROC32_ID`, `S_LPROC32_DPC_ID` for procedures referencing types from the
///    ID stream rather than the Type stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcedureSymbol<'t> {
    /// Whether this is a global or local procedure.
    pub global: bool,
    /// Indicates Deferred Procedure Calls (DPC).
    pub dpc: bool,
    /// The parent scope that this procedure is nested in.
    pub parent: Option<SymbolIndex>,
    /// The end symbol of this procedure.
    pub end: SymbolIndex,
    /// The next procedure symbol.
    pub next: Option<SymbolIndex>,
    /// The length of the code block covered by this procedure.
    pub len: u32,
    /// Start offset of the procedure's body code, which marks the end of the prologue.
    pub dbg_start_offset: u32,
    /// End offset of the procedure's body code, which marks the start of the epilogue.
    pub dbg_end_offset: u32,
    /// Identifier of the procedure type.
    ///
    /// The type contains the complete signature, including parameters, modifiers and the return
    /// type.
    pub type_index: TypeIndex,
    /// Code offset of the start of this procedure.
    pub offset: PdbInternalSectionOffset,
    /// Detailed flags of this procedure.
    pub flags: ProcedureFlags,
    /// The full, demangled name of the procedure.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for ProcedureSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = ProcedureSymbol {
            global: matches!(kind, S_GPROC32 | S_GPROC32_ST | S_GPROC32_ID),
            dpc: matches!(kind, S_LPROC32_DPC | S_LPROC32_DPC_ID),
            parent: parse_optional_index(&mut buf)?,
            end: buf.parse()?,
            next: parse_optional_index(&mut buf)?,
            len: buf.parse()?,
            dbg_start_offset: buf.parse()?,
            dbg_end_offset: buf.parse()?,
            type_index: buf.parse()?,
            offset: buf.parse()?,
            flags: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// The callsite of an inlined function.
///
/// Symbol kind `S_INLINESITE`, or `S_INLINESITE2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InlineSiteSymbol<'t> {
    /// Index of the parent function.
    ///
    /// This might either be a [`ProcedureSymbol`] or another `InlineSiteSymbol`.
    pub parent: Option<SymbolIndex>,
    /// The end symbol of this callsite.
    pub end: SymbolIndex,
    /// Identifier of the type describing the inline function.
    pub inlinee: IdIndex,
    /// The total number of invocations of the inline function.
    pub invocations: Option<u32>,
    /// Binary annotations containing the line program of this call site.
    pub annotations: BinaryAnnotations<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for InlineSiteSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = InlineSiteSymbol {
            parent: parse_optional_index(&mut buf)?,
            end: buf.parse()?,
            inlinee: buf.parse()?,
            invocations: match kind {
                S_INLINESITE2 => Some(buf.parse()?),
                _ => None,
            },
            annotations: BinaryAnnotations::new(buf.take(buf.len())?),
        };

        Ok((symbol, buf.pos()))
    }
}

/// Reference to build information.
///
/// Symbol kind `S_BUILDINFO`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildInfoSymbol {
    /// Index of the build information record.
    pub id: IdIndex,
}

impl<'t> TryFromCtx<'t, SymbolKind> for BuildInfoSymbol {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = Self { id: buf.parse()? };

        Ok((symbol, buf.pos()))
    }
}

/// Name of the object file of this module.
///
/// Symbol kind `S_OBJNAME`, or `S_OBJNAME_ST`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjNameSymbol<'t> {
    /// Signature.
    pub signature: u32,
    /// Path to the object file.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for ObjNameSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = ObjNameSymbol {
            signature: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// A version number refered to by `CompileFlagsSymbol`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompilerVersion {
    /// The major version number.
    pub major: u16,
    /// The minor version number.
    pub minor: u16,
    /// The build (patch) version number.
    pub build: u16,
    /// The QFE (quick fix engineering) number.
    pub qfe: Option<u16>,
}

impl<'t> TryFromCtx<'t, bool> for CompilerVersion {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], has_qfe: bool) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let version = Self {
            major: buf.parse()?,
            minor: buf.parse()?,
            build: buf.parse()?,
            qfe: if has_qfe { Some(buf.parse()?) } else { None },
        };

        Ok((version, buf.pos()))
    }
}

/// Compile flags declared in `CompileFlagsSymbol`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileFlags {
    /// Compiled for edit and continue.
    pub edit_and_continue: bool,
    /// Compiled without debugging info.
    pub no_debug_info: bool,
    /// Compiled with `LTCG`.
    pub link_time_codegen: bool,
    /// Compiled with `/bzalign`.
    pub no_data_align: bool,
    /// Managed code or data is present.
    pub managed: bool,
    /// Compiled with `/GS`.
    pub security_checks: bool,
    /// Compiled with `/hotpatch`.
    pub hot_patch: bool,
    /// Compiled with `CvtCIL`.
    pub cvtcil: bool,
    /// This is a MSIL .NET Module.
    pub msil_module: bool,
    /// Compiled with `/sdl`.
    pub sdl: bool,
    /// Compiled with `/ltcg:pgo` or `pgo:`.
    pub pgo: bool,
    /// This is a .exp module.
    pub exp_module: bool,
}

impl<'t> TryFromCtx<'t, SymbolKind> for CompileFlags {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let is_compile3 = kind == S_COMPILE3;

        let raw = this.pread_with::<u16>(0, LE)?;
        this.pread::<u8>(2)?; // unused

        let flags = Self {
            edit_and_continue: raw & 1 != 0,
            no_debug_info: (raw >> 1) & 1 != 0,
            link_time_codegen: (raw >> 2) & 1 != 0,
            no_data_align: (raw >> 3) & 1 != 0,
            managed: (raw >> 4) & 1 != 0,
            security_checks: (raw >> 5) & 1 != 0,
            hot_patch: (raw >> 6) & 1 != 0,
            cvtcil: (raw >> 7) & 1 != 0,
            msil_module: (raw >> 8) & 1 != 0,
            sdl: (raw >> 9) & 1 != 0 && is_compile3,
            pgo: (raw >> 10) & 1 != 0 && is_compile3,
            exp_module: (raw >> 11) & 1 != 0 && is_compile3,
        };

        Ok((flags, 3))
    }
}

/// Flags used to compile a module.
///
/// Symbol kind `S_COMPILE2`, `S_COMPILE2_ST`, or `S_COMPILE3`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileFlagsSymbol<'t> {
    /// The source code language.
    pub language: SourceLanguage,
    /// Compiler flags.
    pub flags: CompileFlags,
    /// Machine type of the compilation target.
    pub cpu_type: CPUType,
    /// Version of the compiler frontend.
    pub frontend_version: CompilerVersion,
    /// Version of the compiler backend.
    pub backend_version: CompilerVersion,
    /// Display name of the compiler.
    pub version_string: RawString<'t>,
    // TODO: Command block for S_COMPILE2?
}

impl<'t> TryFromCtx<'t, SymbolKind> for CompileFlagsSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let has_qfe = kind == S_COMPILE3;
        let symbol = CompileFlagsSymbol {
            language: buf.parse()?,
            flags: buf.parse_with(kind)?,
            cpu_type: buf.parse()?,
            frontend_version: buf.parse_with(has_qfe)?,
            backend_version: buf.parse_with(has_qfe)?,
            version_string: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// A using namespace directive.
///
/// Symbol kind `S_UNAMESPACE`, or `S_UNAMESPACE_ST`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsingNamespaceSymbol<'t> {
    /// The name of the imported namespace.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for UsingNamespaceSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = UsingNamespaceSymbol {
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

// CV_LVARFLAGS:
const CV_LVARFLAG_ISPARAM: u16 = 0x01;
const CV_LVARFLAG_ADDRTAKEN: u16 = 0x02;
const CV_LVARFLAG_COMPGENX: u16 = 0x04;
const CV_LVARFLAG_ISAGGREGATE: u16 = 0x08;
const CV_LVARFLAG_ISALIASED: u16 = 0x10;
const CV_LVARFLAG_ISALIAS: u16 = 0x20;
const CV_LVARFLAG_ISRETVALUE: u16 = 0x40;
const CV_LVARFLAG_ISOPTIMIZEDOUT: u16 = 0x80;
const CV_LVARFLAG_ISENREG_GLOB: u16 = 0x100;
const CV_LVARFLAG_ISENREG_STAT: u16 = 0x200;

/// Flags for a [`LocalSymbol`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalVariableFlags {
    /// Variable is a parameter.
    pub isparam: bool,
    /// Address is taken.
    pub addrtaken: bool,
    /// Variable is compiler generated.
    pub compgenx: bool,
    /// The symbol is splitted in temporaries, which are treated by compiler as independent
    /// entities.
    pub isaggregate: bool,
    /// Variable has multiple simultaneous lifetimes.
    pub isaliased: bool,
    /// Represents one of the multiple simultaneous lifetimes.
    pub isalias: bool,
    /// Represents a function return value.
    pub isretvalue: bool,
    /// Variable has no lifetimes.
    pub isoptimizedout: bool,
    /// Variable is an enregistered global.
    pub isenreg_glob: bool,
    /// Variable is an enregistered static.
    pub isenreg_stat: bool,
}

impl<'t> TryFromCtx<'t, Endian> for LocalVariableFlags {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let (value, size) = u16::try_from_ctx(this, le)?;

        let flags = Self {
            isparam: value & CV_LVARFLAG_ISPARAM != 0,
            addrtaken: value & CV_LVARFLAG_ADDRTAKEN != 0,
            compgenx: value & CV_LVARFLAG_COMPGENX != 0,
            isaggregate: value & CV_LVARFLAG_ISAGGREGATE != 0,
            isaliased: value & CV_LVARFLAG_ISALIASED != 0,
            isalias: value & CV_LVARFLAG_ISALIAS != 0,
            isretvalue: value & CV_LVARFLAG_ISRETVALUE != 0,
            isoptimizedout: value & CV_LVARFLAG_ISOPTIMIZEDOUT != 0,
            isenreg_glob: value & CV_LVARFLAG_ISENREG_GLOB != 0,
            isenreg_stat: value & CV_LVARFLAG_ISENREG_STAT != 0,
        };

        Ok((flags, size))
    }
}

/// A local symbol in optimized code.
///
/// Symbol kind `S_LOCAL`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalSymbol<'t> {
    /// The type of the symbol.
    pub type_index: TypeIndex,
    /// Flags for this symbol.
    pub flags: LocalVariableFlags,
    /// Name of the symbol.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for LocalSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = LocalSymbol {
            type_index: buf.parse()?,
            flags: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

// https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/include/cvinfo.h#L4456
/// Flags of an [`ExportSymbol`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportSymbolFlags {
    /// An exported constant.
    pub constant: bool,
    /// Exported data (e.g. a static variable).
    pub data: bool,
    /// A private symbol.
    pub private: bool,
    /// A symbol with no name.
    pub no_name: bool,
    /// Ordinal was explicitly assigned.
    pub ordinal: bool,
    /// This is a forwarder.
    pub forwarder: bool,
}

impl<'t> TryFromCtx<'t, Endian> for ExportSymbolFlags {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let (value, size) = u16::try_from_ctx(this, le)?;

        let flags = Self {
            constant: value & 0x01 != 0,
            data: value & 0x02 != 0,
            private: value & 0x04 != 0,
            no_name: value & 0x08 != 0,
            ordinal: value & 0x10 != 0,
            forwarder: value & 0x20 != 0,
        };

        Ok((flags, size))
    }
}

/// An exported symbol.
///
/// Symbol kind `S_EXPORT`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportSymbol<'t> {
    /// Ordinal of the symbol.
    pub ordinal: u16,
    /// Flags declaring the type of the exported symbol.
    pub flags: ExportSymbolFlags,
    /// The name of the exported symbol.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for ExportSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = ExportSymbol {
            ordinal: buf.parse()?,
            flags: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// A label symbol.
///
/// Symbol kind `S_LABEL32`, `S_LABEL16`, or `S_LABEL32_ST`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LabelSymbol<'t> {
    /// Code offset of the start of this label.
    pub offset: PdbInternalSectionOffset,
    /// Detailed flags of this label.
    pub flags: ProcedureFlags,
    /// Name of the symbol.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for LabelSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = LabelSymbol {
            offset: buf.parse()?,
            flags: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// A block symbol.
///
/// Symbol kind `S_BLOCK32`, or `S_BLOCK32_ST`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockSymbol<'t> {
    /// The parent scope that this block is nested in.
    pub parent: SymbolIndex,
    /// The end symbol of this block.
    pub end: SymbolIndex,
    /// The length of the block.
    pub len: u32,
    /// Code offset of the start of this label.
    pub offset: PdbInternalSectionOffset,
    /// The block name.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for BlockSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = BlockSymbol {
            parent: buf.parse()?,
            end: buf.parse()?,
            len: buf.parse()?,
            offset: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// A register relative symbol.
///
/// The address of the variable is the value in the register + offset (e.g. %EBP + 8).
///
/// Symbol kind `S_REGREL32`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterRelativeSymbol<'t> {
    /// The variable offset.
    pub offset: i32,
    /// The type of the variable.
    pub type_index: TypeIndex,
    /// The register this variable address is relative to.
    pub register: Register,
    /// The variable name.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for RegisterRelativeSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = RegisterRelativeSymbol {
            offset: buf.parse()?,
            type_index: buf.parse()?,
            register: buf.parse()?,
            name: parse_symbol_name(&mut buf, kind)?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// Thunk adjustor
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThunkAdjustor<'t> {
    delta: u16,
    target: RawString<'t>,
}

/// A thunk kind
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThunkKind<'t> {
    /// Standard thunk
    NoType,
    /// "this" adjustor thunk with delta and target
    Adjustor(ThunkAdjustor<'t>),
    /// Virtual call thunk with table entry
    VCall(u16),
    /// pcode thunk
    PCode,
    /// thunk which loads the address to jump to via unknown means...
    Load,
    /// Unknown with ordinal value
    Unknown(u8),
}

/// A thunk symbol.
///
/// Symbol kind `S_THUNK32`, or `S_THUNK32_ST`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThunkSymbol<'t> {
    /// The parent scope that this thunk is nested in.
    pub parent: Option<SymbolIndex>,
    /// The end symbol of this thunk.
    pub end: SymbolIndex,
    /// The next symbol.
    pub next: Option<SymbolIndex>,
    /// Code offset of the start of this label.
    pub offset: PdbInternalSectionOffset,
    /// The length of the thunk.
    pub len: u16,
    /// The kind of the thunk.
    pub kind: ThunkKind<'t>,
    /// The thunk name.
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for ThunkSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let parent = parse_optional_index(&mut buf)?;
        let end = buf.parse()?;
        let next = parse_optional_index(&mut buf)?;
        let offset = buf.parse()?;
        let len = buf.parse()?;
        let ord = buf.parse::<u8>()?;
        let name = parse_symbol_name(&mut buf, kind)?;

        let kind = match ord {
            0 => ThunkKind::NoType,
            1 => ThunkKind::Adjustor(ThunkAdjustor {
                delta: buf.parse::<u16>()?,
                target: buf.parse_cstring()?,
            }),
            2 => ThunkKind::VCall(buf.parse::<u16>()?),
            3 => ThunkKind::PCode,
            4 => ThunkKind::Load,
            ord => ThunkKind::Unknown(ord),
        };

        let symbol = ThunkSymbol {
            parent,
            end,
            next,
            offset,
            len,
            kind,
            name,
        };

        Ok((symbol, buf.pos()))
    }
}

// CV_SEPCODEFLAGS:
const CV_SEPCODEFLAG_IS_LEXICAL_SCOPE: u32 = 0x01;
const CV_SEPCODEFLAG_RETURNS_TO_PARENT: u32 = 0x02;

/// Flags for a [`SeparatedCodeSymbol`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeparatedCodeFlags {
    /// S_SEPCODE doubles as lexical scope.
    pub islexicalscope: bool,
    /// code frag returns to parent.
    pub returnstoparent: bool,
}

impl<'t> TryFromCtx<'t, Endian> for SeparatedCodeFlags {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let (value, size) = u32::try_from_ctx(this, le)?;

        let flags = Self {
            islexicalscope: value & CV_SEPCODEFLAG_IS_LEXICAL_SCOPE != 0,
            returnstoparent: value & CV_SEPCODEFLAG_RETURNS_TO_PARENT != 0,
        };

        Ok((flags, size))
    }
}

/// A separated code symbol.
///
/// Symbol kind `S_SEPCODE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeparatedCodeSymbol {
    /// The parent scope that this block is nested in.
    pub parent: SymbolIndex,
    /// The end symbol of this block.
    pub end: SymbolIndex,
    /// The length of the block.
    pub len: u32,
    /// Flags for this symbol
    pub flags: SeparatedCodeFlags,
    /// Code offset of the start of the separated code.
    pub offset: PdbInternalSectionOffset,
    /// Parent offset.
    pub parent_offset: PdbInternalSectionOffset,
}

impl<'t> TryFromCtx<'t, SymbolKind> for SeparatedCodeSymbol {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let parent = buf.parse()?;
        let end = buf.parse()?;
        let len = buf.parse()?;
        let flags = buf.parse()?;
        let offset = buf.parse()?;
        let parent_offset = buf.parse()?;
        let section = buf.parse()?;
        let parent_section = buf.parse()?;

        let symbol = Self {
            parent,
            end,
            len,
            flags,
            offset: PdbInternalSectionOffset { offset, section },
            parent_offset: PdbInternalSectionOffset {
                offset: parent_offset,
                section: parent_section,
            },
        };

        Ok((symbol, buf.pos()))
    }
}

/// Frame procedure flags
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameProcedureFlags {
    /// Function has _alloca
    pub has_alloca: bool,
    /// Function has setjmp
    pub has_setjmp: bool,
    /// Function has longjmp
    pub has_longjmp: bool,
    /// Function has inline assembly
    pub has_inline_assembly: bool,
    /// Function has exception handling
    pub has_exception_handling: bool,
    /// Function is marked as inline
    pub marked_inline: bool,
    /// Function has structured exception handling
    pub has_structured_exception_handling: bool,
    /// Function is naked
    pub naked: bool,
    /// Security checks (/GS)
    pub security_checks: bool,
    /// Asynchronous exception handling (/EHa)
    pub async_exception_handling: bool,
    /// /GS buffer checks are not needed
    pub no_stack_ordering: bool,
    /// Function was inlined
    pub inlined: bool,
    /// Strict security checks
    pub strict_security_checks: bool,
    /// Function is marked as SafeBuffers
    pub safe_buffers: bool,
    /// Encoded local base pointer mask
    pub encoded_local_base_pointer_mask: u8,
    /// Encoded parameter base pointer mask
    pub encoded_param_base_pointer_mask: u8,
    /// Profile guided optimization
    pub profile_guided_optimization: bool,
    /// Valid profile counts
    pub valid_profile_counts: bool,
    /// Optimized for speed
    pub optimized_for_speed: bool,
    /// Function has CFG checks
    pub guard_cfg: bool,
    /// Function has CFW checks
    pub guard_cfw: bool,
}

impl<'t> TryFromCtx<'t, Endian> for FrameProcedureFlags {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let (value, size) = u32::try_from_ctx(this, le)?;

        let flags = Self {
            has_alloca: value & 0x1 != 0,
            has_setjmp: value & 0x2 != 0,
            has_longjmp: value & 0x4 != 0,
            has_inline_assembly: value & 0x8 != 0,
            has_exception_handling: value & 0x10 != 0,
            marked_inline: value & 0x20 != 0,
            has_structured_exception_handling: value & 0x40 != 0,
            naked: value & 0x80 != 0,
            security_checks: value & 0x100 != 0,
            async_exception_handling: value & 0x200 != 0,
            no_stack_ordering: value & 0x400 != 0,
            inlined: value & 0x800 != 0,
            strict_security_checks: value & 0x1000 != 0,
            safe_buffers: value & 0x2000 != 0,
            encoded_local_base_pointer_mask: ((value & 0xc000) >> 14) as u8,
            encoded_param_base_pointer_mask: ((value & 0x30000) >> 16) as u8,
            profile_guided_optimization: value & 0x40000 != 0,
            valid_profile_counts: value & 0x80000 != 0,
            optimized_for_speed: value & 0x100000 != 0,
            guard_cfg: value & 0x200000 != 0,
            guard_cfw: value & 0x400000 != 0,
        };

        Ok((flags, size))
    }
}

/// Frame procedure information
///
/// Symbol kind `S_FRAMEPROC`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameProcSymbol {
    /// Total bytes of frame
    pub total_frame_bytes: u32,
    /// Bytes of padding in frame
    pub padding_frame_bytes: u32,
    /// Offset to padding
    pub offset_to_padding: u32,
    /// Bytes of callee save registers
    pub bytes_of_callee_saved_registers: u32,
    /// Offset of exception handler
    pub offset_of_exception_handler: u32,
    /// Section id of exception handler
    pub section_id_of_exception_handler: u16,
    /// Frame procedure flags
    pub flags: FrameProcedureFlags,
}

impl<'t> TryFromCtx<'t, SymbolKind> for FrameProcSymbol {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = FrameProcSymbol {
            total_frame_bytes: buf.parse()?,
            padding_frame_bytes: buf.parse()?,
            offset_to_padding: buf.parse()?,
            bytes_of_callee_saved_registers: buf.parse()?,
            offset_of_exception_handler: buf.parse()?,
            section_id_of_exception_handler: buf.parse()?,
            flags: buf.parse()?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// Call site information
///
/// Symbol kind `S_CALLSITEINFO`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallSiteInfoSymbol {
    /// Code offset of call site
    pub offset: PdbInternalSectionOffset,
    /// Type index describing function signature
    pub type_index: TypeIndex,
}

impl<'t> TryFromCtx<'t, SymbolKind> for CallSiteInfoSymbol {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let offset = buf.parse::<u32>()?;
        let section = buf.parse::<u16>()?;
        let _padding = buf.parse::<u16>()?; // padding
        let type_index = buf.parse()?;

        let symbol = CallSiteInfoSymbol {
            offset: PdbInternalSectionOffset { offset, section },
            type_index,
        };

        Ok((symbol, buf.pos()))
    }
}

/// Local variable address range
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalVariableAddrRange {
    /// Start offset
    pub offset_start: u32,
    /// Start section
    pub isect_start: u16,
    /// Range
    pub range: u16,
}

impl<'t> TryFromCtx<'t, Endian> for LocalVariableAddrRange {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let offset_start = this.pread_with(offset, le)?;
        offset += 4;
        let isect_start = this.pread_with(offset, le)?;
        offset += 2;
        let range = this.pread_with(offset, le)?;
        offset += 2;

        Ok((
            Self {
                offset_start,
                isect_start,
                range,
            },
            offset,
        ))
    }
}

/// Local variable address gap
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalVariableAddrGap {
    /// Gap start offset
    pub gap_start_offset: u16,
    /// Range
    pub range: u16,
}

impl<'t> TryFromCtx<'t, Endian> for LocalVariableAddrGap {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let gap_start_offset = this.pread_with(offset, le)?;
        offset += 2;
        let range = this.pread_with(offset, le)?;
        offset += 2;

        Ok((
            Self {
                gap_start_offset,
                range,
            },
            offset,
        ))
    }
}

/// DefRange for register symbols
///
/// Symbol kind `S_DEFRANGE_REGISTER`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefRangeRegisterSymbol {
    /// Register
    pub register: Register,
    /// May have no name
    pub may_have_no_name: u16,
    /// Address range
    pub range: LocalVariableAddrRange,
    /// Gaps
    pub gaps: Vec<LocalVariableAddrGap>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for DefRangeRegisterSymbol {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let register = buf.parse()?;
        let may_have_no_name = buf.parse()?;
        let range = buf.parse()?;

        let mut gaps = Vec::new();
        while buf.pos() < buf.len() {
            gaps.push(buf.parse()?);
        }

        let symbol = DefRangeRegisterSymbol {
            register,
            may_have_no_name,
            range,
            gaps,
        };

        Ok((symbol, buf.pos()))
    }
}

/// DefRange for subfield register symbols
///
/// Symbol kind `S_DEFRANGE_SUBFIELD_REGISTER`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefRangeSubfieldRegisterSymbol {
    /// Register
    pub register: Register,
    /// May have no name
    pub may_have_no_name: u16,
    /// Offset in parent
    pub offset_in_parent: u32,
    /// Address range
    pub range: LocalVariableAddrRange,
    /// Gaps
    pub gaps: Vec<LocalVariableAddrGap>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for DefRangeSubfieldRegisterSymbol {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let register = buf.parse()?;
        let may_have_no_name = buf.parse()?;
        let offset_in_parent = buf.parse()?;
        let range = buf.parse()?;

        let mut gaps = Vec::new();
        while buf.pos() < buf.len() {
            gaps.push(buf.parse()?);
        }

        let symbol = DefRangeSubfieldRegisterSymbol {
            register,
            may_have_no_name,
            offset_in_parent,
            range,
            gaps,
        };

        Ok((symbol, buf.pos()))
    }
}

/// DefRange for frame pointer relative symbols (full scope)
///
/// Symbol kind `S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DefRangeFramePointerRelFullScopeSymbol {
    /// Offset
    pub offset: i32,
}

impl<'t> TryFromCtx<'t, SymbolKind> for DefRangeFramePointerRelFullScopeSymbol {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let symbol = DefRangeFramePointerRelFullScopeSymbol {
            offset: buf.parse()?,
        };

        Ok((symbol, buf.pos()))
    }
}

/// DefRange for register relative symbols
///
/// Symbol kind `S_DEFRANGE_REGISTER_REL`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefRangeRegisterRelSymbol {
    /// Register
    pub register: Register,
    /// Flags
    pub flags: u16,
    /// Base pointer offset
    pub base_pointer_offset: i32,
    /// Address range
    pub range: LocalVariableAddrRange,
    /// Gaps
    pub gaps: Vec<LocalVariableAddrGap>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for DefRangeRegisterRelSymbol {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let register = buf.parse()?;
        let flags = buf.parse()?;
        let base_pointer_offset = buf.parse()?;
        let range = buf.parse()?;

        let mut gaps = Vec::new();
        while buf.pos() < buf.len() {
            gaps.push(buf.parse()?);
        }

        let symbol = DefRangeRegisterRelSymbol {
            register,
            flags,
            base_pointer_offset,
            range,
            gaps,
        };

        Ok((symbol, buf.pos()))
    }
}

/// List of callees
///
/// Symbol kind `S_CALLEES`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalleesSymbol {
    /// Type indices of callees
    pub type_indices: Vec<TypeIndex>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for CalleesSymbol {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let count: u32 = buf.parse()?;
        let mut type_indices = Vec::with_capacity(count as usize);

        for _ in 0..count {
            type_indices.push(buf.parse()?);
        }

        let symbol = CalleesSymbol { type_indices };

        Ok((symbol, buf.pos()))
    }
}

/// List of inlinees
///
/// Symbol kind `S_INLINEES`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InlineesSymbol {
    /// Type indices of inlinees
    pub type_indices: Vec<TypeIndex>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for InlineesSymbol {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let count: u32 = buf.parse()?;
        let mut type_indices = Vec::with_capacity(count as usize);

        for _ in 0..count {
            type_indices.push(buf.parse()?);
        }

        let symbol = InlineesSymbol { type_indices };

        Ok((symbol, buf.pos()))
    }
}

/// DefRange for frame pointer relative symbols
///
/// Symbol kind `S_DEFRANGE_FRAMEPOINTER_REL`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefRangeFramePointerRelSymbol {
    /// Offset
    pub offset: i32,
    /// Address range
    pub range: LocalVariableAddrRange,
    /// Gaps
    pub gaps: Vec<LocalVariableAddrGap>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for DefRangeFramePointerRelSymbol {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let offset = buf.parse()?;
        let range = buf.parse()?;

        let mut gaps = Vec::new();
        while buf.pos() < buf.len() {
            gaps.push(buf.parse()?);
        }

        let symbol = DefRangeFramePointerRelSymbol {
            offset,
            range,
            gaps,
        };

        Ok((symbol, buf.pos()))
    }
}

/// A COFF section symbol
///
/// Symbol kind `S_SECTION`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SectionSymbol<'t> {
    /// Section number
    pub section_number: u16,
    /// Alignment
    pub alignment: u8,
    /// RVA
    pub rva: u32,
    /// Length
    pub length: u32,
    /// Characteristics
    pub characteristics: u32,
    /// Name
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for SectionSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let section_number = buf.parse()?;
        let alignment = buf.parse()?;
        let _padding = buf.parse::<u8>()?; // padding
        let rva = buf.parse()?;
        let length = buf.parse()?;
        let characteristics = buf.parse()?;
        let name = parse_symbol_name(&mut buf, kind)?;

        let symbol = SectionSymbol {
            section_number,
            alignment,
            rva,
            length,
            characteristics,
            name,
        };

        Ok((symbol, buf.pos()))
    }
}

/// A COFF group symbol
///
/// Symbol kind `S_COFFGROUP`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoffGroupSymbol<'t> {
    /// Size
    pub size: u32,
    /// Characteristics
    pub characteristics: u32,
    /// Offset
    pub offset: PdbInternalSectionOffset,
    /// Name
    pub name: RawString<'t>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for CoffGroupSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], kind: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let size = buf.parse()?;
        let characteristics = buf.parse()?;
        let offset = buf.parse::<u32>()?;
        let section = buf.parse::<u16>()?;
        let name = parse_symbol_name(&mut buf, kind)?;

        let symbol = CoffGroupSymbol {
            size,
            characteristics,
            offset: PdbInternalSectionOffset { offset, section },
            name,
        };

        Ok((symbol, buf.pos()))
    }
}

/// Environment block symbol
///
/// Symbol kind `S_ENVBLOCK`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvBlockSymbol<'t> {
    /// Environment strings
    pub entries: Vec<RawString<'t>>,
}

impl<'t> TryFromCtx<'t, SymbolKind> for EnvBlockSymbol<'t> {
    type Error = Error;

    fn try_from_ctx(this: &'t [u8], _: SymbolKind) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);

        let _reserved = buf.parse::<u8>()?;

        let mut entries = Vec::new();
        loop {
            let string = buf.parse_cstring()?;
            if string.is_empty() {
                break;
            }
            entries.push(string);
        }

        let symbol = EnvBlockSymbol { entries };

        Ok((symbol, buf.pos()))
    }
}

/// PDB symbol tables contain names, locations, and metadata about functions, global/static data,
/// constants, data types, and more.
///
/// The `SymbolTable` holds a `SourceView` referencing the symbol table inside the PDB file. All the
/// data structures returned by a `SymbolTable` refer to that buffer.
///
/// # Example
///
/// ```
/// # use pdb::FallibleIterator;
/// #
/// # fn test() -> pdb::Result<usize> {
/// let file = std::fs::File::open("fixtures/self/foo.pdb")?;
/// let mut pdb = pdb::PDB::open(file)?;
///
/// let symbol_table = pdb.global_symbols()?;
/// let address_map = pdb.address_map()?;
///
/// # let mut count: usize = 0;
/// let mut symbols = symbol_table.iter();
/// while let Some(symbol) = symbols.next()? {
///     match symbol.parse() {
///         Ok(pdb::SymbolData::Public(data)) if data.function => {
///             // we found the location of a function!
///             let rva = data.offset.to_rva(&address_map).unwrap_or_default();
///             println!("{} is {}", rva, data.name);
///             # count += 1;
///         }
///         _ => {}
///     }
/// }
///
/// # Ok(count)
/// # }
/// # assert!(test().expect("test") > 2000);
/// ```
#[derive(Debug)]
pub struct SymbolTable<'s> {
    stream: Stream<'s>,
}

impl<'s> SymbolTable<'s> {
    /// Parses a symbol table from raw stream data.
    pub(crate) fn new(stream: Stream<'s>) -> Self {
        SymbolTable { stream }
    }

    /// Returns an iterator that can traverse the symbol table in sequential order.
    pub fn iter(&self) -> SymbolIter<'_> {
        SymbolIter::new(self.stream.parse_buffer())
    }

    /// Returns an iterator over symbols starting at the given index.
    pub fn iter_at(&self, index: SymbolIndex) -> SymbolIter<'_> {
        let mut iter = self.iter();
        iter.seek(index);
        iter
    }
}

/// A `SymbolIter` iterates over a `SymbolTable`, producing `Symbol`s.
///
/// Symbol tables are represented internally as a series of records, each of which have a length, a
/// type, and a type-specific field layout. Iteration performance is therefore similar to a linked
/// list.
#[derive(Debug)]
pub struct SymbolIter<'t> {
    buf: ParseBuffer<'t>,
}

impl<'t> SymbolIter<'t> {
    pub(crate) fn new(buf: ParseBuffer<'t>) -> SymbolIter<'t> {
        SymbolIter { buf }
    }

    /// Move the iterator to the symbol referred to by `index`.
    ///
    /// This can be used to jump to the sibiling or parent of a symbol record.
    pub fn seek(&mut self, index: SymbolIndex) {
        self.buf.seek(index.0 as usize);
    }

    /// Skip to the symbol referred to by `index`, returning the symbol.
    ///
    /// This can be used to jump to the sibiling or parent of a symbol record. Iteration continues
    /// after that symbol.
    ///
    /// Note that the symbol may be located **before** the originating symbol, for instance when
    /// jumping to the parent symbol. Take care not to enter an endless loop in this case.
    pub fn skip_to(&mut self, index: SymbolIndex) -> Result<Option<Symbol<'t>>> {
        self.seek(index);
        self.next()
    }
}

impl<'t> FallibleIterator for SymbolIter<'t> {
    type Item = Symbol<'t>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        while !self.buf.is_empty() {
            let index = SymbolIndex(self.buf.pos() as u32);

            // read the length of the next symbol
            let symbol_length = self.buf.parse::<u16>()? as usize;
            if symbol_length < 2 {
                // this can't be correct
                return Err(Error::SymbolTooShort);
            }

            // grab the symbol itself
            let data = self.buf.take(symbol_length)?;
            let symbol = Symbol { index, data };

            // skip over padding in the symbol table
            match symbol.raw_kind() {
                S_ALIGN | S_SKIP => continue,
                _ => return Ok(Some(symbol)),
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    mod parsing {
        use crate::symbol::*;

        #[test]
        fn kind_0006() {
            let data = &[6, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x0006);
            assert_eq!(symbol.parse().expect("parse"), SymbolData::ScopeEnd);
        }

        #[test]
        fn kind_1101() {
            let data = &[1, 17, 0, 0, 0, 0, 42, 32, 67, 73, 76, 32, 42, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1101);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::ObjName(ObjNameSymbol {
                    signature: 0,
                    name: "* CIL *".into(),
                })
            );
        }

        #[test]
        fn kind_1102() {
            let data = &[
                2, 17, 0, 0, 0, 0, 108, 22, 0, 0, 0, 0, 0, 0, 140, 11, 0, 0, 1, 0, 9, 0, 3, 91,
                116, 104, 117, 110, 107, 93, 58, 68, 101, 114, 105, 118, 101, 100, 58, 58, 70, 117,
                110, 99, 49, 96, 97, 100, 106, 117, 115, 116, 111, 114, 123, 56, 125, 39, 0, 0, 0,
                0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1102);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Thunk(ThunkSymbol {
                    parent: None,
                    end: SymbolIndex(0x166c),
                    next: None,
                    offset: PdbInternalSectionOffset {
                        section: 0x1,
                        offset: 0xb8c
                    },
                    len: 9,
                    kind: ThunkKind::PCode,
                    name: "[thunk]:Derived::Func1`adjustor{8}'".into()
                })
            );
        }

        #[test]
        fn kind_1012() {
            let data = &[
                18, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 66,
                17, 0, 0, 0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1012);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::FrameProc(FrameProcSymbol {
                    total_frame_bytes: 0,
                    padding_frame_bytes: 0,
                    offset_to_padding: 0,
                    bytes_of_callee_saved_registers: 0,
                    offset_of_exception_handler: 0,
                    section_id_of_exception_handler: 0,
                    flags: FrameProcedureFlags {
                        has_alloca: false,
                        has_setjmp: false,
                        has_longjmp: false,
                        has_inline_assembly: false,
                        has_exception_handling: false,
                        marked_inline: true,
                        has_structured_exception_handling: false,
                        naked: false,
                        security_checks: false,
                        async_exception_handling: true,
                        no_stack_ordering: false,
                        inlined: false,
                        strict_security_checks: false,
                        safe_buffers: false,
                        encoded_local_base_pointer_mask: 1,
                        encoded_param_base_pointer_mask: 1,
                        profile_guided_optimization: false,
                        valid_profile_counts: false,
                        optimized_for_speed: true,
                        guard_cfg: false,
                        guard_cfw: false,
                    },
                })
            );
        }

        #[test]
        fn kind_1105() {
            let data = &[
                5, 17, 224, 95, 151, 0, 1, 0, 0, 100, 97, 118, 49, 100, 95, 119, 95, 97, 118, 103,
                95, 115, 115, 115, 101, 51, 0, 0, 0, 0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1105);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Label(LabelSymbol {
                    offset: PdbInternalSectionOffset {
                        offset: 0x0097_5fe0,
                        section: 1
                    },
                    flags: ProcedureFlags {
                        nofpo: false,
                        int: false,
                        far: false,
                        never: false,
                        notreached: false,
                        cust_call: false,
                        noinline: false,
                        optdbginfo: false
                    },
                    name: "dav1d_w_avg_ssse3".into(),
                })
            );
        }

        #[test]
        fn kind_1106() {
            let data = &[6, 17, 120, 34, 0, 0, 18, 0, 116, 104, 105, 115, 0, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1106);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::RegisterVariable(RegisterVariableSymbol {
                    type_index: TypeIndex(8824),
                    register: Register(18),
                    name: "this".into(),
                })
            );
        }

        #[test]
        fn kind_110e() {
            let data = &[
                14, 17, 2, 0, 0, 0, 192, 85, 0, 0, 1, 0, 95, 95, 108, 111, 99, 97, 108, 95, 115,
                116, 100, 105, 111, 95, 112, 114, 105, 110, 116, 102, 95, 111, 112, 116, 105, 111,
                110, 115, 0, 0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x110e);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Public(PublicSymbol {
                    code: false,
                    function: true,
                    managed: false,
                    msil: false,
                    offset: PdbInternalSectionOffset {
                        offset: 21952,
                        section: 1
                    },
                    name: "__local_stdio_printf_options".into(),
                })
            );
        }

        #[test]
        fn kind_1111() {
            let data = &[
                17, 17, 12, 0, 0, 0, 48, 16, 0, 0, 22, 0, 109, 97, 120, 105, 109, 117, 109, 95, 99,
                111, 117, 110, 116, 0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1111);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::RegisterRelative(RegisterRelativeSymbol {
                    offset: 12,
                    type_index: TypeIndex(0x1030),
                    register: Register(22),
                    name: "maximum_count".into(),
                })
            );
        }

        #[test]
        fn kind_1124() {
            let data = &[36, 17, 115, 116, 100, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1124);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::UsingNamespace(UsingNamespaceSymbol { name: "std".into() })
            );
        }

        #[test]
        fn kind_1125() {
            let data = &[
                37, 17, 0, 0, 0, 0, 108, 0, 0, 0, 1, 0, 66, 97, 122, 58, 58, 102, 95, 112, 117, 98,
                108, 105, 99, 0,
            ];
            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1125);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::ProcedureReference(ProcedureReferenceSymbol {
                    global: true,
                    sum_name: 0,
                    symbol_index: SymbolIndex(108),
                    module: Some(0),
                    name: Some("Baz::f_public".into()),
                })
            );
        }

        #[test]
        fn kind_1108() {
            let data = &[8, 17, 112, 6, 0, 0, 118, 97, 95, 108, 105, 115, 116, 0];
            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1108);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::UserDefinedType(UserDefinedTypeSymbol {
                    type_index: TypeIndex(1648),
                    name: "va_list".into(),
                })
            );
        }

        #[test]
        fn kind_1107() {
            let data = &[
                7, 17, 201, 18, 0, 0, 1, 0, 95, 95, 73, 83, 65, 95, 65, 86, 65, 73, 76, 65, 66, 76,
                69, 95, 83, 83, 69, 50, 0, 0,
            ];
            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1107);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Constant(ConstantSymbol {
                    managed: false,
                    type_index: TypeIndex(4809),
                    value: Variant::U16(1),
                    name: "__ISA_AVAILABLE_SSE2".into(),
                })
            );
        }

        #[test]
        fn kind_110d() {
            let data = &[
                13, 17, 116, 0, 0, 0, 16, 0, 0, 0, 3, 0, 95, 95, 105, 115, 97, 95, 97, 118, 97,
                105, 108, 97, 98, 108, 101, 0, 0, 0,
            ];
            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x110d);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Data(DataSymbol {
                    global: true,
                    managed: false,
                    type_index: TypeIndex(116),
                    offset: PdbInternalSectionOffset {
                        offset: 16,
                        section: 3
                    },
                    name: "__isa_available".into(),
                })
            );
        }

        #[test]
        fn kind_110c() {
            let data = &[
                12, 17, 32, 0, 0, 0, 240, 36, 1, 0, 2, 0, 36, 120, 100, 97, 116, 97, 115, 121, 109,
                0,
            ];
            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x110c);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Data(DataSymbol {
                    global: false,
                    managed: false,
                    type_index: TypeIndex(32),
                    offset: PdbInternalSectionOffset {
                        offset: 74992,
                        section: 2
                    },
                    name: "$xdatasym".into(),
                })
            );
        }

        #[test]
        fn kind_1127() {
            let data = &[
                39, 17, 0, 0, 0, 0, 128, 4, 0, 0, 182, 0, 99, 97, 112, 116, 117, 114, 101, 95, 99,
                117, 114, 114, 101, 110, 116, 95, 99, 111, 110, 116, 101, 120, 116, 0, 0, 0,
            ];
            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1127);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::ProcedureReference(ProcedureReferenceSymbol {
                    global: false,
                    sum_name: 0,
                    symbol_index: SymbolIndex(1152),
                    module: Some(181),
                    name: Some("capture_current_context".into()),
                })
            );
        }

        #[test]
        fn kind_112c() {
            let data = &[44, 17, 0, 0, 5, 0, 5, 0, 0, 0, 32, 124, 0, 0, 2, 0, 2, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };

            assert_eq!(symbol.raw_kind(), 0x112c);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Trampoline(TrampolineSymbol {
                    tramp_type: TrampolineType::Incremental,
                    size: 0x5,
                    thunk: PdbInternalSectionOffset {
                        offset: 0x5,
                        section: 0x2
                    },
                    target: PdbInternalSectionOffset {
                        offset: 0x7c20,
                        section: 0x2
                    },
                })
            );
        }

        #[test]
        fn kind_1110() {
            let data = &[
                16, 17, 0, 0, 0, 0, 48, 2, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 7,
                16, 0, 0, 64, 85, 0, 0, 1, 0, 0, 66, 97, 122, 58, 58, 102, 95, 112, 114, 111, 116,
                101, 99, 116, 101, 100, 0,
            ];
            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1110);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Procedure(ProcedureSymbol {
                    global: true,
                    dpc: false,
                    parent: None,
                    end: SymbolIndex(560),
                    next: None,
                    len: 6,
                    dbg_start_offset: 5,
                    dbg_end_offset: 5,
                    type_index: TypeIndex(4103),
                    offset: PdbInternalSectionOffset {
                        offset: 21824,
                        section: 1
                    },
                    flags: ProcedureFlags {
                        nofpo: false,
                        int: false,
                        far: false,
                        never: false,
                        notreached: false,
                        cust_call: false,
                        noinline: false,
                        optdbginfo: false
                    },
                    name: "Baz::f_protected".into(),
                })
            );
        }

        #[test]
        fn kind_1103() {
            let data = &[
                3, 17, 244, 149, 9, 0, 40, 151, 9, 0, 135, 1, 0, 0, 108, 191, 184, 2, 1, 0, 0, 0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1103);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Block(BlockSymbol {
                    parent: SymbolIndex(0x0009_95f4),
                    end: SymbolIndex(0x0009_9728),
                    len: 391,
                    offset: PdbInternalSectionOffset {
                        section: 0x1,
                        offset: 0x02b8_bf6c
                    },
                    name: "".into(),
                })
            );
        }

        #[test]
        fn kind_110f() {
            let data = &[
                15, 17, 0, 0, 0, 0, 156, 1, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 4, 0, 0, 0, 9, 0, 0, 0,
                128, 16, 0, 0, 196, 87, 0, 0, 1, 0, 128, 95, 95, 115, 99, 114, 116, 95, 99, 111,
                109, 109, 111, 110, 95, 109, 97, 105, 110, 0, 0, 0,
            ];
            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x110f);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Procedure(ProcedureSymbol {
                    global: false,
                    dpc: false,
                    parent: None,
                    end: SymbolIndex(412),
                    next: None,
                    len: 18,
                    dbg_start_offset: 4,
                    dbg_end_offset: 9,
                    type_index: TypeIndex(4224),
                    offset: PdbInternalSectionOffset {
                        offset: 22468,
                        section: 1
                    },
                    flags: ProcedureFlags {
                        nofpo: false,
                        int: false,
                        far: false,
                        never: false,
                        notreached: false,
                        cust_call: false,
                        noinline: false,
                        optdbginfo: true
                    },
                    name: "__scrt_common_main".into(),
                })
            );
        }

        #[test]
        fn kind_1116() {
            let data = &[
                22, 17, 7, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 14, 0, 10, 0, 115, 98, 77, 105, 99,
                114, 111, 115, 111, 102, 116, 32, 40, 82, 41, 32, 76, 73, 78, 75, 0, 0, 0, 0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1116);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::CompileFlags(CompileFlagsSymbol {
                    language: SourceLanguage::Link,
                    flags: CompileFlags {
                        edit_and_continue: false,
                        no_debug_info: false,
                        link_time_codegen: false,
                        no_data_align: false,
                        managed: false,
                        security_checks: false,
                        hot_patch: false,
                        cvtcil: false,
                        msil_module: false,
                        sdl: false,
                        pgo: false,
                        exp_module: false,
                    },
                    cpu_type: CPUType::Intel80386,
                    frontend_version: CompilerVersion {
                        major: 0,
                        minor: 0,
                        build: 0,
                        qfe: None,
                    },
                    backend_version: CompilerVersion {
                        major: 14,
                        minor: 10,
                        build: 25203,
                        qfe: None,
                    },
                    version_string: "Microsoft (R) LINK".into(),
                })
            );
        }

        #[test]
        fn kind_1132() {
            let data = &[
                50, 17, 0, 0, 0, 0, 108, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0, 196, 252, 10, 0, 56, 67,
                0, 0, 1, 0, 1, 0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1132);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::SeparatedCode(SeparatedCodeSymbol {
                    parent: SymbolIndex(0x0),
                    end: SymbolIndex(0x6c),
                    len: 88,
                    flags: SeparatedCodeFlags {
                        islexicalscope: false,
                        returnstoparent: false
                    },
                    offset: PdbInternalSectionOffset {
                        section: 0x1,
                        offset: 0xafcc4
                    },
                    parent_offset: PdbInternalSectionOffset {
                        section: 0x1,
                        offset: 0x4338
                    }
                })
            );
        }

        #[test]
        fn kind_113c() {
            let data = &[
                60, 17, 1, 36, 2, 0, 7, 0, 19, 0, 13, 0, 6, 102, 0, 0, 19, 0, 13, 0, 6, 102, 0, 0,
                77, 105, 99, 114, 111, 115, 111, 102, 116, 32, 40, 82, 41, 32, 79, 112, 116, 105,
                109, 105, 122, 105, 110, 103, 32, 67, 111, 109, 112, 105, 108, 101, 114, 0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x113c);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::CompileFlags(CompileFlagsSymbol {
                    language: SourceLanguage::Cpp,
                    flags: CompileFlags {
                        edit_and_continue: false,
                        no_debug_info: false,
                        link_time_codegen: true,
                        no_data_align: false,
                        managed: false,
                        security_checks: true,
                        hot_patch: false,
                        cvtcil: false,
                        msil_module: false,
                        sdl: true,
                        pgo: false,
                        exp_module: false,
                    },
                    cpu_type: CPUType::Pentium3,
                    frontend_version: CompilerVersion {
                        major: 19,
                        minor: 13,
                        build: 26118,
                        qfe: Some(0),
                    },
                    backend_version: CompilerVersion {
                        major: 19,
                        minor: 13,
                        build: 26118,
                        qfe: Some(0),
                    },
                    version_string: "Microsoft (R) Optimizing Compiler".into(),
                })
            );
        }

        #[test]
        fn kind_113e() {
            let data = &[62, 17, 193, 19, 0, 0, 1, 0, 116, 104, 105, 115, 0, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x113e);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Local(LocalSymbol {
                    type_index: TypeIndex(5057),
                    flags: LocalVariableFlags {
                        isparam: true,
                        addrtaken: false,
                        compgenx: false,
                        isaggregate: false,
                        isaliased: false,
                        isalias: false,
                        isretvalue: false,
                        isoptimizedout: false,
                        isenreg_glob: false,
                        isenreg_stat: false,
                    },
                    name: "this".into(),
                })
            );
        }

        #[test]
        fn kind_114c() {
            let data = &[76, 17, 95, 17, 0, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x114c);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::BuildInfo(BuildInfoSymbol {
                    id: IdIndex(0x115F)
                })
            );
        }

        #[test]
        fn kind_114d() {
            let data = &[
                77, 17, 144, 1, 0, 0, 208, 1, 0, 0, 121, 17, 0, 0, 12, 6, 3, 0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x114d);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::InlineSite(InlineSiteSymbol {
                    parent: Some(SymbolIndex(0x0190)),
                    end: SymbolIndex(0x01d0),
                    inlinee: IdIndex(4473),
                    invocations: None,
                    annotations: BinaryAnnotations::new(&[12, 6, 3, 0]),
                })
            );
        }

        #[test]
        fn kind_114e() {
            let data = &[78, 17];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x114e);
            assert_eq!(symbol.parse().expect("parse"), SymbolData::InlineSiteEnd);
        }
    }

    mod iterator {
        use crate::symbol::*;

        fn create_iter() -> SymbolIter<'static> {
            let data = &[
                0x00, 0x00, 0x00, 0x00, // module signature (padding)
                0x02, 0x00, 0x4e, 0x11, // S_INLINESITE_END
                0x02, 0x00, 0x06, 0x00, // S_END
            ];

            let mut buf = ParseBuffer::from(&data[..]);
            buf.seek(4); // skip the module signature
            SymbolIter::new(buf)
        }

        #[test]
        fn test_iter() {
            let symbols: Vec<_> = create_iter().collect().expect("collect");

            let expected = [
                Symbol {
                    index: SymbolIndex(0x4),
                    data: &[0x4e, 0x11], // S_INLINESITE_END
                },
                Symbol {
                    index: SymbolIndex(0x8),
                    data: &[0x06, 0x00], // S_END
                },
            ];

            assert_eq!(symbols, expected);
        }

        #[test]
        fn test_seek() {
            let mut symbols = create_iter();
            symbols.seek(SymbolIndex(0x8));

            let symbol = symbols.next().expect("get symbol");
            let expected = Symbol {
                index: SymbolIndex(0x8),
                data: &[0x06, 0x00], // S_END
            };

            assert_eq!(symbol, Some(expected));
        }

        #[test]
        fn test_skip_to() {
            let mut symbols = create_iter();
            let symbol = symbols.skip_to(SymbolIndex(0x8)).expect("get symbol");

            let expected = Symbol {
                index: SymbolIndex(0x8),
                data: &[0x06, 0x00], // S_END
            };

            assert_eq!(symbol, Some(expected));
        }

        #[test]
        fn kind_1139() {
            let data = &[57, 17, 246, 3, 0, 0, 1, 0, 0, 0, 23, 17, 0, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1139);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::CallSiteInfo(CallSiteInfoSymbol {
                    offset: PdbInternalSectionOffset {
                        offset: 0x3f6,
                        section: 1,
                    },
                    type_index: TypeIndex(0x1117),
                })
            );
        }

        #[test]
        fn kind_1141() {
            let data = &[65, 17, 74, 1, 0, 0, 192, 3, 0, 0, 1, 0, 32, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1141);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::DefRangeRegister(DefRangeRegisterSymbol {
                    register: Register(0x14a),
                    may_have_no_name: 0,
                    range: LocalVariableAddrRange {
                        offset_start: 0x3c0,
                        isect_start: 1,
                        range: 0x20,
                    },
                    gaps: vec![],
                })
            );
        }

        #[test]
        fn kind_1142() {
            let data = &[66, 17, 56, 0, 0, 0, 174, 13, 0, 0, 1, 0, 93, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1142);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::DefRangeFramePointerRel(DefRangeFramePointerRelSymbol {
                    offset: 0x38,
                    range: LocalVariableAddrRange {
                        offset_start: 0xdae,
                        isect_start: 1,
                        range: 0x5d,
                    },
                    gaps: vec![],
                })
            );
        }

        #[test]
        fn kind_1143() {
            let data = &[67, 17, 74, 1, 0, 0, 0, 0, 0, 0, 80, 4, 0, 0, 1, 0, 40, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1143);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::DefRangeSubfieldRegister(DefRangeSubfieldRegisterSymbol {
                    register: Register(0x14a),
                    may_have_no_name: 0, // TODO This should be true accord to llvm-pdbutil
                    offset_in_parent: 0,
                    range: LocalVariableAddrRange {
                        offset_start: 0x450,
                        isect_start: 1,
                        range: 0x28,
                    },
                    gaps: vec![],
                })
            );
        }

        #[test]
        fn kind_1144() {
            let data = &[68, 17, 80, 0, 0, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1144);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::DefRangeFramePointerRelFullScope(
                    DefRangeFramePointerRelFullScopeSymbol { offset: 80 }
                )
            );
        }

        #[test]
        fn kind_1145() {
            let data = &[69, 17, 78, 1, 0, 0, 32, 0, 0, 0, 78, 59, 0, 0, 1, 0, 23, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1145);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::DefRangeRegisterRel(DefRangeRegisterRelSymbol {
                    register: Register(0x14e),
                    flags: 0x00,
                    base_pointer_offset: 0x20,
                    range: LocalVariableAddrRange {
                        offset_start: 0x3b4e,
                        isect_start: 1,
                        range: 0x17,
                    },
                    gaps: vec![],
                })
            );
        }

        #[test]
        fn kind_115a() {
            let data = &[90, 17, 1, 0, 0, 0, 98, 16, 0, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x115a);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Callees(CalleesSymbol {
                    type_indices: vec![TypeIndex(0x1062)],
                })
            );
        }

        #[test]
        fn kind_1168() {
            let data = &[104, 17, 1, 0, 0, 0, 102, 16, 0, 0];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1168);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Inlinees(InlineesSymbol {
                    type_indices: vec![TypeIndex(0x1066)],
                })
            );
        }

        #[test]
        fn kind_1136() {
            let data = &[
                54, 17, 1, 0, 12, 0, 0, 16, 0, 0, 145, 75, 0, 0, 32, 0, 0, 96, 46, 116, 101, 120,
                116, 0, 0, 0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1136);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::Section(SectionSymbol {
                    section_number: 1,
                    alignment: 12,
                    rva: 0x1000,
                    length: 0x4b91,
                    characteristics: 0x60000020,
                    name: ".text".into(),
                })
            );
        }

        #[test]
        fn kind_1137() {
            let data = &[
                55, 17, 16, 43, 0, 0, 32, 0, 0, 96, 0, 0, 0, 0, 1, 0, 46, 116, 101, 120, 116, 36,
                109, 110, 0, 0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x1137);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::CoffGroup(CoffGroupSymbol {
                    size: 0x2b10,
                    characteristics: 0x60000020,
                    offset: PdbInternalSectionOffset {
                        offset: 0,
                        section: 1,
                    },
                    name: ".text$mn".into(),
                })
            );
        }

        #[test]
        fn kind_113d() {
            let data = &[
                61, 17, 0, 99, 119, 100, 0, 68, 58, 92, 97, 92, 95, 119, 111, 114, 107, 92, 49, 92,
                115, 92, 115, 114, 99, 92, 118, 99, 116, 111, 111, 108, 115, 92, 99, 114, 116, 92,
                118, 99, 115, 116, 97, 114, 116, 117, 112, 92, 98, 117, 105, 108, 100, 92, 109,
                100, 92, 109, 115, 118, 99, 114, 116, 95, 107, 101, 114, 110, 101, 108, 51, 50, 0,
                101, 120, 101, 0, 68, 58, 92, 97, 92, 95, 119, 111, 114, 107, 92, 49, 92, 115, 92,
                115, 114, 99, 92, 116, 111, 111, 108, 115, 92, 118, 99, 116, 111, 111, 108, 115,
                92, 68, 101, 118, 49, 52, 92, 98, 105, 110, 92, 120, 54, 52, 92, 97, 109, 100, 54,
                52, 92, 109, 108, 54, 52, 46, 101, 120, 101, 0, 115, 114, 99, 0, 68, 58, 92, 97,
                92, 95, 119, 111, 114, 107, 92, 49, 92, 115, 92, 115, 114, 99, 92, 118, 99, 116,
                111, 111, 108, 115, 92, 99, 114, 116, 92, 118, 99, 115, 116, 97, 114, 116, 117,
                112, 92, 115, 114, 99, 92, 109, 105, 115, 99, 92, 97, 109, 100, 54, 52, 92, 103,
                117, 97, 114, 100, 95, 100, 105, 115, 112, 97, 116, 99, 104, 46, 97, 115, 109, 0,
                0, 0, 0, 0,
            ];

            let symbol = Symbol {
                data,
                index: SymbolIndex(0),
            };
            assert_eq!(symbol.raw_kind(), 0x113d);
            assert_eq!(
                symbol.parse().expect("parse"),
                SymbolData::EnvBlock(EnvBlockSymbol {
                    entries: vec![
                        "cwd".into(),
                        r"D:\a\_work\1\s\src\vctools\crt\vcstartup\build\md\msvcrt_kernel32".into(),
                        "exe".into(),
                        r"D:\a\_work\1\s\src\tools\vctools\Dev14\bin\x64\amd64\ml64.exe".into(),
                        r"src".into(),
                        r"D:\a\_work\1\s\src\vctools\crt\vcstartup\src\misc\amd64\guard_dispatch.asm".into(),
                    ],
                })
            );
        }
    }
}
