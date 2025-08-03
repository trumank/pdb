use pdb::{FallibleIterator, PDB};
use std::env;

struct DumpContext<'a> {
    show_va: bool,
    image_base: u64,
    address_map: pdb::AddressMap<'a>,
}

impl<'a> DumpContext<'a> {
    fn new(show_va: bool, image_base: u64, address_map: pdb::AddressMap<'a>) -> Self {
        Self {
            show_va,
            image_base,
            address_map,
        }
    }

    fn format_address(&self, offset: &pdb::PdbInternalSectionOffset) -> String {
        let rva = offset.to_rva(&self.address_map).unwrap_or_default();
        if self.show_va {
            let va = self.image_base + rva.0 as u64;
            format!(
                "{:04X}:{:08X} [VA 0x{:016X}]",
                offset.section, offset.offset, va
            )
        } else {
            format!(
                "{:04X}:{:08X} [RVA 0x{:08X}]",
                offset.section, offset.offset, rva.0
            )
        }
    }

    fn format_dual_address(
        &self,
        offset1: &pdb::PdbInternalSectionOffset,
        offset2: &pdb::PdbInternalSectionOffset,
        name1: &str,
        name2: &str,
    ) -> String {
        let rva1 = offset1.to_rva(&self.address_map).unwrap_or_default();
        let rva2 = offset2.to_rva(&self.address_map).unwrap_or_default();

        if self.show_va {
            let va1 = self.image_base + rva1.0 as u64;
            let va2 = self.image_base + rva2.0 as u64;
            format!(
                "{} @ {:04X}:{:08X} [VA 0x{:016X}], {} @ {:04X}:{:08X} [VA 0x{:016X}]",
                name1,
                offset1.section,
                offset1.offset,
                va1,
                name2,
                offset2.section,
                offset2.offset,
                va2
            )
        } else {
            format!(
                "{} @ {:04X}:{:08X} [RVA 0x{:08X}], {} @ {:04X}:{:08X} [RVA 0x{:08X}]",
                name1,
                offset1.section,
                offset1.offset,
                rva1.0,
                name2,
                offset2.section,
                offset2.offset,
                rva2.0
            )
        }
    }
}

fn dump_pdb_info(pdb: &mut PDB<'_, std::fs::File>) -> pdb::Result<()> {
    println!("=== PDB Information ===");

    let info = pdb.pdb_information()?;
    println!("  Version: {:?}", info.version);
    println!("  Signature: 0x{:08X}", info.signature);
    println!("  Age: {}", info.age);
    println!("  GUID: {}", info.guid);

    // Debug information
    let dbi = pdb.debug_information()?;
    println!("\nDebug Information:");
    println!("  Age: {:?}", dbi.age());
    println!("  Machine type: {:?}", dbi.machine_type());

    // List named streams
    let stream_names = info.stream_names()?;
    println!("\nNamed Streams:");
    for name in stream_names.iter() {
        println!("  [{}] {}", name.stream_id.0, name.name);
    }

    Ok(())
}

fn dump_streams(pdb: &mut PDB<'_, std::fs::File>) -> pdb::Result<()> {
    println!("\n=== Stream Information ===");

    // Try to enumerate all streams
    let mut found_streams = 0;
    let mut i = 0;
    loop {
        match pdb.raw_stream(pdb::StreamIndex(i)) {
            Ok(Some(stream)) => {
                println!("  Stream {}: {} bytes", i, stream.len());
                found_streams += 1;
            }
            Ok(None) => {
                // Stream doesn't exist, but continue checking
            }
            Err(_) => {
                // Stop on error - likely reached the end
                break;
            }
        }
        i += 1;
    }
    println!("  Total streams found: {}", found_streams);

    Ok(())
}

fn print_symbol(symbol: &pdb::Symbol<'_>, indent: &str, ctx: &DumpContext<'_>) -> pdb::Result<()> {
    match symbol.parse() {
        Ok(pdb::SymbolData::Public(data)) => {
            println!(
                "{}PUBLIC: {} @ {} (function: {})",
                indent,
                data.name,
                ctx.format_address(&data.offset),
                data.function
            );
        }
        Ok(pdb::SymbolData::Data(data)) => {
            println!(
                "{}DATA: {} @ {} (global: {})",
                indent,
                data.name,
                ctx.format_address(&data.offset),
                data.global
            );
        }
        Ok(pdb::SymbolData::Procedure(data)) => {
            println!(
                "{}PROCEDURE: {} @ {} (len: 0x{:X})",
                indent,
                data.name,
                ctx.format_address(&data.offset),
                data.len
            );
        }
        Ok(pdb::SymbolData::Thunk(data)) => {
            println!(
                "{}THUNK: {} @ {}",
                indent,
                data.name,
                ctx.format_address(&data.offset)
            );
        }
        Ok(pdb::SymbolData::Constant(data)) => {
            println!(
                "{}CONSTANT: {} = {:?} (type: {:?})",
                indent, data.name, data.value, data.type_index
            );
        }
        Ok(pdb::SymbolData::UserDefinedType(data)) => {
            println!("{}UDT: {} (type: {:?})", indent, data.name, data.type_index);
        }
        Ok(pdb::SymbolData::ProcedureReference(data)) => {
            let name = data
                .name
                .as_ref()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "<unnamed>".into());
            println!(
                "{}PROC_REF: {} (global: {}, symbol: {:?}, module: {:?})",
                indent, name, data.global, data.symbol_index, data.module
            );
        }
        Ok(pdb::SymbolData::DataReference(data)) => {
            let name = data
                .name
                .as_ref()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "<unnamed>".into());
            println!(
                "{}DATA_REF: {} (sum_name: {}, symbol: {:?}, module: {:?})",
                indent, name, data.sum_name, data.symbol_index, data.module
            );
        }
        Ok(pdb::SymbolData::Export(data)) => {
            println!(
                "{}EXPORT: {} (ordinal: {}, flags: {:?})",
                indent, data.name, data.ordinal, data.flags
            );
        }
        Ok(pdb::SymbolData::ThreadStorage(data)) => {
            println!(
                "{}THREAD_STORAGE: {} @ {} (type: {:?})",
                indent,
                data.name,
                ctx.format_address(&data.offset),
                data.type_index
            );
        }
        Ok(pdb::SymbolData::AnnotationReference(data)) => {
            println!(
                "{}ANNOTATION_REF: {} (sum_name: {}, symbol: {:?}, module: {:?})",
                indent, data.name, data.sum_name, data.symbol_index, data.module
            );
        }
        Ok(pdb::SymbolData::Trampoline(data)) => {
            println!(
                "{}TRAMPOLINE: type={:?}, size={}, {}",
                indent,
                data.tramp_type,
                data.size,
                ctx.format_dual_address(&data.thunk, &data.target, "thunk", "target")
            );
        }
        Ok(pdb::SymbolData::Local(data)) => {
            println!(
                "{}LOCAL: {} (type: {:?})",
                indent, data.name, data.type_index
            );
        }
        Ok(pdb::SymbolData::CompileFlags(data)) => {
            println!("{}COMPILE_FLAGS:", indent);
            println!("{}  Language: {:?}", indent, data.language);
            println!("{}  Flags: {:?}", indent, data.flags);
            println!("{}  CPU Type: {:?}", indent, data.cpu_type);
            println!(
                "{}  Frontend version: {}.{}.{:?}.{:?}",
                indent,
                data.frontend_version.major,
                data.frontend_version.minor,
                data.frontend_version.build,
                data.frontend_version.qfe
            );
            println!(
                "{}  Backend version: {}.{}.{:?}.{:?}",
                indent,
                data.backend_version.major,
                data.backend_version.minor,
                data.backend_version.build,
                data.backend_version.qfe
            );
            println!("{}  Version string: {}", indent, data.version_string);
        }
        Ok(pdb::SymbolData::BuildInfo(data)) => {
            println!("{}BUILD_INFO: {:?}", indent, data.id);
        }
        Ok(pdb::SymbolData::Block(data)) => {
            println!(
                "{}BLOCK: @ {} (len: 0x{:X})",
                indent,
                ctx.format_address(&data.offset),
                data.len
            );
        }
        Ok(pdb::SymbolData::Label(data)) => {
            println!(
                "{}LABEL: {} @ {}",
                indent,
                data.name,
                ctx.format_address(&data.offset)
            );
        }
        Ok(pdb::SymbolData::UsingNamespace(data)) => {
            println!("{}USING_NAMESPACE: {}", indent, data.name);
        }
        Ok(pdb::SymbolData::InlineSite(data)) => {
            println!(
                "{}INLINE_SITE: inlinee={:?} @ parent={:?}",
                indent, data.inlinee, data.parent
            );
        }
        Ok(pdb::SymbolData::RegisterRelative(data)) => {
            println!(
                "{}REGISTER_RELATIVE: {} @ reg+{} (type: {:?})",
                indent, data.name, data.offset, data.type_index
            );
        }
        Ok(pdb::SymbolData::DefRangeFramePointerRel(data)) => {
            println!("{}DEF_RANGE_FP_REL: offset={}", indent, data.offset);
        }
        Ok(pdb::SymbolData::ScopeEnd) => {
            println!("{}SCOPE_END", indent);
        }
        Ok(pdb::SymbolData::ObjName(data)) => {
            println!(
                "{}OBJ_NAME: {} (signature: 0x{:08X})",
                indent, data.name, data.signature
            );
        }
        Ok(pdb::SymbolData::RegisterVariable(data)) => {
            println!(
                "{}REGISTER_VARIABLE: {} in reg {:?} (type: {:?})",
                indent, data.name, data.register, data.type_index
            );
        }
        Ok(pdb::SymbolData::FrameProc(data)) => {
            println!(
                "{}FRAME_PROC: frame_size={}, pad_size={}, flags={:?}",
                indent, data.total_frame_bytes, data.padding_frame_bytes, data.flags
            );
        }
        Ok(pdb::SymbolData::Annotation(data)) => {
            println!(
                "{}ANNOTATION: @ {}",
                indent,
                ctx.format_address(&data.code_offset)
            );
            for (i, s) in data.strings.iter().enumerate() {
                println!("{}  [{}] {}", indent, i, s);
            }
        }
        Ok(pdb::SymbolData::InlineSiteEnd) => {
            println!("{}INLINE_SITE_END", indent);
        }
        Ok(pdb::SymbolData::ProcedureEnd) => {
            println!("{}PROCEDURE_END", indent);
        }
        Ok(pdb::SymbolData::CallSiteInfo(data)) => {
            println!(
                "{}CALL_SITE_INFO: @ {} (type: {:?})",
                indent,
                ctx.format_address(&data.offset),
                data.type_index
            );
        }
        Ok(pdb::SymbolData::HeapAllocationSite(data)) => {
            println!(
                "{}HEAP_ALLOC_SITE: @ {} (type: {:?}, size: 0x{:X})",
                indent,
                ctx.format_address(&data.code_offset),
                data.type_index,
                data.call_instruction_size
            );
        }
        Ok(pdb::SymbolData::CoffGroup(data)) => {
            println!(
                "{}COFF_GROUP: {} (size: 0x{:X}, characteristics: 0x{:08X})",
                indent, data.name, data.size, data.characteristics
            );
        }
        Ok(pdb::SymbolData::Section(data)) => {
            println!(
                "{}SECTION: #{} {} @ RVA 0x{:08X} (length: 0x{:X})",
                indent, data.section_number, data.name, data.rva, data.length
            );
            println!(
                "{}  Alignment: {}, characteristics: 0x{:08X}",
                indent, data.alignment, data.characteristics
            );
        }
        Ok(pdb::SymbolData::DefRangeRegister(data)) => {
            println!(
                "{}DEF_RANGE_REGISTER: reg={:?}, range=[{:?}]",
                indent, data.register, data.range
            );
        }
        Ok(pdb::SymbolData::DefRangeRegisterRel(data)) => {
            println!(
                "{}DEF_RANGE_REGISTER_REL: reg={:?}+{}, range=[{:?}]",
                indent, data.register, data.base_pointer_offset, data.range
            );
        }
        Ok(pdb::SymbolData::DefRangeSubfieldRegister(data)) => {
            println!(
                "{}DEF_RANGE_SUBFIELD_REGISTER: reg={:?}, offset={}, range=[{:?}]",
                indent, data.register, data.offset_in_parent, data.range
            );
        }
        Ok(pdb::SymbolData::DefRangeFramePointerRelFullScope(data)) => {
            println!(
                "{}DEF_RANGE_FP_REL_FULL_SCOPE: offset={}",
                indent, data.offset
            );
        }
        Ok(pdb::SymbolData::Callees(data)) => {
            println!("{}CALLEES: indices={:?}", indent, data.type_indices);
        }
        Ok(pdb::SymbolData::Inlinees(data)) => {
            println!("{}INLINEES: indices={:?}", indent, data.type_indices);
        }
        Ok(pdb::SymbolData::FileStatic(data)) => {
            println!(
                "{}FILE_STATIC: {} (type: {:?}, offset: {})",
                indent, data.name, data.type_index, data.mod_filename_offset
            );
        }
        Ok(pdb::SymbolData::SeparatedCode(data)) => {
            println!(
                "{}SEPARATED_CODE: parent={:?}, @ {} (len: 0x{:X})",
                indent,
                data.parent,
                ctx.format_address(&data.offset),
                data.len
            );
            println!("{}  Flags: {:?}", indent, data.flags);
        }
        Ok(pdb::SymbolData::MultiRegisterVariable(data)) => {
            println!(
                "{}MULTI_REGISTER_VARIABLE: (type: {:?})",
                indent, data.type_index
            );
            if !data.registers.is_empty() {
                println!("{}  Registers: {:?}", indent, data.registers);
            }
        }
        Ok(pdb::SymbolData::PogoData(data)) => {
            println!(
                "{}POGO_DATA: {} - invocations={}, dynamic_instructions={}, static_instructions={}",
                indent,
                data.name,
                data.invocation_count,
                data.dynamic_instruction_count,
                data.static_instruction_count
            );
        }
        Ok(pdb::SymbolData::EnvBlock(data)) => {
            println!("{}ENV_BLOCK: {} entries", indent, data.entries.len());
            for entry in &data.entries {
                println!("{}  {}", indent, entry);
            }
        }
        Ok(pdb::SymbolData::FrameCookie(data)) => {
            println!(
                "{}FRAME_COOKIE: offset={:?}, register={:?}, cookie_kind={:?}, flags={}",
                indent, data.code_offset, data.register, data.cookie_kind, data.flags
            );
        }
        Ok(pdb::SymbolData::Callers(data)) => {
            println!(
                "{}CALLERS: count={}, callers={:?}",
                indent, data.count, data.callers
            );
        }
        Ok(pdb::SymbolData::Association(data)) => {
            println!(
                "{}ASSOCIATION: flags={:?}, data={:?}",
                indent, data.flags, data.data
            );
        }
        Ok(pdb::SymbolData::DefRangeConstVal(data)) => {
            println!("{}DEF_RANGE_CONST_VAL: value={:?}", indent, data.value);
        }
        Ok(pdb::SymbolData::DefRangeGlobalSym(data)) => {
            println!(
                "{}DEF_RANGE_GLOBAL_SYM: type_index={:?}, flags={:?}",
                indent, data.type_index, data.flags
            );
        }
        Ok(pdb::SymbolData::InlineSite2Ex(data)) => {
            println!(
                "{}INLINE_SITE2_EX: register={}, flags={}",
                indent, data.register, data.flags
            );
        }
        Ok(other) => {
            eprintln!(
                "WARNING: Unimplemented symbol type: (discriminant {:?})",
                std::mem::discriminant(&other)
            );
            println!("{}{:?}: {:?}", indent, symbol.raw_kind(), other);
        }
        Err(e) => {
            eprintln!("ERROR parsing symbol: {:?}", e);
        }
    }
    Ok(())
}

fn dump_symbols(pdb: &mut PDB<'_, std::fs::File>, ctx: &DumpContext<'_>) -> pdb::Result<()> {
    println!("\n=== Symbol Information ===");
    let addr_type = if ctx.show_va { "VA" } else { "RVA" };
    println!("Address format: {}", addr_type);
    if ctx.show_va {
        println!("Using image base: 0x{:016X}", ctx.image_base);
    }

    // Dump global symbols
    println!("\nGlobal Symbols:");
    let symbol_table = pdb.global_symbols()?;
    let mut count = 0;
    let mut symbols = symbol_table.iter();

    // Show all symbols in detail
    while let Some(symbol) = symbols.next()? {
        print_symbol(&symbol, "  ", ctx)?;
        count += 1;
    }
    println!("  Total: {} global symbols", count);

    // Dump all module symbols
    println!("\nModule Symbols:");
    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;

    while let Some(module) = modules.next()? {
        println!("  From module: {}", module.object_file_name());

        if let Some(info) = pdb.module_info(&module)? {
            let mut module_symbols = info.symbols()?;
            let mut mod_count = 0;

            while let Some(symbol) = module_symbols.next()? {
                print_symbol(&symbol, "    ", ctx)?;
                mod_count += 1;
            }
            println!("    Total symbols in module: {}", mod_count);
        }
    }

    Ok(())
}

fn dump_types(pdb: &mut PDB<'_, std::fs::File>) -> pdb::Result<()> {
    println!("\n=== Type Information ===");

    let type_info = pdb.type_information()?;
    let mut types = type_info.iter();
    let mut count = 0;

    // Show all types
    while let Some(ty) = types.next()? {
        match ty.parse() {
            Ok(pdb::TypeData::Class(data)) => {
                println!("  CLASS: {} (size: {} bytes)", data.name, data.size);
            }
            Ok(pdb::TypeData::Union(data)) => {
                println!("  UNION: {} (size: {} bytes)", data.name, data.size);
            }
            Ok(pdb::TypeData::Enumeration(data)) => {
                println!("  ENUM: {} (type: {:?})", data.name, data.underlying_type);
            }
            Ok(pdb::TypeData::Procedure(data)) => {
                println!(
                    "  PROCEDURE: return={:?}, params={:?}",
                    data.return_type, data.argument_list
                );
            }
            Ok(pdb::TypeData::Pointer(data)) => {
                println!(
                    "  POINTER: to {:?} (size: {} bytes)",
                    data.underlying_type,
                    data.attributes.size()
                );
            }
            Ok(pdb::TypeData::Array(data)) => {
                println!(
                    "  ARRAY: element={:?}, dimensions={:?}",
                    data.element_type, data.dimensions
                );
            }
            Ok(pdb::TypeData::Modifier(data)) => {
                println!(
                    "  MODIFIER: underlying={:?}, const={}, volatile={}",
                    data.underlying_type, data.constant, data.volatile
                );
            }
            Ok(pdb::TypeData::MemberFunction(data)) => {
                println!(
                    "  MEMBER_FUNCTION: return={:?}, class={:?}",
                    data.return_type, data.class_type
                );
            }
            Ok(pdb::TypeData::FieldList(data)) => {
                println!("  FIELD_LIST: {} fields", data.fields.len());
                for field in &data.fields {
                    match field {
                        pdb::TypeData::Member(member) => {
                            println!(
                                "    MEMBER: {} (type: {:?}, offset: {})",
                                member.name, member.field_type, member.offset
                            );
                        }
                        pdb::TypeData::Method(method) => {
                            println!(
                                "    METHOD: {} (type: {:?})",
                                method.name, method.method_type
                            );
                        }
                        pdb::TypeData::StaticMember(static_member) => {
                            println!(
                                "    STATIC_MEMBER: {} (type: {:?})",
                                static_member.name, static_member.field_type
                            );
                        }
                        pdb::TypeData::BaseClass(base) => {
                            println!(
                                "    BASE_CLASS: type={:?}, offset={}",
                                base.base_class, base.offset
                            );
                        }
                        pdb::TypeData::VirtualBaseClass(vbase) => {
                            println!("    VIRTUAL_BASE_CLASS: type={:?}", vbase.base_class);
                        }
                        pdb::TypeData::Enumerate(enum_val) => {
                            println!("    ENUM_VALUE: {} = {:?}", enum_val.name, enum_val.value);
                        }
                        pdb::TypeData::VirtualFunctionTablePointer(vftptr) => {
                            println!("    VFTABLE_PTR: table={:?}", vftptr.table);
                        }
                        _ => {}
                    }
                }
                if data.fields.len() > 5 {
                    println!("    ... and {} more fields", data.fields.len() - 5);
                }
            }
            Ok(pdb::TypeData::Bitfield(data)) => {
                println!(
                    "  BITFIELD: type={:?}, position={}, length={}",
                    data.underlying_type, data.position, data.length
                );
            }
            Ok(pdb::TypeData::ArgumentList(data)) => {
                print!("  ARGUMENT_LIST: (");
                for (i, arg) in data.arguments.iter().enumerate() {
                    if i > 0 {
                        print!(", ");
                    }
                    print!("{:?}", arg);
                }
                println!(")");
            }
            Ok(pdb::TypeData::MethodList(data)) => {
                println!("  METHOD_LIST: {} methods", data.methods.len());
            }
            Ok(pdb::TypeData::Primitive(data)) => {
                println!("  PRIMITIVE: {:?} (kind={:?})", data, data.kind);
            }
            Ok(pdb::TypeData::OverloadedMethod(data)) => {
                println!(
                    "  OVERLOADED_METHOD: {} (count: {}, list: {:?})",
                    data.name, data.count, data.method_list
                );
            }
            Ok(pdb::TypeData::Method(data)) => {
                println!(
                    "  METHOD: {} (type: {:?}, attrs: {:?})",
                    data.name, data.method_type, data.attributes
                );
                if let Some(offset) = data.vtable_offset {
                    println!("    VTable offset: 0x{:X}", offset);
                }
            }
            Ok(pdb::TypeData::StaticMember(data)) => {
                println!(
                    "  STATIC_MEMBER: {} (type: {:?})",
                    data.name, data.field_type
                );
            }
            Ok(pdb::TypeData::Nested(data)) => {
                println!("  NESTED: {} (type: {:?})", data.name, data.nested_type);
            }
            Ok(pdb::TypeData::BaseClass(data)) => {
                println!(
                    "  BASE_CLASS: {:?} @ offset {} (kind: {:?})",
                    data.base_class, data.offset, data.kind
                );
            }
            Ok(pdb::TypeData::VirtualBaseClass(data)) => {
                println!(
                    "  VIRTUAL_BASE_CLASS: {:?} (vbptr: {:?}, vboffset: {}, vtoffset: {})",
                    data.base_class,
                    data.base_pointer,
                    data.base_pointer_offset,
                    data.virtual_base_offset
                );
            }
            Ok(pdb::TypeData::VirtualFunctionTablePointer(data)) => {
                println!("  VFTABLE_PTR: {:?}", data.table);
            }
            Ok(pdb::TypeData::Member(data)) => {
                println!(
                    "  MEMBER: {} (type: {:?}, offset: {})",
                    data.name, data.field_type, data.offset
                );
            }
            Ok(pdb::TypeData::Enumerate(data)) => {
                println!("  ENUMERATE: {} = {:?}", data.name, data.value);
            }
            Ok(pdb::TypeData::VirtualTableShape(data)) => {
                print!("  VTSHAPE: descriptors=[");
                for (i, desc) in data.descriptors.iter().enumerate() {
                    if i > 0 {
                        print!(", ");
                    }
                    print!("{:?}", desc);
                }
                println!("]");
            }
            Ok(pdb::TypeData::VirtualFunctionTable(data)) => {
                println!(
                    "  VFTABLE: owner={:?}, base={:?}, offset=0x{:X}",
                    data.owner_type, data.base_vftable, data.offset_in_object_layout
                );
                if !data.names.is_empty() {
                    println!("    Names:");
                    for (i, name) in data.names.iter().enumerate() {
                        println!("      [{}] {}", i, name);
                    }
                }
            }
            Ok(other) => {
                // Log unimplemented type kinds to stderr
                eprintln!(
                    "WARNING: Unimplemented type kind: {:?}",
                    std::mem::discriminant(&other)
                );
            }
            Err(e) => {
                eprintln!("ERROR parsing type {:?}: {}", ty.index(), e);
            }
        }
        count += 1;
    }
    println!("  Total types: {}", count);

    // Also dump ID information if available
    match pdb.id_information() {
        Ok(id_info) => {
            println!("\nID Information:");
            let mut ids = id_info.iter();
            let mut id_count = 0;

            while let Some(_id) = ids.next()? {
                id_count += 1;
            }
            println!("  Total IDs: {}", id_count);
        }
        Err(_) => {
            println!("\nNo ID information available");
        }
    }

    Ok(())
}

fn dump_modules(pdb: &mut PDB<'_, std::fs::File>) -> pdb::Result<()> {
    println!("\n=== Module Information ===");

    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    let mut count = 0;

    while let Some(module) = modules.next()? {
        println!("  Module {}:", count);
        println!("    Object file: {}", module.object_file_name());
        println!("    Module name: {}", module.module_name());

        // Get module info for additional details
        if let Some(info) = pdb.module_info(&module)? {
            // Check for line information
            match info.line_program() {
                Ok(_) => println!("    Has line information: yes"),
                Err(_) => println!("    Has line information: no"),
            }

            // Count symbols
            let mut sym_count = 0;
            let mut symbols = info.symbols()?;
            while symbols.next()?.is_some() {
                sym_count += 1;
            }
            println!("    Symbol count: {}", sym_count);
        }

        count += 1;
    }
    println!("  Total: {} modules", count);

    Ok(())
}

fn dump_source_files(pdb: &mut PDB<'_, std::fs::File>) -> pdb::Result<()> {
    println!("\n=== Source Files ===");

    let string_table = pdb.string_table()?;
    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    let mut total_files = 0;

    // Iterate through modules to find source files
    while let Some(module) = modules.next()? {
        if let Some(info) = pdb.module_info(&module)? {
            match info.line_program() {
                Ok(program) => {
                    let mut files = program.files();
                    let mut module_files = 0;

                    while let Some(file) = files.next()? {
                        let file_name = file.name.to_string_lossy(&string_table)?;
                        println!("  {}", file_name);
                        module_files += 1;
                        total_files += 1;
                    }

                    if module_files > 0 {
                        println!("    (from module: {})", module.module_name());
                    }
                }
                Err(_) => {
                    // Module has no line program
                }
            }
        }
    }

    println!("  Total source files: {}", total_files);

    Ok(())
}

fn dump_sections(pdb: &mut PDB<'_, std::fs::File>) -> pdb::Result<()> {
    println!("\n=== Section Headers ===");

    match pdb.sections() {
        Ok(Some(sections)) => {
            for (i, section) in sections.iter().enumerate() {
                println!(
                    "  Section {}: {}",
                    i + 1,
                    String::from_utf8_lossy(&section.name).trim_end_matches('\0')
                );
                println!("    Virtual Size: 0x{:08X}", section.virtual_size);
                println!("    Virtual Address: 0x{:08X}", section.virtual_address);
                println!("    Size of Raw Data: 0x{:08X}", section.size_of_raw_data);
                println!(
                    "    Pointer to Raw Data: 0x{:08X}",
                    section.pointer_to_raw_data
                );
                println!("    Characteristics: {:?}", section.characteristics);
            }
            println!("  Total sections: {}", sections.len());
        }
        Ok(None) => {
            println!("  No section information available");
        }
        Err(e) => {
            eprintln!("  Error reading sections: {}", e);
        }
    }

    Ok(())
}

fn dump_frame_data(pdb: &mut PDB<'_, std::fs::File>) -> pdb::Result<()> {
    println!("\n=== Frame Data ===");

    match pdb.frame_table() {
        Ok(frame_table) => {
            let mut frames = frame_table.iter();
            let mut count = 0;

            while let Some(frame) = frames.next()? {
                if count < 20 {
                    // Show first 20 frames
                    println!("  Frame @ {:?}:", frame.code_start);
                    println!("    Code size: 0x{:X}", frame.code_size);
                    println!("    Prolog size: {}", frame.prolog_size);
                    println!("    Saved regs size: {}", frame.saved_regs_size);
                    println!("    Type: {:?}", frame.ty);
                }
                count += 1;
            }

            if count > 20 {
                println!("  ... and {} more frames", count - 20);
            }
            println!("  Total frames: {}", count);
        }
        Err(e) => {
            println!("  No frame data available: {}", e);
        }
    }

    Ok(())
}

fn dump_omap(_pdb: &mut PDB<'_, std::fs::File>) -> pdb::Result<()> {
    println!("\n=== OMAP Information ===");

    // OMAP is not directly exposed in the current API
    println!("  OMAP information not directly available through public API");

    Ok(())
}

fn dump_string_table(pdb: &mut PDB<'_, std::fs::File>) -> pdb::Result<()> {
    println!("\n=== String Table ===");

    match pdb.string_table() {
        Ok(_string_table) => {
            // The string table doesn't provide direct iteration, but we can see it's used
            println!("  String table loaded successfully");
            println!("  (Strings are referenced throughout the PDB and shown inline)");
        }
        Err(e) => {
            println!("  Error loading string table: {}", e);
        }
    }

    Ok(())
}

fn dump_cross_module_refs(pdb: &mut PDB<'_, std::fs::File>) -> pdb::Result<()> {
    println!("\n=== Cross-Module References ===");

    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    let mut total_imports = 0;
    let mut total_exports = 0;

    // Look for cross-module references in symbols
    while let Some(module) = modules.next()? {
        if let Some(info) = pdb.module_info(&module)? {
            let mut symbols = info.symbols()?;
            let mut module_imports = 0;
            let mut module_exports = 0;

            while let Some(symbol) = symbols.next()? {
                match symbol.parse() {
                    Ok(pdb::SymbolData::ProcedureReference(ref data)) => {
                        if data.module.is_some() {
                            module_imports += 1;
                            if total_imports < 10 {
                                println!(
                                    "  Import: {} from module {:?}",
                                    data.name.as_ref().unwrap_or(&"<unnamed>".into()),
                                    data.module
                                );
                            }
                        }
                    }
                    Ok(pdb::SymbolData::DataReference(ref data)) => {
                        if data.module.is_some() {
                            module_imports += 1;
                        }
                    }
                    Ok(pdb::SymbolData::Export(ref data)) => {
                        module_exports += 1;
                        if total_exports < 10 {
                            println!(
                                "  Export: {} (ordinal: {}, flags: {:?})",
                                data.name, data.ordinal, data.flags
                            );
                        }
                    }
                    _ => {}
                }
            }

            if module_imports > 0 || module_exports > 0 {
                println!(
                    "  Module {}: {} imports, {} exports",
                    module.module_name(),
                    module_imports,
                    module_exports
                );
            }

            total_imports += module_imports;
            total_exports += module_exports;
        }
    }

    println!(
        "  Total cross-module references: {} imports, {} exports",
        total_imports, total_exports
    );

    Ok(())
}

fn dump_line_info(pdb: &mut PDB<'_, std::fs::File>) -> pdb::Result<()> {
    println!("\n=== Line Number Information ===");

    let address_map = pdb.address_map()?;
    let string_table = pdb.string_table()?;
    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    let mut total_lines = 0;
    let mut shown_lines = 0;

    while let Some(module) = modules.next()? {
        if let Some(info) = pdb.module_info(&module)? {
            // Get the line program for this module
            if let Ok(program) = info.line_program() {
                let mut symbols = info.symbols()?;

                // Find procedures in this module
                while let Some(symbol) = symbols.next()? {
                    if let Ok(pdb::SymbolData::Procedure(proc)) = symbol.parse() {
                        // Get line information for this procedure
                        let mut lines = program.lines_for_symbol(proc.offset);
                        let mut proc_lines = 0;

                        while let Some(line_info) = lines.next()? {
                            if shown_lines < 20 {
                                // Show first 20 lines
                                let rva = line_info.offset.to_rva(&address_map).unwrap_or_default();
                                let file_info = program.get_file_info(line_info.file_index)?;
                                let file_name = file_info.name.to_string_lossy(&string_table)?;

                                println!(
                                    "  {} @ RVA 0x{:08X} => {}:{}",
                                    proc.name, rva.0, file_name, line_info.line_start
                                );
                            }
                            proc_lines += 1;
                            shown_lines += 1;
                        }

                        if proc_lines > 0 {
                            total_lines += proc_lines;
                        }
                    }
                }
            }
        }
    }

    if total_lines > 20 {
        println!("  ... and {} more line mappings", total_lines - 20);
    }
    println!("  Total line number mappings: {}", total_lines);

    Ok(())
}

fn dump_statistics(pdb: &mut PDB<'_, std::fs::File>) -> pdb::Result<()> {
    println!("\n=== PDB Statistics Summary ===");

    // Collect statistics about the PDB
    let mut stats = std::collections::HashMap::new();

    // Count global symbols by type
    let symbol_table = pdb.global_symbols()?;
    let mut symbols = symbol_table.iter();
    while let Some(symbol) = symbols.next()? {
        match symbol.parse() {
            Ok(pdb::SymbolData::Public(_)) => *stats.entry("Public symbols").or_insert(0) += 1,
            Ok(pdb::SymbolData::Data(_)) => *stats.entry("Data symbols").or_insert(0) += 1,
            Ok(pdb::SymbolData::Procedure(_)) => {
                *stats.entry("Procedure symbols").or_insert(0) += 1
            }
            Ok(pdb::SymbolData::UserDefinedType(_)) => {
                *stats.entry("UDT symbols").or_insert(0) += 1
            }
            Ok(pdb::SymbolData::Constant(_)) => *stats.entry("Constant symbols").or_insert(0) += 1,
            Ok(pdb::SymbolData::ProcedureReference(_)) => {
                *stats.entry("Procedure references").or_insert(0) += 1
            }
            Ok(pdb::SymbolData::DataReference(_)) => {
                *stats.entry("Data references").or_insert(0) += 1
            }
            _ => {}
        }
    }

    // Count module symbols
    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    let mut module_count = 0;
    let mut total_module_symbols = 0;

    while let Some(module) = modules.next()? {
        module_count += 1;
        if let Some(info) = pdb.module_info(&module)? {
            let mut symbols = info.symbols()?;
            while let Some(_) = symbols.next()? {
                total_module_symbols += 1;
            }
        }
    }

    stats.insert("Modules", module_count);
    stats.insert("Module symbols", total_module_symbols);

    // Count types
    let type_info = pdb.type_information()?;
    let mut types = type_info.iter();
    let mut type_count = 0;
    let mut class_count = 0;
    let mut enum_count = 0;
    let mut union_count = 0;

    while let Some(ty) = types.next()? {
        type_count += 1;
        match ty.parse() {
            Ok(pdb::TypeData::Class(_)) => class_count += 1,
            Ok(pdb::TypeData::Enumeration(_)) => enum_count += 1,
            Ok(pdb::TypeData::Union(_)) => union_count += 1,
            _ => {}
        }
    }

    stats.insert("Total types", type_count);
    stats.insert("Classes", class_count);
    stats.insert("Enumerations", enum_count);
    stats.insert("Unions", union_count);

    // Count streams
    let mut stream_count = 0;
    let mut total_stream_size = 0;
    for i in 0..200 {
        match pdb.raw_stream(pdb::StreamIndex(i)) {
            Ok(Some(stream)) => {
                stream_count += 1;
                total_stream_size += stream.len();
            }
            Ok(None) => {}
            Err(_) => break,
        }
    }

    stats.insert("Streams", stream_count);
    stats.insert("Total stream bytes", total_stream_size);

    // Print statistics in sorted order
    let mut sorted_stats: Vec<_> = stats.iter().collect();
    sorted_stats.sort_by_key(|&(k, _)| k);

    for (key, value) in sorted_stats {
        println!("  {}: {}", key, value);
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.len() > 4 {
        eprintln!(
            "Usage: {} <input.pdb> [--va|--rva] [image_base_hex]",
            args[0]
        );
        eprintln!("  --va: Show Virtual Addresses (requires image base)");
        eprintln!("  --rva: Show Relative Virtual Addresses (default)");
        eprintln!("  image_base_hex: Image base address in hex (default: 0x140000000 for VA mode)");
        eprintln!("  Examples:");
        eprintln!("    {} sample.pdb", args[0]);
        eprintln!("    {} sample.pdb --rva", args[0]);
        eprintln!("    {} sample.pdb --va", args[0]);
        eprintln!("    {} sample.pdb --va 0x400000", args[0]);
        std::process::exit(1);
    }

    let filename = &args[1];
    let mut show_va = false;
    let mut image_base = 0x140000000u64; // Default for 64-bit Windows
    let mut arg_idx = 2;

    // Parse address format flag
    if args.len() > 2 {
        match args[2].as_str() {
            "--va" => {
                show_va = true;
                arg_idx = 3;
            }
            "--rva" => {
                show_va = false;
                arg_idx = 3;
            }
            _ => {
                // No flag specified, check if it's a hex number
                if args[2].starts_with("0x") || args[2].chars().all(|c| c.is_ascii_hexdigit()) {
                    // It's an image base, default to VA mode
                    show_va = true;
                    arg_idx = 2;
                } else {
                    eprintln!("Error: Unknown flag '{}'. Use --va or --rva", args[2]);
                    std::process::exit(1);
                }
            }
        }
    }

    // Parse image base if provided
    if args.len() > arg_idx {
        let hex_str = args[arg_idx].strip_prefix("0x").unwrap_or(&args[arg_idx]);
        match u64::from_str_radix(hex_str, 16) {
            Ok(base) => image_base = base,
            Err(_) => {
                eprintln!(
                    "Error: Invalid hex format for image base: {}",
                    args[arg_idx]
                );
                std::process::exit(1);
            }
        }
    }

    // For RVA mode, image base is not used but we keep it for consistency
    if !show_va {
        image_base = 0;
    }

    println!("Dumping PDB: {}", filename);

    let file = match std::fs::File::open(filename) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening file: {}", e);
            std::process::exit(1);
        }
    };

    let mut pdb = match PDB::open(file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error opening PDB: {}", e);
            std::process::exit(1);
        }
    };

    // Create the dump context
    let address_map = match pdb.address_map() {
        Ok(map) => map,
        Err(e) => {
            eprintln!("Error loading address map: {}", e);
            std::process::exit(1);
        }
    };
    let ctx = DumpContext::new(show_va, image_base, address_map);

    // Dump all the information
    if let Err(e) = dump_pdb_info(&mut pdb) {
        eprintln!("Error dumping PDB info: {}", e);
    }

    if let Err(e) = dump_streams(&mut pdb) {
        eprintln!("Error dumping streams: {}", e);
    }

    if let Err(e) = dump_symbols(&mut pdb, &ctx) {
        eprintln!("Error dumping symbols: {}", e);
    }

    if let Err(e) = dump_types(&mut pdb) {
        eprintln!("Error dumping types: {}", e);
    }

    if let Err(e) = dump_modules(&mut pdb) {
        eprintln!("Error dumping modules: {}", e);
    }

    if let Err(e) = dump_source_files(&mut pdb) {
        eprintln!("Error dumping source files: {}", e);
    }

    if let Err(e) = dump_sections(&mut pdb) {
        eprintln!("Error dumping sections: {}", e);
    }

    if let Err(e) = dump_frame_data(&mut pdb) {
        eprintln!("Error dumping frame data: {}", e);
    }

    if let Err(e) = dump_omap(&mut pdb) {
        eprintln!("Error dumping OMAP: {}", e);
    }

    if let Err(e) = dump_string_table(&mut pdb) {
        eprintln!("Error dumping string table: {}", e);
    }

    if let Err(e) = dump_cross_module_refs(&mut pdb) {
        eprintln!("Error dumping cross-module references: {}", e);
    }

    if let Err(e) = dump_line_info(&mut pdb) {
        eprintln!("Error dumping line information: {}", e);
    }

    // Dump statistics summary
    if let Err(e) = dump_statistics(&mut pdb) {
        eprintln!("Error dumping statistics: {}", e);
    }
}
