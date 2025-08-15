use std::collections::BTreeSet;
use std::io::Write;

use pdb::{FallibleIterator, PrimitiveKind, PrimitiveType};

type TypeSet = BTreeSet<pdb::TypeIndex>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Rust,
    Cpp,
}

impl Language {
    fn from_str(s: &str) -> Option<Language> {
        match s.to_lowercase().as_str() {
            "rust" | "rs" => Some(Language::Rust),
            "cpp" | "c++" | "hpp" => Some(Language::Cpp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub language: Language,
    pub skip_dependencies: bool,
}

impl Config {
    pub fn new(language: Language) -> Self {
        Self {
            language,
            skip_dependencies: false,
        }
    }

    pub fn with_skip_dependencies(mut self, skip_dependencies: bool) -> Self {
        self.skip_dependencies = skip_dependencies;
        self
    }
}

pub fn type_name<'p>(
    config: &Config,
    type_finder: &pdb::TypeFinder<'p>,
    type_index: pdb::TypeIndex,
    needed_types: &mut TypeSet,
) -> pdb::Result<String> {
    let mut name = match type_finder.find(type_index)?.parse()? {
        pdb::TypeData::Primitive(data) => match config.language {
            Language::Rust => {
                let mut name = String::from(if data.indirection.is_some() {
                    "*const "
                } else {
                    ""
                });

                name.push_str(&match data.kind {
                    pdb::PrimitiveKind::Void => "void".to_string(),
                    pdb::PrimitiveKind::Char => "char".to_string(),
                    pdb::PrimitiveKind::RChar => "char".to_string(),
                    pdb::PrimitiveKind::UChar => "unsigned char".to_string(),
                    pdb::PrimitiveKind::WChar => "wchar_t".to_string(),

                    pdb::PrimitiveKind::I8 => "i8".to_string(),
                    pdb::PrimitiveKind::U8 => "u8".to_string(),
                    pdb::PrimitiveKind::I16 => "i16".to_string(),
                    pdb::PrimitiveKind::U16 => "u16".to_string(),
                    pdb::PrimitiveKind::I32 => "i32".to_string(),
                    pdb::PrimitiveKind::U32 => "u32".to_string(),
                    pdb::PrimitiveKind::I64 => "i64".to_string(),
                    pdb::PrimitiveKind::U64 => "u64".to_string(),

                    pdb::PrimitiveKind::F32 => "f32".to_string(),
                    pdb::PrimitiveKind::F64 => "f64".to_string(),

                    pdb::PrimitiveKind::UShort => "u16".to_string(),
                    pdb::PrimitiveKind::UQuad => "u64".to_string(),

                    pdb::PrimitiveKind::Bool8 => "bool".to_string(),

                    _ => format!("unhandled_primitive.kind /* {:?} */", data.kind),
                });

                name
            }
            Language::Cpp => {
                let mut name = match data.kind {
                    pdb::PrimitiveKind::Void => "void".to_string(),
                    pdb::PrimitiveKind::Char => "char".to_string(),
                    pdb::PrimitiveKind::RChar => "char".to_string(),
                    pdb::PrimitiveKind::UChar => "unsigned char".to_string(),
                    pdb::PrimitiveKind::WChar => "wchar_t".to_string(),

                    pdb::PrimitiveKind::I8 => "int8_t".to_string(),
                    pdb::PrimitiveKind::U8 => "uint8_t".to_string(),
                    pdb::PrimitiveKind::I16 => "int16_t".to_string(),
                    pdb::PrimitiveKind::U16 => "uint16_t".to_string(),
                    pdb::PrimitiveKind::I32 => "int32_t".to_string(),
                    pdb::PrimitiveKind::U32 => "uint32_t".to_string(),
                    pdb::PrimitiveKind::I64 => "int64_t".to_string(),
                    pdb::PrimitiveKind::U64 => "uint64_t".to_string(),

                    pdb::PrimitiveKind::F32 => "float".to_string(),
                    pdb::PrimitiveKind::F64 => "double".to_string(),

                    pdb::PrimitiveKind::UShort => "uint16_t".to_string(),
                    pdb::PrimitiveKind::UQuad => "uint64_t".to_string(),

                    pdb::PrimitiveKind::Bool8 => "bool".to_string(),

                    _ => format!("unhandled_primitive.kind /* {:?} */", data.kind),
                };

                if data.indirection.is_some() {
                    name.push_str(" *");
                }

                name
            }
        },

        pdb::TypeData::Class(data) => {
            if !config.skip_dependencies {
                needed_types.insert(type_index);
            }
            data.name.to_string().into_owned()
        }

        pdb::TypeData::Enumeration(data) => {
            if !config.skip_dependencies {
                needed_types.insert(type_index);
            }
            data.name.to_string().into_owned()
        }

        pdb::TypeData::Union(data) => {
            if !config.skip_dependencies {
                needed_types.insert(type_index);
            }
            data.name.to_string().into_owned()
        }

        pdb::TypeData::Pointer(data) => {
            let is_func = matches!(
                type_finder.find(data.underlying_type)?.parse()?,
                pdb::TypeData::Procedure(_)
            );
            match config.language {
                Language::Rust => {
                    let prefix = if is_func { "" } else { "*const " };
                    format!(
                        "{}{}",
                        prefix,
                        type_name(config, type_finder, data.underlying_type, needed_types)?
                    )
                }
                Language::Cpp => {
                    let suffix = if is_func { "" } else { "*" };
                    format!(
                        "{}{}",
                        type_name(config, type_finder, data.underlying_type, needed_types)?,
                        suffix
                    )
                }
            }
        }

        pdb::TypeData::Modifier(data) => {
            if data.constant {
                match config.language {
                    Language::Rust => format!(
                        "[const] {}",
                        type_name(config, type_finder, data.underlying_type, needed_types)?
                    ),
                    Language::Cpp => format!(
                        "const {}",
                        type_name(config, type_finder, data.underlying_type, needed_types)?
                    ),
                }
            } else if data.volatile {
                match config.language {
                    Language::Rust => format!(
                        "[volatile] {}",
                        type_name(config, type_finder, data.underlying_type, needed_types)?
                    ),
                    Language::Cpp => format!(
                        "volatile {}",
                        type_name(config, type_finder, data.underlying_type, needed_types)?
                    ),
                }
            } else {
                type_name(config, type_finder, data.underlying_type, needed_types)?
            }
        }

        pdb::TypeData::Array(data) => {
            let mut name = type_name(config, type_finder, data.element_type, needed_types)?;
            for size in data.dimensions {
                name = format!("{}[{}]", name, size);
            }
            name
        }

        pdb::TypeData::Procedure(data) => {
            let return_type = if let Some(ret) = data.return_type {
                let ret_str = type_name(config, type_finder, ret, needed_types)?;
                if ret_str == "void" {
                    None
                } else {
                    Some(ret_str)
                }
            } else {
                None
            };
            let arguments = type_name(config, type_finder, data.argument_list, needed_types)?;

            match config.language {
                Language::Rust => format!(
                    "extern \"system\" fn({}){}",
                    arguments,
                    return_type
                        .map(|r| format!(" -> {}", r))
                        .unwrap_or_default()
                ),
                Language::Cpp => format!(
                    "{}({})",
                    return_type
                        .map(|r| format!("{}(*)", r))
                        .unwrap_or_else(|| "void(*)".to_string()),
                    arguments
                ),
            }
        }

        pdb::TypeData::ArgumentList(data) => {
            let mut buf = String::new();
            let mut iter = data.arguments.iter().peekable();
            let mut cur = iter.next();
            while let Some(arg) = cur {
                buf.push_str(&type_name(config, type_finder, *arg, needed_types)?);
                cur = iter.next();
                if cur.is_some() {
                    buf.push_str(", ");
                }
            }
            buf
        }

        _ => format!("Type{} /* TODO: figure out how to name it */", type_index),
    };

    // TODO: search and replace std:: patterns
    if name == "std::basic_string<char,std::char_traits<char>,std::allocator<char> >" {
        name = "std::string".to_string();
    }

    Ok(name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Class<'p> {
    kind: pdb::ClassKind,
    name: pdb::RawString<'p>,
    base_classes: Vec<BaseClass>,
    fields: Vec<Field<'p>>,
    instance_methods: Vec<Method<'p>>,
    static_methods: Vec<Method<'p>>,
}

impl<'p> Class<'p> {
    #[allow(clippy::unnecessary_wraps)]
    fn add_derived_from(
        &mut self,
        _: &Config,
        _: &pdb::TypeFinder<'p>,
        _: pdb::TypeIndex,
        _: &mut TypeSet,
    ) -> pdb::Result<()> {
        // TODO
        Ok(())
    }

    fn add_fields(
        &mut self,
        config: &Config,
        type_finder: &pdb::TypeFinder<'p>,
        type_index: pdb::TypeIndex,
        needed_types: &mut TypeSet,
    ) -> pdb::Result<()> {
        match type_finder.find(type_index)?.parse()? {
            pdb::TypeData::FieldList(data) => {
                for field in &data.fields {
                    self.add_field(config, type_finder, field, needed_types)?;
                }

                if let Some(continuation) = data.continuation {
                    // recurse
                    self.add_fields(config, type_finder, continuation, needed_types)?;
                }
            }
            other => {
                println!(
                    "trying to Class::add_fields() got {} -> {:?}",
                    type_index, other
                );
                panic!("unexpected type in Class::add_fields()");
            }
        }

        Ok(())
    }

    fn add_field(
        &mut self,
        config: &Config,
        type_finder: &pdb::TypeFinder<'p>,
        field: &pdb::TypeData<'p>,
        needed_types: &mut TypeSet,
    ) -> pdb::Result<()> {
        match *field {
            pdb::TypeData::Member(ref data) => {
                // TODO: attributes (static, virtual, etc.)
                self.fields.push(Field {
                    type_name: type_name(config, type_finder, data.field_type, needed_types)?,
                    name: data.name,
                    offset: data.offset,
                });
            }

            pdb::TypeData::Method(ref data) => {
                let method = Method::find(
                    config,
                    data.name,
                    data.attributes,
                    type_finder,
                    data.method_type,
                    needed_types,
                    data.vtable_offset,
                )?;
                if data.attributes.is_static() {
                    self.static_methods.push(method);
                } else {
                    self.instance_methods.push(method);
                }
            }

            pdb::TypeData::OverloadedMethod(ref data) => {
                // this just means we have more than one method with the same name
                // find the method list
                match type_finder.find(data.method_list)?.parse()? {
                    pdb::TypeData::MethodList(method_list) => {
                        for pdb::MethodListEntry {
                            attributes,
                            method_type,
                            vtable_offset,
                            ..
                        } in method_list.methods
                        {
                            // hooray
                            let method = Method::find(
                                config,
                                data.name,
                                attributes,
                                type_finder,
                                method_type,
                                needed_types,
                                vtable_offset,
                            )?;

                            if attributes.is_static() {
                                self.static_methods.push(method);
                            } else {
                                self.instance_methods.push(method);
                            }
                        }
                    }
                    other => {
                        println!(
                            "processing OverloadedMethod, expected MethodList, got {} -> {:?}",
                            data.method_list, other
                        );
                        panic!("unexpected type in Class::add_field()");
                    }
                }
            }

            pdb::TypeData::BaseClass(ref data) => self.base_classes.push(BaseClass {
                type_name: type_name(config, type_finder, data.base_class, needed_types)?,
                offset: data.offset,
            }),

            pdb::TypeData::VirtualBaseClass(ref data) => self.base_classes.push(BaseClass {
                type_name: type_name(config, type_finder, data.base_class, needed_types)?,
                offset: data.base_pointer_offset,
            }),

            _ => {
                // ignore everything else even though that's sad
            }
        }

        Ok(())
    }
}

impl<'p> Class<'p> {
    fn write_with_config(&self, w: &mut dyn Write, config: &Config) -> std::io::Result<()> {
        let class_keyword = match config.language {
            Language::Rust => match self.kind {
                pdb::ClassKind::Class => "struct",
                pdb::ClassKind::Struct => "struct",
                pdb::ClassKind::Interface => "interface",
            },
            Language::Cpp => match self.kind {
                pdb::ClassKind::Class => "class",
                pdb::ClassKind::Struct => "struct",
                pdb::ClassKind::Interface => "interface",
            },
        };

        write!(w, "{} {} ", class_keyword, self.name.to_string())?;

        if !self.base_classes.is_empty() {
            for (i, base) in self.base_classes.iter().enumerate() {
                let prefix = match i {
                    0 => ":",
                    _ => ",",
                };
                write!(w, "{} {}", prefix, base.type_name)?;
            }
        }

        writeln!(w, " {{")?;

        for base in &self.base_classes {
            writeln!(
                w,
                "\t/* offset 0x{:03x} */ /* fields for {} */",
                base.offset, base.type_name
            )?;
        }

        for field in &self.fields {
            match config.language {
                Language::Rust => writeln!(
                    w,
                    "\t/* offset 0x{:03x} */ {}: {},",
                    field.offset,
                    field.name.to_string(),
                    field.type_name,
                )?,
                Language::Cpp => writeln!(
                    w,
                    "\t/* offset 0x{:03x} */ {} {};",
                    field.offset,
                    field.type_name,
                    field.name.to_string()
                )?,
            }
        }

        if !self.instance_methods.is_empty() {
            writeln!(w, "\t")?;
            for method in &self.instance_methods {
                writeln!(
                    w,
                    "\t{}{}{} {}({});",
                    if let Some(offset) = method.vtable_offset {
                        format!("/* @0x{offset:x} */ ")
                    } else {
                        " ".into()
                    },
                    if method.is_virtual { "virtual " } else { "" },
                    method.return_type_name,
                    method.name.to_string(),
                    method.arguments.join(", ")
                )?;
            }
        }

        if !self.static_methods.is_empty() {
            writeln!(w, "\t")?;
            for method in &self.static_methods {
                writeln!(
                    w,
                    "\t{}static {} {}({});",
                    if method.is_virtual { "virtual " } else { "" },
                    method.return_type_name,
                    method.name.to_string(),
                    method.arguments.join(", ")
                )?;
            }
        }

        writeln!(w, "}}")?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BaseClass {
    type_name: String,
    offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Field<'p> {
    type_name: String,
    name: pdb::RawString<'p>,
    offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Method<'p> {
    name: pdb::RawString<'p>,
    return_type_name: String,
    arguments: Vec<String>,
    is_virtual: bool,
    vtable_offset: Option<u32>,
}

impl<'p> Method<'p> {
    fn find(
        config: &Config,
        name: pdb::RawString<'p>,
        attributes: pdb::FieldAttributes,
        type_finder: &pdb::TypeFinder<'p>,
        type_index: pdb::TypeIndex,
        needed_types: &mut TypeSet,
        vtable_offset: Option<u32>,
    ) -> pdb::Result<Method<'p>> {
        match type_finder.find(type_index)?.parse()? {
            pdb::TypeData::MemberFunction(data) => Ok(Method {
                name,
                return_type_name: type_name(config, type_finder, data.return_type, needed_types)?,
                arguments: argument_list(config, type_finder, data.argument_list, needed_types)?,
                is_virtual: attributes.is_virtual(),
                vtable_offset,
            }),

            other => {
                println!("other: {:?}", other);
                Err(pdb::Error::UnimplementedFeature("that"))
            }
        }
    }
}

fn argument_list<'p>(
    config: &Config,
    type_finder: &pdb::TypeFinder<'p>,
    type_index: pdb::TypeIndex,
    needed_types: &mut TypeSet,
) -> pdb::Result<Vec<String>> {
    match type_finder.find(type_index)?.parse()? {
        pdb::TypeData::ArgumentList(data) => {
            let mut args: Vec<String> = Vec::new();
            for arg_type in data.arguments {
                args.push(type_name(config, type_finder, arg_type, needed_types)?);
            }
            Ok(args)
        }
        _ => Err(pdb::Error::UnimplementedFeature(
            "argument list of non-argument-list type",
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Enum<'p> {
    name: pdb::RawString<'p>,
    underlying_type_name: String,
    values: Vec<EnumValue<'p>>,
}

impl<'p> Enum<'p> {
    fn add_fields(
        &mut self,
        config: &Config,
        type_finder: &pdb::TypeFinder<'p>,
        type_index: pdb::TypeIndex,
        needed_types: &mut TypeSet,
    ) -> pdb::Result<()> {
        match type_finder.find(type_index)?.parse()? {
            pdb::TypeData::FieldList(data) => {
                for field in &data.fields {
                    self.add_field(config, type_finder, field, needed_types);
                }

                if let Some(continuation) = data.continuation {
                    // recurse
                    self.add_fields(config, type_finder, continuation, needed_types)?;
                }
            }
            pdb::TypeData::Primitive(PrimitiveType {
                kind: PrimitiveKind::NoType,
                indirection: None,
            }) => {}
            other => {
                println!(
                    "trying to Enum::add_fields() got {} -> {:?}",
                    type_index, other
                );
                panic!("unexpected type in Enum::add_fields()");
            }
        }

        Ok(())
    }

    fn add_field(
        &mut self,
        _: &Config,
        _: &pdb::TypeFinder<'p>,
        field: &pdb::TypeData<'p>,
        _: &mut TypeSet,
    ) {
        // ignore everything else even though that's sad
        if let pdb::TypeData::Enumerate(ref data) = field {
            self.values.push(EnumValue {
                name: data.name,
                value: data.value,
            });
        }
    }
}

impl<'p> Enum<'p> {
    fn write_with_config(&self, w: &mut dyn Write, _config: &Config) -> std::io::Result<()> {
        writeln!(
            w,
            "enum {} /* stored as {} */ {{",
            self.name.to_string(),
            self.underlying_type_name
        )?;

        for value in &self.values {
            writeln!(
                w,
                "\t{} = {},",
                value.name.to_string(),
                match value.value {
                    pdb::Variant::U8(v) => format!("0x{:02x}", v),
                    pdb::Variant::U16(v) => format!("0x{:04x}", v),
                    pdb::Variant::U32(v) => format!("0x{:08x}", v),
                    pdb::Variant::U64(v) => format!("0x{:016x}", v),
                    pdb::Variant::I8(v) => format!("{}", v),
                    pdb::Variant::I16(v) => format!("{}", v),
                    pdb::Variant::I32(v) => format!("{}", v),
                    pdb::Variant::I64(v) => format!("{}", v),
                }
            )?;
        }
        writeln!(w, "}}")?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnumValue<'p> {
    name: pdb::RawString<'p>,
    value: pdb::Variant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardReference<'p> {
    kind: pdb::ClassKind,
    name: pdb::RawString<'p>,
}

impl<'p> ForwardReference<'p> {
    fn write_with_config(&self, w: &mut dyn Write, config: &Config) -> std::io::Result<()> {
        let class_keyword = match config.language {
            Language::Rust => match self.kind {
                pdb::ClassKind::Class => "struct",
                pdb::ClassKind::Struct => "struct",
                pdb::ClassKind::Interface => "interface", // when can this happen?
            },
            Language::Cpp => match self.kind {
                pdb::ClassKind::Class => "class",
                pdb::ClassKind::Struct => "struct",
                pdb::ClassKind::Interface => "interface", // when can this happen?
            },
        };

        writeln!(w, "{} {};", class_keyword, self.name.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Data<'p> {
    forward_references: Vec<ForwardReference<'p>>,
    classes: Vec<Class<'p>>,
    enums: Vec<Enum<'p>>,
}

impl<'p> Data<'p> {
    fn write_with_config(&self, w: &mut dyn Write, config: &Config) -> std::io::Result<()> {
        writeln!(w, "// automatically generated by pdb2src\n// do not edit")?;

        if !self.forward_references.is_empty() {
            writeln!(w)?;
            for e in &self.forward_references {
                e.write_with_config(w, config)?;
            }
        }

        for e in &self.enums {
            writeln!(w)?;
            e.write_with_config(w, config)?;
        }

        for class in &self.classes {
            writeln!(w)?;
            class.write_with_config(w, config)?;
        }

        Ok(())
    }
}

impl<'p> Data<'p> {
    fn new() -> Data<'p> {
        Data {
            forward_references: Vec::new(),
            classes: Vec::new(),
            enums: Vec::new(),
        }
    }

    fn add(
        &mut self,
        config: &Config,
        type_finder: &pdb::TypeFinder<'p>,
        type_index: pdb::TypeIndex,
        needed_types: &mut TypeSet,
    ) -> pdb::Result<()> {
        match type_finder.find(type_index)?.parse()? {
            pdb::TypeData::Class(data) => {
                if data.properties.forward_reference() {
                    self.forward_references.push(ForwardReference {
                        kind: data.kind,
                        name: data.name,
                    });

                    return Ok(());
                }

                let mut class = Class {
                    kind: data.kind,
                    name: data.name,
                    fields: Vec::new(),
                    base_classes: Vec::new(),
                    instance_methods: Vec::new(),
                    static_methods: Vec::new(),
                };

                if let Some(derived_from) = data.derived_from {
                    class.add_derived_from(config, type_finder, derived_from, needed_types)?;
                }

                if let Some(fields) = data.fields {
                    class.add_fields(config, type_finder, fields, needed_types)?;
                }

                self.classes.insert(0, class);
            }

            pdb::TypeData::Enumeration(data) => {
                let mut e = Enum {
                    name: data.name,
                    underlying_type_name: type_name(
                        config,
                        type_finder,
                        data.underlying_type,
                        needed_types,
                    )?,
                    values: Vec::new(),
                };

                e.add_fields(config, type_finder, data.fields, needed_types)?;

                self.enums.insert(0, e);
            }

            // ignore
            other => eprintln!("warning: don't know how to add {:?}", other),
        }

        Ok(())
    }
}

fn write_class(config: &Config, filename: &str, class_name: &str) -> pdb::Result<()> {
    let file = std::fs::File::open(filename)?;
    let mut pdb = pdb::PDB::open(file)?;

    let type_information = pdb.type_information()?;
    let mut type_finder = type_information.finder();

    let mut needed_types = TypeSet::new();
    let mut data = Data::new();

    let mut type_iter = type_information.iter();
    while let Some(typ) = type_iter.next()? {
        // keep building the index
        type_finder.update(&type_iter);

        if let Ok(pdb::TypeData::Class(class)) = typ.parse() {
            if class.name.as_bytes() == class_name.as_bytes()
                && !class.properties.forward_reference()
            {
                data.add(config, &type_finder, typ.index(), &mut needed_types)?;
                break;
            }
        }
    }

    // add all the needed types iteratively until we're done (unless skipping dependencies)
    if !config.skip_dependencies {
        while let Some(type_index) = needed_types.iter().next_back().copied() {
            // remove it
            needed_types.remove(&type_index);

            // add the type
            data.add(config, &type_finder, type_index, &mut needed_types)?;
        }
    }

    if data.classes.is_empty() {
        eprintln!("sorry, class {} was not found", class_name);
    } else {
        data.write_with_config(&mut std::io::stdout(), config)?;
    }

    Ok(())
}

fn print_usage(program: &str, opts: getopts::Options) {
    let brief = format!(
        "Usage: {} [options] <language> input.pdb ClassName",
        program
    );
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let program = args[0].clone();

    let mut opts = getopts::Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optflag(
        "",
        "no-deps",
        "skip dependency types, only output the main requested type",
    );

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!("{}", f.to_string()),
    };

    let (language_str, filename, class_name) = if matches.free.len() == 3 {
        (&matches.free[0], &matches.free[1], &matches.free[2])
    } else {
        print_usage(&program, opts);
        return;
    };

    let language = match Language::from_str(language_str) {
        Some(lang) => lang,
        None => {
            eprintln!(
                "error: unsupported language '{}'. Supported languages: rust, cpp",
                language_str
            );
            return;
        }
    };

    let config = Config::new(language).with_skip_dependencies(matches.opt_present("no-deps"));

    match write_class(&config, filename, class_name) {
        Ok(_) => (),
        Err(e) => eprintln!("error dumping PDB: {}", e),
    }
}
