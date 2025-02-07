use std::{borrow::Cow, collections::HashMap};

use anyhow::{bail, Context as _};
use bytes::BufMut;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use winnow::{
    binary::{le_u16, le_u32},
    combinator::{alt, preceded},
    error::{ContextError, StrContext},
    prelude::*,
    token::take,
};

use crate::{
    parse::{Layout, Parse, Write},
    util::fmt::ByteStr,
};

use super::string_table::StringTable;

#[derive(Debug, Clone)]
pub struct SymbolTable {
    pub entries: Vec<SymbolTableEntry>,
}

#[derive(Debug)]
pub struct GlobalSymbolTable<'a> {
    // Map from symbol name to symbol definition
    symbols: HashMap<Cow<'a, str>, GlobalSymbol<'a>>,
}

#[derive(Debug)]
pub struct GlobalSymbol<'a> {
    // The actual symbol entry
    pub entry: &'a SymbolTableEntry,
    // The object file index this symbol came from
    pub object_idx: usize,
    // The resolved name
    pub name: Cow<'a, str>,
}

impl<'a> GlobalSymbolTable<'a> {
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
        }
    }

    pub fn add(
        &mut self,
        symbol_table: &'a SymbolTable,
        string_table: Option<&'a StringTable<'a>>,
        object_idx: usize,
    ) -> anyhow::Result<()> {
        // Process each symbol in the table
        for entry in &symbol_table.entries {
            // Resolve the symbol name
            let name = match &entry.name {
                Name::Short(bytes) => {
                    // Find null terminator or use whole slice
                    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());

                    String::from_utf8_lossy(&bytes[..len])
                }
                Name::Long(offset) => {
                    let string_table = string_table
                        .context("Symbol uses long name but no string table provided")?;
                    let name = string_table
                        .get(*offset)
                        .context("Invalid string table offset")?;
                    Cow::Borrowed(name)
                }
            };

            // Check for existing symbol
            if let Some(existing) = self.symbols.get(&name) {
                match (entry.storage_class, existing.entry.storage_class) {
                    // External symbol already defined
                    (StorageClass::External, StorageClass::External) => {
                        if existing.entry.section_number > 0 && entry.section_number > 0 {
                            bail!("Symbol {} already defined", name);
                        }
                        // Otherwise one is undefined (section 0) so this is ok
                    }

                    // Weak external - implement fallback logic
                    (StorageClass::WeakExternal, _) => {
                        // Keep existing symbol
                        continue;
                    }

                    (StorageClass::Static, StorageClass::Static)
                        if entry.value == 0 && existing.entry.value == 0 =>
                    {
                        // Static symbols w/ value 0 represent section names, ignore conflicts?
                        continue;
                    }

                    // Other combinations are errors
                    other => bail!("symbol {name} has conflicting storage classes: {other:?}"),
                }
            }

            // Add to global table
            self.symbols.insert(
                name.clone(),
                GlobalSymbol {
                    entry,
                    object_idx,
                    name,
                },
            );
        }

        Ok(())
    }

    // Get a symbol by name
    pub fn get(&self, name: &str) -> Option<&GlobalSymbol<'a>> {
        self.symbols.get(name)
    }

    // Get a symbol by index from its original symbol table
    pub fn get_by_index(&self, object_idx: usize, symbol_idx: usize) -> Option<&GlobalSymbol<'a>> {
        self.symbols
            .values()
            .find(|sym| sym.object_idx == object_idx && sym.entry.offset == symbol_idx)
    }
}

#[derive(Debug, Clone)]
pub struct SymbolTableEntry {
    /// Offset within the symbol table
    pub offset: usize,
    pub name: Name,
    pub value: u32,
    /// 1-based section index
    /// 0 = section undefined (external symbol)
    /// -1 = absolute non-relocatable symbol
    /// -2 = debug symbol
    pub section_number: i16,
    pub type_: u16,
    pub storage_class: StorageClass,
    pub number_of_aux_symbols: u8,
    pub aux_symbols: Vec<AuxSymbolRecord>,
}

#[derive(Clone, Copy)]
pub enum Name {
    Short([u8; 8]),
    Long(u32), // Offset into string table
}

impl std::fmt::Debug for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Short(inner) => f.debug_tuple("Short").field(&ByteStr(inner)).finish(),
            Self::Long(arg0) => f.debug_tuple("Long").field(arg0).finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum StorageClass {
    End = 0xff,
    Null = 0,
    Automatic = 1,
    External = 2,
    Static = 3,
    Register = 4,
    ExternalDef = 5,
    Label = 6,
    UndefinedLabel = 7,
    MemberOfStruct = 8,
    Argument = 9,
    StructTag = 10,
    MemberOfUnion = 11,
    UnionTag = 12,
    TypeDefinition = 13,
    UndefinedStatic = 14,
    EnumTag = 15,
    MemberOfEnum = 16,
    RegisterParam = 17,
    BitField = 18,
    Block = 100,
    Function = 101,
    EndOfStruct = 102,
    File = 103,
    Section = 104,
    WeakExternal = 105,
    CLRToken = 107,
}

#[derive(Debug, Clone, Copy)]
pub enum AuxSymbolRecord {
    Function {
        tag_index: u32,
        total_size: u32,
        pointer_to_line_number: u32,
        pointer_to_next_function: u32,
    },
    BeginEndFunction {
        line_number: u16,
        pointer_to_next_function: u32,
    },
    WeakExternal {
        tag_index: u32,
        characteristics: u32,
    },
    File {
        filename: [u8; 18],
    },
    Section {
        length: u32,
        number_of_relocations: u16,
        number_of_line_numbers: u16,
        checksum: u32,
        number: u16,
        selection: u8,
    },
    Raw([u8; 18]), // For unhandled auxiliary records
}

impl Layout for SymbolTableEntry {
    fn fix_layout(&mut self) -> u32 {
        self.number_of_aux_symbols = self.aux_symbols.len() as u8;
        self.total_size()
    }

    fn total_size(&self) -> u32 {
        18 + (self.aux_symbols.len() as u32 * 18) // Each symbol is 18 bytes
    }
}

impl Layout for SymbolTable {
    fn fix_layout(&mut self) -> u32 {
        // Fix layout of all entries
        let mut total = 0;
        for entry in &mut self.entries {
            total += entry.fix_layout();
        }
        total
    }

    fn total_size(&self) -> u32 {
        self.entries.iter().map(|e| e.total_size()).sum()
    }
}

impl Write for AuxSymbolRecord {
    type Error = std::io::Error;

    fn write(&self, mut out: &mut [u8]) -> Result<(), Self::Error> {
        match self {
            Self::Function {
                tag_index,
                total_size,
                pointer_to_line_number,
                pointer_to_next_function,
            } => {
                out.put_u32_le(*tag_index);
                out.put_u32_le(*total_size);
                out.put_u32_le(*pointer_to_line_number);
                out.put_u32_le(*pointer_to_next_function);
                out.put_bytes(0, 2); // Unused
            }
            Self::BeginEndFunction {
                line_number,
                pointer_to_next_function,
            } => {
                out.put_u16_le(*line_number);
                out.put_u32_le(*pointer_to_next_function);
                out.put_bytes(0, 12); // Unused
            }
            Self::WeakExternal {
                tag_index,
                characteristics,
            } => {
                out.put_u32_le(*tag_index);
                out.put_u32_le(*characteristics);
                out.put_bytes(0, 10); // Unused
            }
            Self::File { filename } => {
                out.put_slice(filename);
            }
            Self::Section {
                length,
                number_of_relocations,
                number_of_line_numbers,
                checksum,
                number,
                selection,
            } => {
                out.put_u32_le(*length);
                out.put_u16_le(*number_of_relocations);
                out.put_u16_le(*number_of_line_numbers);
                out.put_u32_le(*checksum);
                out.put_u16_le(*number);
                out.put_u8(*selection);
                out.put_bytes(0, 3); // Unused
            }
            Self::Raw(raw) => {
                out.put_slice(raw);
            }
        }
        Ok(())
    }
}

impl Write for SymbolTableEntry {
    type Error = std::io::Error;

    fn write(&self, mut out: &mut [u8]) -> Result<(), Self::Error> {
        // Write name
        match self.name {
            Name::Short(bytes) => {
                out.put_slice(&bytes);
            }
            Name::Long(offset) => {
                out.put_u32_le(0); // First 4 bytes zero
                out.put_u32_le(offset); // Offset into string table
            }
        }

        out.put_u32_le(self.value);
        out.put_i16_le(self.section_number);
        out.put_u16_le(self.type_);
        out.put_u8(self.storage_class as u8);
        out.put_u8(self.number_of_aux_symbols);

        // Write auxiliary symbols
        for aux in &self.aux_symbols {
            aux.write(out)?;
        }

        Ok(())
    }
}

impl Write for SymbolTable {
    type Error = std::io::Error;

    fn write(&self, mut out: &mut [u8]) -> Result<(), Self::Error> {
        for entry in &self.entries {
            let n = entry.total_size() as usize;
            entry.write(&mut out[..n])?;
            out = &mut out[n..];
        }

        Ok(())
    }
}

impl<'a> Parse<'a> for SymbolTableEntry {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        // Parse name - first 8 bytes
        let name = alt((
            preceded(b"\0\0\0\0", le_u32).map(Name::Long),
            take(8usize).map(|s: &[u8]| Name::Short(s.try_into().unwrap())),
        ))
        .context(StrContext::Label("name"))
        .parse_next(input)?;

        let value = le_u32.parse_next(input)?;
        let section_number = le_u16.parse_next(input)? as i16;
        let type_ = le_u16.parse_next(input)?;
        let storage_class = input.next_token().unwrap();
        let storage_class = StorageClass::from_u8(storage_class).unwrap_or(StorageClass::Null);
        let number_of_aux_symbols = input.next_token().unwrap();

        // let aux_symbols = repeat(number_of_aux_symbols as usize, parser)

        // Parse auxiliary symbol records
        let mut aux_symbols = Vec::with_capacity(number_of_aux_symbols as usize);
        for _ in 0..number_of_aux_symbols {
            let aux_record = AuxSymbolRecord::parse_with_class(storage_class, input)?;
            aux_symbols.push(aux_record);
        }

        let entry = SymbolTableEntry {
            // offset is not known here
            offset: 0,
            name,
            value,
            section_number,
            type_,
            storage_class,
            number_of_aux_symbols,
            aux_symbols,
        };

        Ok(entry)
    }
}

impl AuxSymbolRecord {
    fn parse_with_class<'a>(
        storage_class: StorageClass,
        input: &mut &'a [u8],
    ) -> Result<Self, ContextError> {
        match storage_class {
            StorageClass::Function => {
                let tag_index = le_u32
                    .context(StrContext::Label("tag index"))
                    .parse_next(input)?;
                let total_size = le_u32
                    .context(StrContext::Label("total size"))
                    .parse_next(input)?;
                let pointer_to_line_number = le_u32
                    .context(StrContext::Label("line number pointer"))
                    .parse_next(input)?;
                let pointer_to_next_function = le_u32
                    .context(StrContext::Label("next function pointer"))
                    .parse_next(input)?;
                take(2usize)
                    .context(StrContext::Label("unused"))
                    .parse_next(input)?;
                Ok(AuxSymbolRecord::Function {
                    tag_index,
                    total_size,
                    pointer_to_line_number,
                    pointer_to_next_function,
                })
            }
            StorageClass::Block => {
                let line_number = le_u16
                    .context(StrContext::Label("line number"))
                    .parse_next(input)?;
                let pointer_to_next_function = le_u32
                    .context(StrContext::Label("next function pointer"))
                    .parse_next(input)?;
                take(12usize)
                    .context(StrContext::Label("unused"))
                    .parse_next(input)?;
                Ok(AuxSymbolRecord::BeginEndFunction {
                    line_number,
                    pointer_to_next_function,
                })
            }
            StorageClass::WeakExternal => {
                let tag_index = le_u32
                    .context(StrContext::Label("tag index"))
                    .parse_next(input)?;
                let characteristics = le_u32
                    .context(StrContext::Label("characteristics"))
                    .parse_next(input)?;
                take(10usize)
                    .context(StrContext::Label("unused"))
                    .parse_next(input)?;
                Ok(AuxSymbolRecord::WeakExternal {
                    tag_index,
                    characteristics,
                })
            }
            StorageClass::File => {
                let filename = take(18usize)
                    .context(StrContext::Label("filename"))
                    .parse_next(input)?;
                Ok(AuxSymbolRecord::File {
                    filename: filename.try_into().unwrap(),
                })
            }
            StorageClass::Section => {
                let length = le_u32
                    .context(StrContext::Label("length"))
                    .parse_next(input)?;
                let number_of_relocations = le_u16
                    .context(StrContext::Label("relocations"))
                    .parse_next(input)?;
                let number_of_line_numbers = le_u16
                    .context(StrContext::Label("line numbers"))
                    .parse_next(input)?;
                let checksum = le_u32
                    .context(StrContext::Label("checksum"))
                    .parse_next(input)?;
                let number = le_u16
                    .context(StrContext::Label("number"))
                    .parse_next(input)?;
                let selection = input.next_token().unwrap();
                take(3usize)
                    .context(StrContext::Label("unused"))
                    .parse_next(input)?;
                Ok(AuxSymbolRecord::Section {
                    length,
                    number_of_relocations,
                    number_of_line_numbers,
                    checksum,
                    number,
                    selection,
                })
            }
            _ => {
                // Save raw bytes for unhandled aux record types
                let raw = take(18usize)
                    .context(StrContext::Label("raw aux record"))
                    .parse_next(input)?;
                Ok(AuxSymbolRecord::Raw(raw.try_into().unwrap()))
            }
        }
    }
}
