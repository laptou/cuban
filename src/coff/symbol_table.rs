use std::{borrow::Cow, collections::HashMap};

use anyhow::{bail, Context as _};
use bytes::BufMut;
use derive_more::From;
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

use super::{string_table::StringTable, ObjectIdx, SymbolIdx};

#[derive(Debug, Clone)]
pub struct SymbolTable {
    pub entries: Vec<SymbolTableEntry>,
}

#[derive(Debug, Clone)]
pub struct SymbolTableEntry {
    /// Offset within the symbol table
    pub offset: SymbolIdx,
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

impl SymbolTableEntry {
    /// Returns the auxiliary symbol record for the section definition if this
    /// symbol refers to a section.
    pub fn section_info(&self) -> Option<&AuxSymbolRecordSection> {
        match self.storage_class {
            StorageClass::Static | StorageClass::Section => {
                self.aux_symbols.iter().find_map(|a| match a {
                    AuxSymbolRecord::Section(sect) => Some(sect),
                    _ => None,
                })
            }
            _ => None,
        }
    }
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

impl Name {
    pub fn as_str<'a, 'b: 'a>(&'b self, string_table: Option<&StringTable<'a>>) -> Option<&'a str> {
        match self {
            Name::Short(bytes) => {
                // Find null terminator or use whole slice
                let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                std::str::from_utf8(&bytes[..len]).ok()
            }
            Name::Long(offset) => string_table?.get(*offset),
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

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum WeakExternalCharacteristics {
    NoLibrarySearch = 1,
    LibrarySearch = 2,
    Alias = 3,
}

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive, PartialEq, Eq)]
#[repr(u8)]
pub enum ComdatSelection {
    NoDuplicates = 1,
    Any = 2,
    SameSize = 3,
    ExactMatch = 4,
    Associative = 5,
    Largest = 6,
}

#[derive(Debug, Clone, Copy)]
pub struct AuxSymbolRecordSection {
    pub length: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub checksum: u32,
    pub number: u16,
    pub selection: ComdatSelection,
}

#[derive(Debug, Clone, Copy)]
pub struct AuxSymbolRecordFunction {
    pub tag_index: u32,
    pub total_size: u32,
    pub pointer_to_line_number: u32,
    pub pointer_to_next_function: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct AuxSymbolRecordBeginEndFunction {
    pub line_number: u16,
    pub pointer_to_next_function: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct AuxSymbolRecordWeakExternal {
    pub tag_index: u32,
    pub characteristics: WeakExternalCharacteristics,
}

#[derive(Debug, Clone, Copy, From)]
pub struct AuxSymbolRecordFile {
    pub filename: [u8; 18],
}

#[derive(Debug, Clone, Copy, From)]
pub enum AuxSymbolRecord {
    Function(AuxSymbolRecordFunction),
    BeginEndFunction(AuxSymbolRecordBeginEndFunction),
    WeakExternal(AuxSymbolRecordWeakExternal),
    File(AuxSymbolRecordFile),
    Section(AuxSymbolRecordSection),
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
            Self::Function(AuxSymbolRecordFunction {
                tag_index,
                total_size,
                pointer_to_line_number,
                pointer_to_next_function,
            }) => {
                out.put_u32_le(*tag_index);
                out.put_u32_le(*total_size);
                out.put_u32_le(*pointer_to_line_number);
                out.put_u32_le(*pointer_to_next_function);
                out.put_bytes(0, 2); // Unused
            }
            Self::BeginEndFunction(AuxSymbolRecordBeginEndFunction {
                line_number,
                pointer_to_next_function,
            }) => {
                out.put_u16_le(*line_number);
                out.put_u32_le(*pointer_to_next_function);
                out.put_bytes(0, 12); // Unused
            }
            Self::WeakExternal(AuxSymbolRecordWeakExternal {
                tag_index,
                characteristics,
            }) => {
                out.put_u32_le(*tag_index);
                out.put_u32_le(*characteristics as u32);
                out.put_bytes(0, 10); // Unused
            }
            Self::File(AuxSymbolRecordFile { filename }) => {
                out.put_slice(filename);
            }
            Self::Section(AuxSymbolRecordSection {
                length,
                number_of_relocations,
                number_of_line_numbers,
                checksum,
                number,
                selection,
            }) => {
                out.put_u32_le(*length);
                out.put_u16_le(*number_of_relocations);
                out.put_u16_le(*number_of_line_numbers);
                out.put_u32_le(*checksum);
                out.put_u16_le(*number);
                out.put_u8(*selection as u8);
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

        // Parse auxiliary symbol records based on storage class
        let mut aux_symbols = Vec::with_capacity(number_of_aux_symbols as usize);
        for _ in 0..number_of_aux_symbols {
            let aux_record = match storage_class {
                StorageClass::Function => {
                    // Function definition aux record
                    let tag_index = le_u32.parse_next(input)?;
                    let total_size = le_u32.parse_next(input)?;
                    let pointer_to_line_number = le_u32.parse_next(input)?;
                    let pointer_to_next_function = le_u32.parse_next(input)?;
                    take(2usize).parse_next(input)?; // Unused
                    
                    AuxSymbolRecord::Function(AuxSymbolRecordFunction {
                        tag_index,
                        total_size,
                        pointer_to_line_number,
                        pointer_to_next_function,
                    })
                }
                StorageClass::Block => {
                    // .bf and .ef symbols
                    let line_number = le_u16.parse_next(input)?;
                    let pointer_to_next_function = le_u32.parse_next(input)?;
                    take(12usize).parse_next(input)?; // Unused
                    
                    AuxSymbolRecord::BeginEndFunction(AuxSymbolRecordBeginEndFunction {
                        line_number,
                        pointer_to_next_function,
                    })
                }
                StorageClass::WeakExternal => {
                    // Weak externals
                    let tag_index = le_u32.parse_next(input)?;
                    let characteristics = le_u32.parse_next(input)?;
                    take(10usize).parse_next(input)?; // Unused
                    
                    let characteristics = WeakExternalCharacteristics::from_u32(characteristics)
                        .unwrap_or(WeakExternalCharacteristics::NoLibrarySearch);
                        
                    AuxSymbolRecord::WeakExternal(AuxSymbolRecordWeakExternal {
                        tag_index,
                        characteristics,
                    })
                }
                StorageClass::File => {
                    // File aux record
                    let filename = take(18usize).parse_next(input)?;
                    AuxSymbolRecord::File(AuxSymbolRecordFile {
                        filename: filename.try_into().unwrap(),
                    })
                }
                StorageClass::Section | StorageClass::Static => {
                    // Section definition
                    let length = le_u32.parse_next(input)?;
                    let number_of_relocations = le_u16.parse_next(input)?;
                    let number_of_line_numbers = le_u16.parse_next(input)?;
                    let checksum = le_u32.parse_next(input)?;
                    let number = le_u16.parse_next(input)?;
                    let selection = input.next_token().unwrap();
                    let selection = ComdatSelection::from_u8(selection)
                        .unwrap_or(ComdatSelection::Any);
                    take(3usize).parse_next(input)?; // Unused
                    
                    AuxSymbolRecord::Section(AuxSymbolRecordSection {
                        length,
                        number_of_relocations,
                        number_of_line_numbers,
                        checksum,
                        number,
                        selection,
                    })
                }
                _ => {
                    // Unhandled aux record types - store raw bytes
                    let raw = take(18usize).parse_next(input)?;
                    AuxSymbolRecord::Raw(raw.try_into().unwrap())
                }
            };
            aux_symbols.push(aux_record);
        }

        let entry = SymbolTableEntry {
            // offset is not known here
            offset: SymbolIdx(0),
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

