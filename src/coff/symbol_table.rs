use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use winnow::{
    binary::{le_u16, le_u32},
    combinator::{alt, preceded},
    error::{ContextError, StrContext},
    prelude::*,
    token::take,
};

use crate::parse::Parse;

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

#[derive(Debug, Clone)]
pub struct SymbolTableEntry {
    pub name: Name,
    pub value: u32,
    pub section_number: i16,
    pub type_: u16,
    pub storage_class: StorageClass,
    pub number_of_aux_symbols: u8,
    pub aux_symbols: Vec<AuxSymbolRecord>,
}

#[derive(Debug, Clone, Copy)]
pub enum Name {
    Short([u8; 8]),
    Long(u32), // Offset into string table
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

        // Parse auxiliary symbol records
        let mut aux_symbols = Vec::with_capacity(number_of_aux_symbols as usize);
        for _ in 0..number_of_aux_symbols {
            let aux_record = match storage_class {
                StorageClass::Function => {
                    let tag_index = le_u32.parse_next(input)?;
                    let total_size = le_u32.parse_next(input)?;
                    let pointer_to_line_number = le_u32.parse_next(input)?;
                    let pointer_to_next_function = le_u32.parse_next(input)?;
                    take(2usize).parse_next(input)?; // Unused
                    AuxSymbolRecord::Function {
                        tag_index,
                        total_size,
                        pointer_to_line_number,
                        pointer_to_next_function,
                    }
                }
                StorageClass::Block => {
                    let line_number = le_u16.parse_next(input)?;
                    let pointer_to_next_function = le_u32.parse_next(input)?;
                    take(12usize).parse_next(input)?; // Unused
                    AuxSymbolRecord::BeginEndFunction {
                        line_number,
                        pointer_to_next_function,
                    }
                }
                StorageClass::WeakExternal => {
                    let tag_index = le_u32.parse_next(input)?;
                    let characteristics = le_u32.parse_next(input)?;
                    take(10usize).parse_next(input)?; // Unused
                    AuxSymbolRecord::WeakExternal {
                        tag_index,
                        characteristics,
                    }
                }
                StorageClass::File => {
                    let filename = take(18usize).parse_next(input)?;
                    AuxSymbolRecord::File {
                        filename: filename.try_into().unwrap(),
                    }
                }
                StorageClass::Section => {
                    let length = le_u32.parse_next(input)?;
                    let number_of_relocations = le_u16.parse_next(input)?;
                    let number_of_line_numbers = le_u16.parse_next(input)?;
                    let checksum = le_u32.parse_next(input)?;
                    let number = le_u16.parse_next(input)?;
                    let selection = input.next_token().unwrap();
                    take(3usize).parse_next(input)?; // Unused
                    AuxSymbolRecord::Section {
                        length,
                        number_of_relocations,
                        number_of_line_numbers,
                        checksum,
                        number,
                        selection,
                    }
                }
                _ => {
                    // Save raw bytes for unhandled aux record types
                    let raw = take(18usize).parse_next(input)?;
                    AuxSymbolRecord::Raw(raw.try_into().unwrap())
                }
            };
            aux_symbols.push(aux_record);
        }

        Ok(SymbolTableEntry {
            name,
            value,
            section_number,
            type_,
            storage_class,
            number_of_aux_symbols,
            aux_symbols,
        })
    }
}
