//! Parser for Common Object File Format (COFF).

use std::borrow::Cow;

use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use string_table::StringTable;
use symbol_table::SymbolTable;
use symbol_table::SymbolTableEntry;
use thiserror::Error;
use winnow::binary::le_u16;
use winnow::binary::le_u32;
use winnow::combinator::repeat;
use winnow::error::{ContextError, ParseError, StrContext};
use winnow::prelude::*;
use winnow::token::take;
use winnow::token::take_while;

use crate::flags::FileCharacteristics;
use crate::flags::SectionCharacteristics;
use crate::parse::Parse;

pub mod archive;
pub mod relocations;
pub mod sections;
pub mod string_table;
pub mod symbol_table;

use relocations::CoffRelocation;

#[derive(Error, Debug)]
pub enum CoffError<'a> {
    #[error("invalid magic number")]
    InvalidMagic,
    #[error("invalid section alignment")]
    InvalidAlignment,
    #[error("parse error: {0}")]
    Context(ContextError),
    #[error("parse error: {0}")]
    Parse(ParseError<&'a [u8], ContextError>),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive)]
#[repr(u16)]
pub enum Machine {
    Unknown = 0x0,
    Alpha = 0x184,
    Alpha64 = 0x284,
    AM33 = 0x1d3,
    AMD64 = 0x8664,
    ARM = 0x1c0,
    ARM64 = 0xaa64,
    ARMNT = 0x1c4,
    EBC = 0xebc,
    I386 = 0x14c,
    IA64 = 0x200,
    LoongArch32 = 0x6232,
    LoongArch64 = 0x6264,
    M32R = 0x9041,
    MIPS16 = 0x266,
    MIPSFPU = 0x366,
    MIPSFPU16 = 0x466,
    PowerPC = 0x1f0,
    PowerPCFP = 0x1f1,
    R4000 = 0x166,
    RISCV32 = 0x5032,
    RISCV64 = 0x5064,
    RISCV128 = 0x5128,
    SH3 = 0x1a2,
    SH3DSP = 0x1a3,
    SH4 = 0x1a6,
    SH5 = 0x1a8,
    Thumb = 0x1c2,
    WCEMipsV2 = 0x169,
}

#[derive(Debug, Clone, Copy)]
pub struct CoffFileHeader {
    pub machine: Machine,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: FileCharacteristics,
}

impl<'a> Parse<'a> for CoffFileHeader {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let machine = le_u16
            .verify_map(|m| Machine::from_u16(m))
            .context(StrContext::Label("machine"))
            .parse_next(input)?;

        let (
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
        ) = (
            le_u16,
            le_u32,
            le_u32,
            le_u32,
            le_u16,
            le_u16.verify_map(FileCharacteristics::from_bits),
        )
            .parse_next(input)?;

        Ok(CoffFileHeader {
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CoffSectionHeader<'a> {
    pub name: Cow<'a, str>,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: SectionCharacteristics,
}

impl<'a> Parse<'a> for CoffSectionHeader<'a> {
    type Error = ContextError;

    fn parse(data: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let mut name = take(8usize)
            .context(StrContext::Label("name"))
            .parse_next(data)?;
        let name = take_while(0..8, |c| c != 0)
            .verify_map(|s| std::str::from_utf8(s).ok())
            .context(StrContext::Label("name utf-8"))
            .parse_next(&mut name)?;

        let (
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            pointer_to_relocations,
            pointer_to_linenumbers,
            number_of_relocations,
            number_of_linenumbers,
            characteristics,
        ) = (
            le_u32,
            le_u32,
            le_u32,
            le_u32,
            le_u32,
            le_u32,
            le_u16,
            le_u16,
            le_u32.verify_map(SectionCharacteristics::from_bits),
        )
            .parse_next(data)?;

        Ok(Self {
            name: name.into(),
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            pointer_to_relocations,
            pointer_to_linenumbers,
            number_of_relocations,
            number_of_linenumbers,
            characteristics,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffSectionId {
    pub object_idx: usize,
    pub section_idx: usize,
}

#[derive(Debug, Clone)]
pub struct CoffSection<'a> {
    /// Not parsed from file, but assigned by `cuban` for tracking
    pub id: CoffSectionId,

    pub header: CoffSectionHeader<'a>,
    pub data: Option<Cow<'a, [u8]>>,
    pub relocations: Vec<CoffRelocation>,
}

#[derive(Debug, Clone)]
pub struct CoffFile<'a> {
    pub header: CoffFileHeader,
    pub sections: Vec<CoffSection<'a>>,
    pub symbol_table: Option<SymbolTable>,
    pub string_table: Option<StringTable<'a>>,
}

impl<'a> Parse<'a> for CoffFile<'a> {
    type Error = ContextError;

    fn parse(data: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let all_data = *data;

        let file_header = CoffFileHeader::parse
            .context(StrContext::Label("coff header"))
            .parse_next(data)?;

        let section_headers: Vec<_> = repeat(
            file_header.number_of_sections as usize,
            CoffSectionHeader::parse,
        )
        .context(StrContext::Label("sections"))
        .parse_next(data)?;

        let mut sections: Vec<_> = section_headers
            .into_iter()
            .enumerate()
            .map(|(idx, header)| CoffSection {
                id: CoffSectionId {
                    object_idx: 0,
                    section_idx: idx,
                },
                data: if header.pointer_to_raw_data > 0 && header.size_of_raw_data > 0 {
                    let ptr = header.pointer_to_raw_data as usize;
                    let len = header.size_of_raw_data as usize;
                    Some(all_data[ptr..ptr + len].into())
                } else {
                    None
                },
                header,
                relocations: vec![],
            })
            .collect();

        // Parse relocations for each section
        for section in &mut sections {
            if section.header.number_of_relocations > 0 && section.header.pointer_to_relocations > 0
            {
                let reloc_data = &mut &all_data[section.header.pointer_to_relocations as usize..];

                let section_relocs: Vec<_> = repeat(
                    section.header.number_of_relocations as usize,
                    CoffRelocation::parse,
                )
                .context(StrContext::Label("relocations"))
                .parse_next(reloc_data)?;

                section.relocations.extend(section_relocs);
            }
        }

        let (symbol_table, string_table) = if file_header.pointer_to_symbol_table > 0
            && file_header.number_of_symbols > 0
        {
            let symbol_table_data = &mut &all_data[file_header.pointer_to_symbol_table as usize..];
            // auxiliary symbol table entries count against the total number of symbols
            let mut i = 0;

            let mut symbol_table_entries = vec![];

            while i < file_header.number_of_symbols {
                let mut entry = SymbolTableEntry::parse
                    .context(StrContext::Label("symbol table entry"))
                    .parse_next(symbol_table_data)?;
                entry.offset = i as usize;
                i += 1 + entry.number_of_aux_symbols as u32;
                symbol_table_entries.push(entry);
            }

            let symbol_table = Some(SymbolTable {
                entries: symbol_table_entries,
            });

            // String table follows symbol table
            let symbol_table_size = file_header.number_of_symbols as usize * 18;
            let string_table_offset =
                file_header.pointer_to_symbol_table as usize + symbol_table_size;

            let string_table = if string_table_offset < all_data.len() {
                let string_table_data = &mut &all_data[string_table_offset..];
                Some(StringTable::parse(string_table_data)?)
            } else {
                None
            };

            (symbol_table, string_table)
        } else {
            (None, None)
        };

        Ok(Self {
            header: file_header,
            sections,
            symbol_table,
            string_table,
        })
    }
}
