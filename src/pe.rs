use thiserror::Error;
use winnow::binary::le_u16;
use winnow::binary::le_u32;
use winnow::binary::le_u64;
use winnow::combinator::opt;
use winnow::error::ContextError;
use winnow::error::ParseError;
use winnow::prelude::*;
use winnow::token::take;

use crate::coff::{CoffFileHeader, CoffSectionHeader};
use crate::parse::Parse;

#[derive(Error, Debug)]
pub enum PeError<'a> {
    #[error("invalid DOS magic number")]
    InvalidDosMagic,
    #[error("invalid PE magic number")]
    InvalidPeMagic,
    #[error("parse error: {0}")]
    Context(ContextError),
    #[error("parse error: {0}")]
    Parse(ParseError<&'a [u8], ContextError>),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// MS-DOS Header
#[derive(Debug, Clone, Copy)]
pub struct DosHeader {
    /// File address of PE header
    pub e_lfanew: u32,
}

impl<'a> Parse<'a> for DosHeader {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        b"MZ".parse_next(input)?;
        // Skip the rest of the DOS header fields
        take(58usize).parse_next(input)?;
        let e_lfanew = le_u32.parse_next(input)?;

        Ok(DosHeader { e_lfanew })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl<'a> Parse<'a> for DataDirectory {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let virtual_address = le_u32.parse_next(input)?;
        let size = le_u32.parse_next(input)?;

        Ok(DataDirectory {
            virtual_address,
            size,
        })
    }
}

// Optional Header
#[derive(Debug)]
pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: Vec<DataDirectory>,
}

impl<'a> Parse<'a> for OptionalHeader {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let magic = le_u16.parse_next(input)?;
        let is_pe32_plus = magic == 0x20b;

        let major_linker_version: u8 = input.next_token().unwrap();
        let minor_linker_version = input.next_token().unwrap();
        let size_of_code = le_u32.parse_next(input)?;
        let size_of_initialized_data = le_u32.parse_next(input)?;
        let size_of_uninitialized_data = le_u32.parse_next(input)?;
        let address_of_entry_point = le_u32.parse_next(input)?;
        let base_of_code = le_u32.parse_next(input)?;

        let image_base = if is_pe32_plus {
            le_u64.parse_next(input)?
        } else {
            le_u32.parse_next(input)? as u64
        };

        let section_alignment = le_u32.parse_next(input)?;
        let file_alignment = le_u32.parse_next(input)?;
        let major_operating_system_version = le_u16.parse_next(input)?;
        let minor_operating_system_version = le_u16.parse_next(input)?;
        let major_image_version = le_u16.parse_next(input)?;
        let minor_image_version = le_u16.parse_next(input)?;
        let major_subsystem_version = le_u16.parse_next(input)?;
        let minor_subsystem_version = le_u16.parse_next(input)?;
        let win32_version_value = le_u32.parse_next(input)?;
        let size_of_image = le_u32.parse_next(input)?;
        let size_of_headers = le_u32.parse_next(input)?;
        let checksum = le_u32.parse_next(input)?;
        let subsystem = le_u16.parse_next(input)?;
        let dll_characteristics = le_u16.parse_next(input)?;

        // PE32+ uses 64-bit fields
        let (
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
        ) = if is_pe32_plus {
            (
                le_u64.parse_next(input)?,
                le_u64.parse_next(input)?,
                le_u64.parse_next(input)?,
                le_u64.parse_next(input)?,
            )
        } else {
            (
                le_u32.parse_next(input)? as u64,
                le_u32.parse_next(input)? as u64,
                le_u32.parse_next(input)? as u64,
                le_u32.parse_next(input)? as u64,
            )
        };

        let loader_flags = le_u32.parse_next(input)?;
        let number_of_rva_and_sizes = le_u32.parse_next(input)?;

        let mut data_directories = Vec::new();
        for _ in 0..number_of_rva_and_sizes {
            data_directories.push(DataDirectory::parse(input)?);
        }

        Ok(OptionalHeader {
            magic,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_initialized_data,
            size_of_uninitialized_data,
            address_of_entry_point,
            base_of_code,
            image_base,
            section_alignment,
            file_alignment,
            major_operating_system_version,
            minor_operating_system_version,
            major_image_version,
            minor_image_version,
            major_subsystem_version,
            minor_subsystem_version,
            win32_version_value,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            loader_flags,
            number_of_rva_and_sizes,
            data_directories,
        })
    }
}

// Top level PE file structure
#[derive(Debug)]
pub struct PeFile<'a> {
    pub dos_header: DosHeader,
    pub coff_header: CoffFileHeader,
    pub optional_header: OptionalHeader,
    pub section_headers: Vec<CoffSectionHeader<'a>>,
}

impl<'a> Parse<'a> for PeFile<'a> {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let dos_header = DosHeader::parse(input)?;

        // Skip to PE header using e_lfanew
        let pe_offset = dos_header.e_lfanew as usize;
        take(pe_offset).parse_next(input)?;

        // Verify PE signature
        b"PE\0\0".parse_next(input)?;

        let coff_header = CoffFileHeader::parse(input)?;
        let optional_header = OptionalHeader::parse(input)?;

        let mut section_headers = Vec::new();
        for _ in 0..coff_header.number_of_sections {
            section_headers.push(CoffSectionHeader::parse(input)?);
        }

        Ok(PeFile {
            dos_header,
            coff_header,
            optional_header,
            section_headers,
        })
    }
}
