use bytes::BufMut;
use num_traits::FromPrimitive;
use thiserror::Error;
use winnow::binary::le_u16;
use winnow::binary::le_u32;
use winnow::binary::le_u64;
use winnow::combinator::repeat;
use winnow::error::ParserError;
use winnow::error::{ContextError, ParseError, StrContext};
use winnow::prelude::*;
use winnow::token::take;

use crate::coff::CoffSection;
use crate::coff::CoffSectionId;
use crate::parse::{Layout, Write};

use crate::coff::{
    string_table::StringTable,
    symbol_table::{SymbolTable, SymbolTableEntry},
    CoffFileHeader, CoffSectionHeader,
};
use crate::flags::{DllCharacteristics, Subsystem};
use crate::parse::Parse;

// MS-DOS Header
#[derive(Debug, Clone, Copy)]
pub struct DosHeader {
    /// File address of PE header
    pub e_lfanew: u32,
}

impl Layout for DosHeader {
    fn total_size(&self) -> u32 {
        // DOS header is fixed size: 2 bytes magic + 58 bytes stub + 4 bytes e_lfanew
        64
    }
}

impl Write for DosHeader {
    type Error = std::io::Error;

    fn write(&self, mut out: &mut [u8]) -> Result<(), Self::Error> {
        // Write DOS magic "MZ"
        out.put_slice(b"MZ");
        // Write 58 bytes of DOS stub
        out.put_bytes(0, 58);
        // Write e_lfanew
        out.put_u32_le(self.e_lfanew);
        Ok(())
    }
}

impl<'a> Parse<'a> for DosHeader {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        b"MZ"
            .context(StrContext::Label("dos magic"))
            .parse_next(input)?;
        // Skip the rest of the DOS header fields
        take(58usize)
            .context(StrContext::Label("dos header"))
            .parse_next(input)?;
        let e_lfanew = le_u32
            .context(StrContext::Label("e_lfanew"))
            .parse_next(input)?;

        Ok(DosHeader { e_lfanew })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl Layout for DataDirectory {
    fn total_size(&self) -> u32 {
        8 // Fixed size: 4 bytes VA + 4 bytes size
    }
}

impl Write for DataDirectory {
    type Error = std::io::Error;

    fn write(&self, mut out: &mut [u8]) -> Result<(), Self::Error> {
        out.put_u32_le(self.virtual_address);
        out.put_u32_le(self.size);
        Ok(())
    }
}

impl<'a> Parse<'a> for DataDirectory {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let virtual_address = le_u32
            .context(StrContext::Label("virtual address"))
            .parse_next(input)?;
        let size = le_u32
            .context(StrContext::Label("size"))
            .parse_next(input)?;

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
    pub subsystem: Subsystem,
    pub dll_characteristics: DllCharacteristics,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: Vec<DataDirectory>,
}

impl OptionalHeader {
    pub const MAGIC_PE32: u16 = 0x10;
    pub const MAGIC_PE32_PLUS: u16 = 0x20;
}

impl Layout for OptionalHeader {
    fn fix_layout(&mut self) -> u32 {
        // Update number_of_rva_and_sizes
        self.number_of_rva_and_sizes = self.data_directories.len() as u32;
        self.total_size()
    }

    fn total_size(&self) -> u32 {
        let is_pe32_plus = self.magic == Self::MAGIC_PE32_PLUS;

        // Calculate base size without data directories
        let base_size = if is_pe32_plus {
            // PE32+ header size up to but not including data directories
            112
        } else {
            // PE32 header size up to but not including data directories
            96
        };

        base_size + (self.number_of_rva_and_sizes * 8) as u32
    }
}

impl Write for OptionalHeader {
    type Error = std::io::Error;

    fn write(&self, mut out: &mut [u8]) -> Result<(), Self::Error> {
        out.put_u16_le(self.magic);
        out.put_u8(self.major_linker_version);
        out.put_u8(self.minor_linker_version);
        out.put_u32_le(self.size_of_code);
        out.put_u32_le(self.size_of_initialized_data);
        out.put_u32_le(self.size_of_uninitialized_data);
        out.put_u32_le(self.address_of_entry_point);
        out.put_u32_le(self.base_of_code);

        let is_pe32_plus = self.magic == Self::MAGIC_PE32_PLUS;

        if is_pe32_plus {
            out.put_u64_le(self.image_base);
        } else {
            out.put_u32_le(self.image_base as u32);
        }

        out.put_u32_le(self.section_alignment);
        out.put_u32_le(self.file_alignment);
        out.put_u16_le(self.major_operating_system_version);
        out.put_u16_le(self.minor_operating_system_version);
        out.put_u16_le(self.major_image_version);
        out.put_u16_le(self.minor_image_version);
        out.put_u16_le(self.major_subsystem_version);
        out.put_u16_le(self.minor_subsystem_version);
        out.put_u32_le(self.win32_version_value);
        out.put_u32_le(self.size_of_image);
        out.put_u32_le(self.size_of_headers);
        out.put_u32_le(self.checksum);
        out.put_u16_le(self.subsystem as u16);
        out.put_u16_le(self.dll_characteristics.bits());

        if is_pe32_plus {
            out.put_u64_le(self.size_of_stack_reserve);
            out.put_u64_le(self.size_of_stack_commit);
            out.put_u64_le(self.size_of_heap_reserve);
            out.put_u64_le(self.size_of_heap_commit);
        } else {
            out.put_u32_le(self.size_of_stack_reserve as u32);
            out.put_u32_le(self.size_of_stack_commit as u32);
            out.put_u32_le(self.size_of_heap_reserve as u32);
            out.put_u32_le(self.size_of_heap_commit as u32);
        }

        out.put_u32_le(self.loader_flags);
        out.put_u32_le(self.number_of_rva_and_sizes);

        for dir in &self.data_directories {
            dir.write(out)?;
        }

        Ok(())
    }
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
        let subsystem = le_u16.verify_map(Subsystem::from_u16).parse_next(input)?;
        let dll_characteristics = le_u16
            .verify_map(DllCharacteristics::from_bits)
            .parse_next(input)?;

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
    pub sections: Vec<CoffSection<'a>>,
    pub symbol_table: Option<SymbolTable>,
    pub string_table: Option<StringTable<'a>>,
}

impl<'a> Layout for PeFile<'a> {
    fn total_size(&self) -> u32 {
        // Start with DOS header size
        let dos_header_size = self.dos_header.total_size();

        // Calculate PE header offset - must be aligned to 8 bytes
        let pe_header_offset = (dos_header_size + 7) & !7;

        // PE signature (4 bytes) + COFF header (20 bytes)
        let mut current_offset = pe_header_offset + 24;

        // Optional header
        current_offset += self.optional_header.total_size();

        // Section headers (40 bytes each)
        let section_headers_size = (self.sections.len() * 40) as u32;
        current_offset += section_headers_size;

        // Calculate total size including section data and relocations
        let mut data_offset = current_offset;
        for section in &self.sections {
            if let Some(data) = section.data.as_deref() {
                data_offset += data.len() as u32;

                // Add space for relocations if any
                if !section.relocations.is_empty() {
                    data_offset += (section.relocations.len() * 10) as u32; // Each relocation is 10 bytes
                }
            }
        }

        // Add symbol table size if present
        if let Some(symbol_table) = &self.symbol_table {
            let num_symbols: u32 = symbol_table
                .entries
                .iter()
                .map(|e| 1 + e.number_of_aux_symbols as u32)
                .sum();
            data_offset += num_symbols * 18; // Each symbol is 18 bytes
        }

        data_offset
    }

    fn fix_layout(&mut self) -> u32 {
        // Start with DOS header size
        let dos_header_size = self.dos_header.fix_layout();

        // Calculate PE header offset - must be aligned to 8 bytes
        let pe_header_offset = (dos_header_size + 7) & !7;
        self.dos_header.e_lfanew = pe_header_offset;

        // PE signature (4 bytes) + COFF header (20 bytes)
        let mut current_offset = pe_header_offset + 24;

        // Fix optional header layout
        let optional_header_size = self.optional_header.fix_layout();
        self.coff_header.size_of_optional_header = optional_header_size as u16;
        current_offset += optional_header_size;

        // Section headers (40 bytes each)
        let section_headers_size = (self.sections.len() * 40) as u32;
        current_offset += section_headers_size;

        // Update section data offsets and sizes
        let mut data_offset = current_offset;
        for section in &mut self.sections {
            if let Some(data) = section.data.as_deref() {
                section.header.pointer_to_raw_data = data_offset;
                section.header.size_of_raw_data = data.len() as u32;
                data_offset += section.header.size_of_raw_data;

                // Add space for relocations if any
                if !section.relocations.is_empty() {
                    section.header.pointer_to_relocations = data_offset;
                    section.header.number_of_relocations = section.relocations.len() as u16;
                    data_offset += (section.relocations.len() * 10) as u32; // Each relocation is 10 bytes
                }
            }
        }

        // Update COFF header fields
        self.coff_header.number_of_sections = self.sections.len() as u16;

        // Calculate symbol table offset if present
        if let Some(symbol_table) = &self.symbol_table {
            self.coff_header.pointer_to_symbol_table = data_offset;
            self.coff_header.number_of_symbols = symbol_table
                .entries
                .iter()
                .map(|e| 1 + e.number_of_aux_symbols as u32)
                .sum();
            data_offset += self.coff_header.number_of_symbols * 18; // Each symbol is 18 bytes
        }

        // Update optional header fields
        self.optional_header.size_of_headers = current_offset;
        self.optional_header.size_of_image = data_offset;

        data_offset
    }
}

impl<'a> Write for PeFile<'a> {
    type Error = std::io::Error;

    fn write(&self, mut out: &mut [u8]) -> Result<(), Self::Error> {
        // Write DOS header
        self.dos_header.write(out)?;

        // Seek to PE header location
        // TODO
        let current_pos = 0;
        let padding_size = self.dos_header.e_lfanew as usize - current_pos;
        out.put_bytes(0, padding_size);

        // Write PE signature
        out.put_slice(b"PE\0\0");

        // Calculate symbol table info
        let (pointer_to_symbol_table, number_of_symbols) =
            if let Some(symbol_table) = &self.symbol_table {
                // Calculate total number of symbol table entries including aux symbols
                let number_of_symbols = symbol_table
                    .entries
                    .iter()
                    .map(|entry| 1 + entry.number_of_aux_symbols as u32)
                    .sum();

                // Symbol table follows section headers
                let pointer_to_symbol_table = self.dos_header.e_lfanew as u32 + 4 + // PE signature
                20 + // COFF header size
                self.coff_header.size_of_optional_header as u32 +
                (self.sections.len() * 40) as u32; // Each section header is 40 bytes

                (pointer_to_symbol_table, number_of_symbols)
            } else {
                (0, 0)
            };

        // Write COFF header with calculated values
        out.put_u16_le(self.coff_header.machine as u16);
        out.put_u16_le(self.sections.len() as u16);
        out.put_u32_le(self.coff_header.time_date_stamp);
        out.put_u32_le(pointer_to_symbol_table);
        out.put_u32_le(number_of_symbols);
        out.put_u16_le(self.coff_header.size_of_optional_header);
        out.put_u16_le(self.coff_header.characteristics.bits());

        // Write optional header
        self.optional_header.write(out)?;

        // Track current position for calculating raw data pointers
        let mut current_raw_data_pos = self.dos_header.e_lfanew as u32 + 4 + // PE signature
            20 + // COFF header size
            self.coff_header.size_of_optional_header as u32 +
            (self.sections.len() * 40) as u32; // Section headers

        // Write section headers with calculated values
        for section in &self.sections {
            // Write name (padded to 8 bytes)
            let name_bytes = section.header.name.as_bytes();
            out.put_slice(&name_bytes[..std::cmp::min(name_bytes.len(), 8)]);
            if name_bytes.len() < 8 {
                out.put_bytes(0, 8 - name_bytes.len());
            }

            out.put_u32_le(section.header.virtual_size);
            out.put_u32_le(section.header.virtual_address);

            let raw_data_len = section
                .data
                .as_ref()
                .map(|d| d.len() as u32)
                .unwrap_or_default();

            out.put_u32_le(raw_data_len);
            out.put_u32_le(current_raw_data_pos); // Calculate pointer_to_raw_data

            // Calculate relocation pointer if section has relocations
            let pointer_to_relocations = if !section.relocations.is_empty() {
                current_raw_data_pos + raw_data_len
            } else {
                0
            };
            out.put_u32_le(pointer_to_relocations);

            out.put_u32_le(0); // pointer_to_linenumbers (not supported)
            out.put_u16_le(section.relocations.len() as u16);
            out.put_u16_le(0); // number_of_linenumbers (not supported)
            out.put_u32_le(section.header.characteristics.bits());

            // Update current position
            current_raw_data_pos += raw_data_len;
            if !section.relocations.is_empty() {
                // Each relocation is 10 bytes
                current_raw_data_pos += (section.relocations.len() * 10) as u32;
            }
        }

        // Write symbol table if present
        if let Some(symbol_table) = &self.symbol_table {
            symbol_table.write(out)?;
        }

        // Write string table if present
        if let Some(string_table) = &self.string_table {
            string_table.write(out)?;
        }

        Ok(())
    }
}

impl<'a> Parse<'a> for PeFile<'a> {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let all_data = *input; // Save full input for later use

        let dos_header = DosHeader::parse
            .context(StrContext::Label("dos header"))
            .parse_next(input)?;

        // Skip to PE header using e_lfanew
        let pe_offset = dos_header.e_lfanew as usize;
        take(pe_offset - input.len())
            .context(StrContext::Label("pe header offset"))
            .parse_next(input)?;

        // Verify PE signature
        b"PE\0\0"
            .context(StrContext::Label("pe magic"))
            .parse_next(input)?;

        let coff_header = CoffFileHeader::parse
            .context(StrContext::Label("coff header"))
            .parse_next(input)?;
        let optional_header = OptionalHeader::parse
            .context(StrContext::Label("optional header"))
            .parse_next(input)?;

        let section_headers: Vec<_> = repeat(
            coff_header.number_of_sections as usize,
            CoffSectionHeader::parse,
        )
        .context(StrContext::Label("sections"))
        .parse_next(input)?;

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
                return Err(ContextError::assert(
                    input,
                    "pe file must not contain relocations",
                ));
            }
        }

        // Parse symbol table and string table if present
        let (symbol_table, string_table) = if coff_header.pointer_to_symbol_table > 0
            && coff_header.number_of_symbols > 0
        {
            let symbol_table_data = &mut &all_data[coff_header.pointer_to_symbol_table as usize..];

            // Parse symbol table entries
            let mut i = 0;
            let mut symbol_table_entries = vec![];

            while i < coff_header.number_of_symbols {
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
            let symbol_table_size = coff_header.number_of_symbols as usize * 18;
            let string_table_offset =
                coff_header.pointer_to_symbol_table as usize + symbol_table_size;

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

        Ok(PeFile {
            dos_header,
            coff_header,
            optional_header,
            sections,
            symbol_table,
            string_table,
        })
    }
}
