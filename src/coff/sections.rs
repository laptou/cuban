use crate::parse::{Parse, Write};
use bytes::BufMut;
use winnow::{
    binary::{le_u16, le_u32, le_u64},
    error::ContextError,
    prelude::*,
};

// .edata section - Export Directory
#[derive(Debug, Clone)]
pub struct ExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name_rva: u32,
    pub ordinal_base: u32,
    pub address_table_entries: u32,
    pub number_of_name_pointers: u32,
    pub export_address_table_rva: u32,
    pub name_pointer_rva: u32,
    pub ordinal_table_rva: u32,
}

// .idata section - Import Directory
#[derive(Debug, Clone)]
pub struct ImportDirectory {
    pub import_lookup_table_rva: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: u32,
    pub import_address_table_rva: u32,
}

// .pdata section - Exception Directory
#[derive(Debug, Clone)]
pub struct ExceptionDirectory {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

// .reloc section - Base Relocation Block
#[derive(Debug, Clone)]
pub struct BaseRelocationBlock {
    pub page_rva: u32,
    pub block_size: u32,
    pub entries: Vec<BaseRelocationEntry>,
}

#[derive(Debug, Clone)]
pub struct BaseRelocationEntry {
    pub offset: u16,
    pub relocation_type: u16,
}

// .tls section - TLS Directory
#[derive(Debug, Clone)]
pub struct TlsDirectory {
    pub raw_data_start_va: u64,
    pub raw_data_end_va: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

// .rsrc section - Resource Directory
#[derive(Debug, Clone)]
pub struct ResourceDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub number_of_named_entries: u16,
    pub number_of_id_entries: u16,
    pub entries: Vec<ResourceDirectoryEntry>,
}

#[derive(Debug, Clone)]
pub struct ResourceDirectoryEntry {
    pub name: u32,
    pub offset: u32,
}

// Implement Parse trait for each structure
impl<'a> Parse<'a> for ExportDirectory {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let (
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            name_rva,
            ordinal_base,
            address_table_entries,
            number_of_name_pointers,
            export_address_table_rva,
            name_pointer_rva,
            ordinal_table_rva,
        ) = (
            le_u32, le_u32, le_u16, le_u16, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32,
        )
            .parse_next(input)?;

        Ok(ExportDirectory {
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            name_rva,
            ordinal_base,
            address_table_entries,
            number_of_name_pointers,
            export_address_table_rva,
            name_pointer_rva,
            ordinal_table_rva,
        })
    }
}

impl<'a> Parse<'a> for ImportDirectory {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let (
            import_lookup_table_rva,
            time_date_stamp,
            forwarder_chain,
            name_rva,
            import_address_table_rva,
        ) = (le_u32, le_u32, le_u32, le_u32, le_u32).parse_next(input)?;

        Ok(ImportDirectory {
            import_lookup_table_rva,
            time_date_stamp,
            forwarder_chain,
            name_rva,
            import_address_table_rva,
        })
    }
}

impl<'a> Parse<'a> for ExceptionDirectory {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let (begin_address, end_address, unwind_info_address) = (le_u32, le_u32, le_u32)
            .parse_next(input)?;

        Ok(ExceptionDirectory {
            begin_address,
            end_address,
            unwind_info_address,
        })
    }
}

impl<'a> Parse<'a> for BaseRelocationBlock {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let page_rva = le_u32.parse_next(input)?;
        let block_size = le_u32.parse_next(input)?;
        
        let num_entries = (block_size as usize - 8) / 2;
        let mut entries = Vec::with_capacity(num_entries);
        
        for _ in 0..num_entries {
            let entry = le_u16.parse_next(input)?;
            entries.push(BaseRelocationEntry {
                offset: entry & 0xFFF,
                relocation_type: entry >> 12,
            });
        }

        Ok(BaseRelocationBlock {
            page_rva,
            block_size,
            entries,
        })
    }
}

impl<'a> Parse<'a> for TlsDirectory {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let (
            raw_data_start_va,
            raw_data_end_va,
            address_of_index,
            address_of_callbacks,
            size_of_zero_fill,
            characteristics,
        ) = (le_u64, le_u64, le_u64, le_u64, le_u32, le_u32).parse_next(input)?;

        Ok(TlsDirectory {
            raw_data_start_va,
            raw_data_end_va,
            address_of_index,
            address_of_callbacks,
            size_of_zero_fill,
            characteristics,
        })
    }
}

impl<'a> Parse<'a> for ResourceDirectory {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let (
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            number_of_named_entries,
            number_of_id_entries,
        ) = (le_u32, le_u32, le_u16, le_u16, le_u16, le_u16).parse_next(input)?;

        let total_entries = (number_of_named_entries + number_of_id_entries) as usize;
        let mut entries = Vec::with_capacity(total_entries);

        for _ in 0..total_entries {
            let name = le_u32.parse_next(input)?;
            let offset = le_u32.parse_next(input)?;
            entries.push(ResourceDirectoryEntry { name, offset });
        }

        Ok(ResourceDirectory {
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            number_of_named_entries,
            number_of_id_entries,
            entries,
        })
    }
}
