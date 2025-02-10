use num_traits::FromPrimitive;
use std::borrow::Cow;
use winnow::{
    binary::{le_u16, le_u32, le_u8},
    error::ContextError,
    token::take_until,
    Parser,
};

use crate::parse::Parse;

#[derive(Debug, Clone)]
pub struct ShortImportLibrary<'a> {
    pub header: ImportHeader,
    pub import_name: Cow<'a, str>,
    pub dll_name: Cow<'a, str>,
}

#[derive(Debug, Clone)]
pub struct ImportHeader {
    pub sig1: u16,
    pub sig2: u16,
    pub version: u16,
    pub machine: u16,
    pub time_date_stamp: u32,
    pub size_of_data: u32,
    pub ordinal_hint: u16,
    pub type_info: TypeInfo,
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub import_type: ImportType,
    pub name_type: NameType,
}

impl FromPrimitive for TypeInfo {
    fn from_i64(n: i64) -> Option<Self> {
        Self::from_u64(n as u64)
    }

    fn from_u64(n: u64) -> Option<Self> {
        Some(TypeInfo {
            import_type: match n & 0x3 {
                0 => ImportType::Code,
                1 => ImportType::Data,
                2 => ImportType::Const,
                _ => return None,
            },
            name_type: match (n >> 2) & 0x3 {
                0 => NameType::Ordinal,
                1 => NameType::Name,
                2 => NameType::NoPrefix,
                3 => NameType::Undecorate,
                _ => return None,
            },
        })
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum ImportType {
    Code = 0,
    Data = 1,
    Const = 2,
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum NameType {
    Ordinal = 0,
    Name = 1,
    NoPrefix = 2,
    Undecorate = 3,
}

impl<'a> Parse<'a> for ShortImportLibrary<'a> {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let header = ImportHeader::parse(input)?;

        // Parse null-terminated strings
        let import_name = take_until(0.., 0)
            .try_map(std::str::from_utf8)
            .parse_next(input)?;

        // Skip null terminator
        le_u8.parse_next(input)?;

        let dll_name = take_until(0.., 0)
            .try_map(std::str::from_utf8)
            .parse_next(input)?;

        Ok(ShortImportLibrary {
            header,
            import_name: Cow::Borrowed(import_name),
            dll_name: Cow::Borrowed(dll_name),
        })
    }
}

impl Parse<'_> for ImportHeader {
    type Error = ContextError;

    fn parse(input: &mut &[u8]) -> Result<Self, Self::Error> {
        let sig1 = le_u16.parse_next(input)?;
        let sig2 = le_u16.parse_next(input)?;
        let version = le_u16.parse_next(input)?;
        let machine = le_u16.parse_next(input)?;
        let time_date_stamp = le_u32.parse_next(input)?;
        let size_of_data = le_u32.parse_next(input)?;
        let ordinal_hint = le_u16.parse_next(input)?;

        // Parse type info bits
        let type_info = le_u16.verify_map(TypeInfo::from_u16).parse_next(input)?;

        Ok(ImportHeader {
            sig1,
            sig2,
            version,
            machine,
            time_date_stamp,
            size_of_data,
            ordinal_hint,
            type_info,
        })
    }
}
