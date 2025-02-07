use std::borrow::Cow;

use bytes::BufMut;
use winnow::{
    binary::{le_u16, le_u32},
    combinator::repeat,
    error::{ContextError, StrContext},
    prelude::*,
    token::take,
};

use crate::parse::{Layout, Parse, Write};

use super::CoffFile;

const ARCHIVE_MAGIC: &[u8] = b"!<arch>\n";
const FIRST_LINKER_MEMBER: &[u8] = b"/               ";
const SECOND_LINKER_MEMBER: &[u8] = b"/               ";
const LONGNAMES_MEMBER: &[u8] = b"//              ";

#[derive(Debug, Clone)]
pub struct CoffArchive<'a> {
    pub first_linker: Option<FirstLinkerMember<'a>>,
    pub second_linker: Option<SecondLinkerMember<'a>>,
    pub longnames: Option<LongnamesMember<'a>>,
    pub members: Vec<ArchiveMember<'a>>,
}

#[derive(Debug, Clone)]
pub struct ArchiveMember<'a> {
    pub header: ArchiveMemberHeader<'a>,
    pub data: Cow<'a, [u8]>,
}

#[derive(Debug, Clone)]
pub struct ArchiveMemberHeader<'a> {
    pub name: ArchiveMemberName<'a>,
    pub date: u32,
    pub user_id: u16,
    pub group_id: u16,
    pub mode: u32,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub enum ArchiveMemberName<'a> {
    /// Regular name, up to 16 bytes
    Name(Cow<'a, str>),
    /// Name stored in longnames member at given offset
    LongName(u32),
    /// First linker member
    FirstLinker,
    /// Second linker member  
    SecondLinker,
    /// Longnames member
    Longnames,
}

#[derive(Debug, Clone)]
pub struct FirstLinkerMember<'a> {
    pub symbols: Vec<(u32, Cow<'a, str>)>, // (offset, name) pairs
}

#[derive(Debug, Clone)] 
pub struct SecondLinkerMember<'a> {
    pub member_offsets: Vec<u32>,
    pub symbols: Vec<(u16, Cow<'a, str>)>, // (index, name) pairs
}

#[derive(Debug, Clone)]
pub struct LongnamesMember<'a> {
    pub strings: Cow<'a, [u8]>,
}

impl<'a> Parse<'a> for CoffArchive<'a> {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let all_data = *input;

        // Check magic
        let magic = take(8usize)
            .context(StrContext::Label("archive magic"))
            .parse_next(input)?;
        if magic != ARCHIVE_MAGIC {
            return Err(ContextError::context(
                "invalid archive magic",
                input,
                StrContext::Label("archive magic"),
            ));
        }

        let mut members = Vec::new();
        let mut first_linker = None;
        let mut second_linker = None;
        let mut longnames = None;

        // Parse archive members until we run out of data
        while !input.is_empty() {
            let member = ArchiveMember::parse.parse_next(input)?;

            match &member.header.name {
                ArchiveMemberName::FirstLinker => {
                    let linker = FirstLinkerMember::parse_with_size(member.data.len(), &mut &*member.data)?;
                    first_linker = Some(linker);
                }
                ArchiveMemberName::SecondLinker => {
                    let linker = SecondLinkerMember::parse_with_size(member.data.len(), &mut &*member.data)?;
                    second_linker = Some(linker);
                }
                ArchiveMemberName::Longnames => {
                    longnames = Some(LongnamesMember {
                        strings: member.data,
                    });
                }
                _ => {
                    members.push(member);
                }
            }

            // Archive members are 2-byte aligned
            if input.len() % 2 == 1 {
                let _pad = take(1usize).parse_next(input)?;
            }
        }

        Ok(CoffArchive {
            first_linker,
            second_linker,
            longnames,
            members,
        })
    }
}

impl<'a> Parse<'a> for ArchiveMember<'a> {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let header = ArchiveMemberHeader::parse.parse_next(input)?;
        let data = take(header.size as usize)
            .context(StrContext::Label("member data"))
            .parse_next(input)?;

        Ok(ArchiveMember {
            header,
            data: Cow::Borrowed(data),
        })
    }
}

impl<'a> Parse<'a> for ArchiveMemberHeader<'a> {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let name_bytes = take(16usize)
            .context(StrContext::Label("member name"))
            .parse_next(input)?;

        let name = if name_bytes == FIRST_LINKER {
            ArchiveMemberName::FirstLinker
        } else if name_bytes == SECOND_LINKER {
            ArchiveMemberName::SecondLinker
        } else if name_bytes == LONGNAMES_MEMBER {
            ArchiveMemberName::Longnames
        } else if name_bytes.starts_with(b"/") {
            // Long name - number after / is offset into longnames member
            let offset_str = std::str::from_utf8(&name_bytes[1..])
                .map_err(|_| ContextError::context("invalid long name offset", input, StrContext::Label("long name")))?
                .trim_end();
            let offset = offset_str.parse::<u32>()
                .map_err(|_| ContextError::context("invalid long name offset", input, StrContext::Label("long name")))?;
            ArchiveMemberName::LongName(offset)
        } else {
            // Regular name
            let len = name_bytes.iter().position(|&b| b == b'/' || b == b' ').unwrap_or(16);
            let name = std::str::from_utf8(&name_bytes[..len])
                .map_err(|_| ContextError::context("invalid member name", input, StrContext::Label("member name")))?;
            ArchiveMemberName::Name(Cow::Borrowed(name))
        };

        let date = take(12usize)
            .verify_map(|s: &[u8]| std::str::from_utf8(s).ok()?.trim().parse::<u32>().ok())
            .context(StrContext::Label("date"))
            .parse_next(input)?;

        let user_id = take(6usize)
            .verify_map(|s: &[u8]| std::str::from_utf8(s).ok()?.trim().parse::<u16>().ok())
            .context(StrContext::Label("user id"))
            .parse_next(input)?;

        let group_id = take(6usize)
            .verify_map(|s: &[u8]| std::str::from_utf8(s).ok()?.trim().parse::<u16>().ok())
            .context(StrContext::Label("group id"))
            .parse_next(input)?;

        let mode = take(8usize)
            .verify_map(|s: &[u8]| std::str::from_utf8(s).ok()?.trim().parse::<u32>().ok())
            .context(StrContext::Label("mode"))
            .parse_next(input)?;

        let size = take(10usize)
            .verify_map(|s: &[u8]| std::str::from_utf8(s).ok()?.trim().parse::<u32>().ok())
            .context(StrContext::Label("size"))
            .parse_next(input)?;

        // Check ending characters
        let end = take(2usize)
            .context(StrContext::Label("header end"))
            .parse_next(input)?;
        if end != b"`\n" {
            return Err(ContextError::context(
                "invalid header end",
                input,
                StrContext::Label("header end"),
            ));
        }

        Ok(ArchiveMemberHeader {
            name,
            date,
            user_id,
            group_id,
            mode,
            size,
        })
    }
}

impl<'a> FirstLinkerMember<'a> {
    fn parse_with_size(size: usize, input: &mut &'a [u8]) -> Result<Self, ContextError> {
        let num_symbols = le_u32
            .context(StrContext::Label("number of symbols"))
            .parse_next(input)?;

        let offsets = repeat(
            num_symbols as usize,
            le_u32.context(StrContext::Label("symbol offset")),
        )
        .parse_next(input)?;

        let mut symbols = Vec::with_capacity(num_symbols as usize);
        let mut string_data = *input;

        for offset in offsets {
            let name_end = string_data
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| ContextError::context("unterminated string", input, StrContext::Label("symbol name")))?;

            let name = std::str::from_utf8(&string_data[..name_end])
                .map_err(|_| ContextError::context("invalid symbol name", input, StrContext::Label("symbol name")))?;

            symbols.push((offset, Cow::Borrowed(name)));
            string_data = &string_data[name_end + 1..];
        }

        Ok(FirstLinkerMember { symbols })
    }
}

impl<'a> SecondLinkerMember<'a> {
    fn parse_with_size(size: usize, input: &mut &'a [u8]) -> Result<Self, ContextError> {
        let num_members = le_u32
            .context(StrContext::Label("number of members"))
            .parse_next(input)?;

        let member_offsets = repeat(
            num_members as usize,
            le_u32.context(StrContext::Label("member offset")),
        )
        .parse_next(input)?;

        let num_symbols = le_u32
            .context(StrContext::Label("number of symbols"))
            .parse_next(input)?;

        let indices = repeat(
            num_symbols as usize,
            le_u16.context(StrContext::Label("symbol index")),
        )
        .parse_next(input)?;

        let mut symbols = Vec::with_capacity(num_symbols as usize);
        let mut string_data = *input;

        for index in indices {
            let name_end = string_data
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| ContextError::context("unterminated string", input, StrContext::Label("symbol name")))?;

            let name = std::str::from_utf8(&string_data[..name_end])
                .map_err(|_| ContextError::context("invalid symbol name", input, StrContext::Label("symbol name")))?;

            symbols.push((index, Cow::Borrowed(name)));
            string_data = &string_data[name_end + 1..];
        }

        Ok(SecondLinkerMember {
            member_offsets,
            symbols,
        })
    }
}
