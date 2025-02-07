use std::borrow::Cow;
use std::str::FromStr;

use bytes::BufMut;
use winnow::{
    ascii::digit1,
    binary::{le_u16, le_u32},
    combinator::{self, alt, preceded, repeat},
    error::{ContextError, StrContext},
    prelude::*,
    token::{one_of, take, take_until},
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
                    let linker =
                        FirstLinkerMember::parse_with_size(member.data.len(), &mut &*member.data)?;
                    first_linker = Some(linker);
                }
                ArchiveMemberName::SecondLinker => {
                    let linker =
                        SecondLinkerMember::parse_with_size(member.data.len(), &mut &*member.data)?;
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
        let mut name_bytes = take(16usize)
            .context(StrContext::Label("member name"))
            .parse_next(input)?;

        let name = alt((
            FIRST_LINKER_MEMBER.map(|_| ArchiveMemberName::FirstLinker),
            SECOND_LINKER_MEMBER.map(|_| ArchiveMemberName::SecondLinker),
            LONGNAMES_MEMBER.map(|_| ArchiveMemberName::Longnames),
            preceded(b"/", digit1)
                .try_map(std::str::from_utf8)
                .try_map(u32::from_str)
                .map(ArchiveMemberName::LongName),
            take_until(..16, b'/')
                .try_map(std::str::from_utf8)
                .map(Cow::Borrowed)
                .map(ArchiveMemberName::Name),
        ))
        .parse_next(&mut name_bytes)?;

        let date = take(12usize)
            .try_map(std::str::from_utf8)
            .map(str::trim)
            .try_map(u32::from_str)
            .context(StrContext::Label("date"))
            .parse_next(input)?;

        let user_id = take(6usize)
            .try_map(std::str::from_utf8)
            .map(str::trim)
            .try_map(u16::from_str)
            .context(StrContext::Label("user id"))
            .parse_next(input)?;

        let group_id = take(6usize)
            .try_map(std::str::from_utf8)
            .map(str::trim)
            .try_map(u16::from_str)
            .context(StrContext::Label("group id"))
            .parse_next(input)?;

        let mode = take(8usize)
            .try_map(std::str::from_utf8)
            .map(str::trim)
            .try_map(u32::from_str)
            .context(StrContext::Label("mode"))
            .parse_next(input)?;

        let size = take(10usize)
            .try_map(std::str::from_utf8)
            .map(str::trim)
            .try_map(u32::from_str)
            .context(StrContext::Label("size"))
            .parse_next(input)?;

        // Check ending characters
        let end = b"`\n"
            .context(StrContext::Label("header end"))
            .parse_next(input)?;

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
            let name_end = string_data.iter().position(|&b| b == 0).ok_or_else(|| {
                ContextError::context(
                    "unterminated string",
                    input,
                    StrContext::Label("symbol name"),
                )
            })?;

            let name = std::str::from_utf8(&string_data[..name_end]).map_err(|_| {
                ContextError::context(
                    "invalid symbol name",
                    input,
                    StrContext::Label("symbol name"),
                )
            })?;

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
            let name_end = string_data.iter().position(|&b| b == 0).ok_or_else(|| {
                ContextError::context(
                    "unterminated string",
                    input,
                    StrContext::Label("symbol name"),
                )
            })?;

            let name = std::str::from_utf8(&string_data[..name_end]).map_err(|_| {
                ContextError::context(
                    "invalid symbol name",
                    input,
                    StrContext::Label("symbol name"),
                )
            })?;

            symbols.push((index, Cow::Borrowed(name)));
            string_data = &string_data[name_end + 1..];
        }

        Ok(SecondLinkerMember {
            member_offsets,
            symbols,
        })
    }
}
