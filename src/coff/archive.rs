use std::borrow::Cow;
use std::str::FromStr;

use winnow::{
    ascii::digit1,
    binary::{be_u32, le_u16, le_u32},
    combinator::{alt, empty, opt, preceded, repeat},
    error::{ContextError, StrContext},
    prelude::*,
    token::{take, take_until},
};

use crate::parse::Parse;

const ARCHIVE_MAGIC: &[u8] = b"!<arch>\n";
const LINKER_MEMBER: &[u8] = b"/               ";
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
    pub data: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct ArchiveMemberHeader<'a> {
    pub name: ArchiveMemberName<'a>,
    pub date: i64,
    pub user_id: Option<u16>,
    pub group_id: Option<u16>,
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
    Linker,
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
    pub strings: &'a [u8],
}

impl<'a> Parse<'a> for CoffArchive<'a> {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let all_data = *input;

        // Check magic
        ARCHIVE_MAGIC
            .context(StrContext::Label("archive magic"))
            .parse_next(input)?;

        let mut members = Vec::new();
        let mut first_linker = None;
        let mut second_linker = None;
        let mut longnames = None;

        while !input.is_empty() {
            let mut member: ArchiveMember<'a> = ArchiveMember::parse
                .context(StrContext::Label("archive member"))
                .parse_next(input)?;

            match &member.header.name {
                ArchiveMemberName::Linker => {
                    if first_linker.is_none() {
                        first_linker = Some(
                            FirstLinkerMember::parse
                                .context(StrContext::Label("first linker member"))
                                .parse_next(&mut member.data)?,
                        );
                    } else {
                        second_linker = Some(
                            SecondLinkerMember::parse
                                .context(StrContext::Label("first linker member"))
                                .parse_next(&mut member.data)?,
                        );
                    }
                }
                ArchiveMemberName::Longnames => {
                    longnames = Some(LongnamesMember {
                        strings: member.data,
                    });
                }
                _ => members.push(member),
            }

            // Archive members are 2-byte aligned
            if input.len() % 2 == 1 {
                take(1usize).parse_next(input)?;
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
        let header = ArchiveMemberHeader::parse
            .context(StrContext::Label("archive member header"))
            .parse_next(input)?;
        let data = take(header.size as usize)
            .context(StrContext::Label("member data"))
            .parse_next(input)?;

        Ok(ArchiveMember { header, data })
    }
}

impl<'a> Parse<'a> for ArchiveMemberHeader<'a> {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let mut name_bytes = take(16usize)
            .context(StrContext::Label("member name"))
            .parse_next(input)?;

        let name = alt((
            LINKER_MEMBER.map(|_| ArchiveMemberName::Linker),
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
            .try_map(i64::from_str)
            .context(StrContext::Label("date"))
            .parse_next(input)?;

        let user_id = take(6usize)
            .try_map(std::str::from_utf8)
            .map(str::trim)
            .and_then(opt(digit1.try_map(u16::from_str)))
            .context(StrContext::Label("user id"))
            .parse_next(input)?;

        let group_id = take(6usize)
            .try_map(std::str::from_utf8)
            .map(str::trim)
            .and_then(opt(digit1.try_map(u16::from_str)))
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

impl<'a> Parse<'a> for FirstLinkerMember<'a> {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, ContextError> {
        let num_symbols = be_u32
            .context(StrContext::Label("symbol count"))
            .parse_next(input)?;

        let offsets: Vec<u32> = repeat(num_symbols as usize, be_u32)
            .context(StrContext::Label("symbol offsets"))
            .parse_next(input)?;
        let mut symbols = Vec::with_capacity(num_symbols as usize);

        for offset in offsets {
            let name = take_until(0.., 0)
                .try_map(std::str::from_utf8)
                .context(StrContext::Label("symbol name"))
                .parse_next(input)?;

            symbols.push((offset, Cow::Borrowed(name)));
        }

        Ok(FirstLinkerMember { symbols })
    }
}

impl<'a> Parse<'a> for SecondLinkerMember<'a> {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, ContextError> {
        let num_members = le_u32.parse_next(input)?;
        let member_offsets = repeat(num_members as usize, le_u32).parse_next(input)?;

        let num_symbols = le_u32.parse_next(input)?;
        let indices: Vec<u16> = repeat(num_symbols as usize, le_u16).parse_next(input)?;

        let mut symbols = Vec::with_capacity(num_symbols as usize);

        for index in indices {
            let name = take_until(0.., 0)
                .try_map(std::str::from_utf8)
                .context(StrContext::Label("symbol name"))
                .parse_next(input)?;

            symbols.push((index, Cow::Borrowed(name)));
        }

        Ok(SecondLinkerMember {
            member_offsets,
            symbols,
        })
    }
}
