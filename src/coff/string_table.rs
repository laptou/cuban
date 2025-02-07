use std::fmt::Debug;

use bytes::BufMut;
use winnow::{
    binary::le_u32,
    error::{ContextError, StrContext},
    prelude::*,
    token::take,
};

use crate::{
    parse::{Parse, Write},
    util::fmt::ByteStr,
};

#[derive(Clone)]
pub struct StringTable<'a> {
    data: &'a [u8],
}

impl<'a> std::fmt::Debug for StringTable<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct StringTableDebug<'a> {
            data: &'a [u8],
        }

        impl Debug for StringTableDebug<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let mut list = f.debug_list();

                for s in self.data.split(|&c| c == 0) {
                    list.entry(&ByteStr(s));
                }

                list.finish()?;
                Ok(())
            }
        }

        f.debug_struct("StringTable")
            .field("len", &self.data.len())
            .field("strings", &StringTableDebug { data: self.data })
            .finish()
    }
}

impl<'a> StringTable<'a> {
    pub fn get(&self, offset: u32) -> Option<&'a str> {
        if offset as usize >= self.data.len() {
            return None;
        }

        let str_bytes = &self.data[offset as usize..];
        let len = str_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(str_bytes.len());

        std::str::from_utf8(&str_bytes[..len]).ok()
    }
}

impl<'a> Write for StringTable<'a> {
    type Error = std::io::Error;

    fn write(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        // Write total size including the size field itself
        let total_size = (self.data.len() + 4) as u32;
        out.put_u32_le(total_size);
        
        // Write string table data
        out.put_slice(self.data);
        
        Ok(())
    }
}

impl<'a> Parse<'a> for StringTable<'a> {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let total_size = le_u32
            .context(StrContext::Label("string table size"))
            .parse_next(input)?;

        if total_size < 4 {
            return Ok(StringTable { data: &[] });
        }

        let data = take(total_size as usize - 4)
            .context(StrContext::Label("string table data"))
            .parse_next(input)?;

        Ok(StringTable { data })
    }
}
