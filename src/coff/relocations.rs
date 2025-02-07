use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use winnow::{
    binary::{le_u16, le_u32},
    error::ContextError,
    prelude::*,
};

use crate::parse::Parse;

#[derive(Debug, Clone)]
pub struct CoffRelocation {
    pub virtual_address: u32,
    pub symbol_table_index: u32,
    pub relocation_type: RelocationType,
}

impl<'a> Parse<'a> for CoffRelocation {
    type Error = ContextError;

    fn parse(input: &mut &'a [u8]) -> Result<Self, Self::Error> {
        let virtual_address = le_u32.parse_next(input)?;
        let symbol_table_index = le_u32.parse_next(input)?;
        let type_raw = le_u16.parse_next(input)?;
        
        // Get machine type from context to determine relocation type enum
        // For now just parse as x64 relocations
        let relocation_type = X64RelocationType::from_u16(type_raw)
            .unwrap_or(X64RelocationType::Absolute);

        Ok(CoffRelocation {
            virtual_address,
            symbol_table_index,
            relocation_type: RelocationType::X64(relocation_type),
        })
    }
}

#[derive(Debug, Clone)]
pub enum RelocationType {
    X64(X64RelocationType),
    I386(I386RelocationType),
    // Add other architectures as needed:
    // ARM(ARMRelocationType),
    // etc.
}

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive)]
#[repr(u16)]
pub enum I386RelocationType {
    Absolute = 0x0000,
    Dir16 = 0x0001,
    Rel16 = 0x0002,
    Dir32 = 0x0006,
    Dir32NB = 0x0007,
    Seg12 = 0x0009,
    Section = 0x000A,
    SecRel = 0x000B,
    Token = 0x000C,
    SecRel7 = 0x000D,
    Rel32 = 0x0014,
}

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive)]
#[repr(u16)]
pub enum X64RelocationType {
    Absolute = 0x0000,
    Addr64 = 0x0001,
    Addr32 = 0x0002,
    Addr32NB = 0x0003,
    Rel32 = 0x0004,
    Rel32_1 = 0x0005,
    Rel32_2 = 0x0006,
    Rel32_3 = 0x0007,
    Rel32_4 = 0x0008,
    Rel32_5 = 0x0009,
    Section = 0x000A,
    SecRel = 0x000B,
    SecRel7 = 0x000C,
    Token = 0x000D,
    SRel32 = 0x000E,
    Pair = 0x000F,
    SSpan32 = 0x0010,
}
