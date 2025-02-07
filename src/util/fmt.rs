use std::fmt::Debug;

pub fn byte_str_format(
    f: &mut std::fmt::Formatter<'_>,
    inner: &[u8],
) -> Result<(), std::fmt::Error> {
    for &byte in inner {
        if byte.is_ascii_graphic() || byte == b' ' {
            write!(f, "{}", byte as char)?;
        } else {
            write!(f, "\\x{:x}", byte)?;
        }
    }

    Ok(())
}

pub struct ByteStr<'a>(pub &'a [u8]);

impl Debug for ByteStr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"")?;
        byte_str_format(f, self.0)?;
        write!(f, "\"")?;
        Ok(())
    }
}
