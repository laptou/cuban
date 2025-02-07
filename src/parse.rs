#[derive(Debug, Clone)]
pub struct Lazy<'a, T> {
    data: &'a [u8],
    _phantom: std::marker::PhantomData<T>,
}

impl<'a, T> Lazy<'a, T> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, T: Parse<'a>> Lazy<'a, T> {
    pub fn parse(&self) -> Result<T, T::Error> {
        let mut data = self.data;
        let input = &mut data;
        T::parse(input)
    }
}

pub trait Parse<'a>: Sized {
    type Error: 'a;

    fn parse(data: &mut &'a [u8]) -> Result<Self, Self::Error>;
}

pub trait Write {
    type Error;
    fn write(&self, out: &mut [u8]) -> Result<(), Self::Error>;
}

pub trait Layout {
    /// Updates any internal pointers and lengths, then returns the total size in bytes
    /// Updates any internal pointers and lengths, then returns the total size in bytes
    fn fix_layout(&mut self) -> u32 {
        self.total_size()
    }

    /// Returns the total size in bytes that this component will occupy
    fn total_size(&self) -> u32;
}
