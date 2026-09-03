pub mod analysis;
pub mod diag;

/// A 64-bit little-endian ELF file.
/// [object::read::elf::ElfFile64] with the endianness and word size
/// pre-populated.
pub type Elf64Le<'data, T> = object::read::elf::ElfFile64<'data, object::LittleEndian, T>;

/// A 32-bit little-endian ELF file.
/// [object::read::elf::ElfFile32] with the endianness and word size
/// pre-populated.
pub type Elf32Le<'data, T> = object::read::elf::ElfFile32<'data, object::LittleEndian, T>;

macro_rules! decl_word_size {
    ($($ty:ty),*) => {$(
        impl WordSize for $ty {
            const ZERO: Self = 0;
            const MAX: Self = <$ty>::MAX;

            fn from_bytes(bytes: &[u8], is_le: bool) -> Self {
                let bytes = bytes.try_into().unwrap();
                if is_le {
                    <$ty>::from_le_bytes(bytes)
                } else {
                    <$ty>::from_be_bytes(bytes)
                }
            }

            fn as_u64(&self) -> u64 {
                (*self).into()
            }

            fn from_u64(value: u64) -> Option<Self> {
                value.try_into().ok()
            }
        }
    )*};
}

decl_word_size!(u32, u64);

pub trait WordSize: Copy + Eq + Ord + std::fmt::LowerHex {
    const ZERO: Self;
    const MAX: Self;

    fn from_bytes(bytes: &[u8], is_le: bool) -> Self;

    fn as_u64(&self) -> u64;

    fn from_u64(value: u64) -> Option<Self>;
}
