//! [`Analyze`] is the central data structure of this module.
//!
//! ## Small example
//! ```no_run
//! use dustbin_elf::analysis::Analyze64Le;
//!
//! let a = Analyze64Le::begin(dustbin_elf_tests::linux_bash_x86_64).unwrap();
//! let main = a.function_definitions().lookup(b"main").unwrap();
//! assert_eq!(main.address, 0x2ae0);
//! ```

pub mod dynamic;
pub mod reloc;
pub mod special;
pub mod text;

use std::sync::Arc;
use std::sync::OnceLock;

use object::LittleEndian;
use object::ReadRef;
use object::elf::FileHeader32;
use object::elf::FileHeader64;
use object::read::elf::ElfFile;
use object::read::elf::FileHeader;

use crate::WordSize;
use crate::diag::Diagnostics;

pub type Analyze64Le<'data, R> = Analyze<'data, FileHeader64<LittleEndian>, R>;
pub type Analyze32Le<'data, R> = Analyze<'data, FileHeader32<LittleEndian>, R>;

#[derive(derive_more::Debug, Clone)]
pub struct Analyze<'data, Elf, R = &'data [u8]>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
    R: ReadRef<'data>,
{
    #[debug(skip)]
    elf: Arc<ElfFile<'data, Elf, R>>,

    diagnostics: Diagnostics,
    relocations: Arc<OnceLock<reloc::Relocations<'data, Elf>>>,
    functions: Arc<OnceLock<text::Functions<'data, Elf>>>,
    stated_dynamic_linking: Arc<OnceLock<dynamic::StatedDynamicLinking<'data, Elf>>>,
    lifecycle_sections: Arc<OnceLock<special::LifecycleSections<Elf>>>,
}

impl<'data, Elf, R> Analyze<'data, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    Elf::Word: WordSize,
{
    pub fn new(elf: ElfFile<'data, Elf, R>) -> Self {
        Self {
            elf: Arc::new(elf),
            diagnostics: Diagnostics::new(),
            relocations: Default::default(),
            functions: Default::default(),
            stated_dynamic_linking: Default::default(),
            lifecycle_sections: Default::default(),
        }
    }

    pub fn begin(data: R) -> object::read::Result<Self> {
        Ok(Self::new(ElfFile::parse(data)?))
    }
}

mod checks {
    use super::*;
    static_assertions::assert_impl_all!(Analyze<'static, FileHeader64<LittleEndian>, &'static [u8]>: Send, Sync);
    static_assertions::assert_impl_all!(Analyze<'static, FileHeader32<LittleEndian>, &'static [u8]>: Send, Sync);
}
