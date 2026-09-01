use dustbin_elf::WordSize;
use dustbin_elf::analysis::Analyze;
use object::ReadRef;
use object::read::elf::FileHeader;

pub struct LinuxDrc<'data, Elf, R = &'data [u8]>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
    R: ReadRef<'data>,
{
    analysis: Analyze<'data, Elf, R>,
}

impl<'data, Elf, R> LinuxDrc<'data, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    Elf::Word: WordSize,
{
}
