use bstr::BStr;
use object::Object;
use object::ObjectSymbol;
use object::ReadRef;
use object::SymbolKind;
use object::read::elf::FileHeader;
use object::read::elf::SectionHeader;
use object::read::elf::Sym;

use crate::WordSize;
use crate::analysis::Analyze;

#[derive(derive_more::Debug)]
pub struct FuncDefn<'data, Elf>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
{
    pub name: &'data BStr,

    #[debug("{address:#x}")]
    pub address: Elf::Word,

    #[debug(skip)]
    pub text: &'data [u8],
}

#[derive(derive_more::Debug)]
pub struct Functions<'data, Elf>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
{
    defns: Vec<FuncDefn<'data, Elf>>,
}

impl<'data, Elf> Functions<'data, Elf>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
{
    pub fn iter(&self) -> impl Iterator<Item = &FuncDefn<'data, Elf>> {
        self.defns.iter()
    }

    pub fn lookup(&self, name: &[u8]) -> Option<&FuncDefn<'data, Elf>> {
        self.iter().find(|x| x.name == name)
    }

    pub fn get(&self, address: Elf::Word) -> Option<&FuncDefn<'data, Elf>> {
        self.iter().find(|x| x.address == address)
    }
}

impl<'data, Elf, R> Analyze<'data, Elf, R>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
    R: ReadRef<'data>,
{
    pub fn function_definitions(&self) -> &Functions<'data, Elf> {
        self.functions.get_or_init(|| {
            let iter = self
                .elf
                .dynamic_symbols()
                .chain(self.elf.symbols())
                .filter(|s| s.kind() == SymbolKind::Text && s.is_definition())
                .filter_map(|sym| {
                    let sec = self
                        .elf
                        .elf_section_table()
                        .section(sym.section_index()?)
                        .ok()?;

                    let offset_of_sec = sec.sh_offset(self.elf.endian());

                    let sec_base_addr = sec.sh_addr(self.elf.endian());

                    let offset = sym.address() - sec_base_addr.into();

                    let base = offset_of_sec.into() + offset;

                    Some(FuncDefn {
                        address: sym.elf_symbol().st_value(self.elf.endian()),
                        name: sym.name_bytes().ok()?.into(),
                        text: self
                            .elf
                            .data()
                            .read_slice_at(base, sym.size() as usize)
                            .ok()?,
                    })
                });

            Functions {
                defns: iter.collect(),
            }
        })
    }
}

pub mod x86 {
    use std::marker::PhantomData;

    use iced_x86::Decoder;
    use iced_x86::DecoderOptions;
    use iced_x86::Formatter;
    use iced_x86::GasFormatter;
    use iced_x86::Instruction;
    use object::read::elf::FileHeader;
    use thiserror::Error;

    use super::FuncDefn;

    #[derive(Debug)]
    pub struct DecodedFuncDefn<Elf>
    where
        Elf: FileHeader,
    {
        pub ins: Vec<Instruction>,

        _pd: PhantomData<Elf>,
    }

    #[derive(Debug, Error)]
    pub enum FuncDecodeError {}

    impl<Elf> DecodedFuncDefn<Elf>
    where
        Elf: FileHeader,
        Elf::Word: crate::WordSize,
    {
        pub fn decode(defn: &FuncDefn<'_, Elf>) -> Result<Self, FuncDecodeError> {
            let bitness = if Elf::is_type_64_sized() { 64 } else { 32 };

            let mut ins = vec![];

            let mut decoder = Decoder::new(bitness, defn.text, DecoderOptions::NONE);

            while decoder.can_decode() {
                ins.push(decoder.decode());
            }

            Ok(Self {
                ins,
                _pd: PhantomData,
            })
        }
    }

    impl<Elf> std::fmt::Display for DecodedFuncDefn<Elf>
    where
        Elf: FileHeader,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut formatter = GasFormatter::new();

            for inst in self.ins.iter() {
                let mut line = String::new();
                formatter.format(inst, &mut line);
                writeln!(f, "{}", line)?;
            }

            Ok(())
        }
    }
}
