use std::collections::BTreeMap;
use std::collections::HashMap;
use std::marker::PhantomData;

use bstr::BString;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use object::ObjectSymbolTable;
use object::ReadRef;
use object::elf;
use object::read::RelocationTarget as ObjectRelocationTarget;
use object::read::elf::FileHeader;
use object::read::elf::SectionHeader;

use crate::WordSize;
use crate::analysis::Analyze;

/// Relocations indexed by the address of the bytes they modify.
#[derive(Debug)]
pub struct Relocations<'data, Elf>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
{
    by_address: BTreeMap<Elf::Word, Vec<Relocation<Elf::Word>>>,
    _pd: PhantomData<&'data Elf>,
}

#[derive(Debug)]
pub struct Relocation<W: WordSize> {
    pub site: RelocationSite<W>,
    pub source: RelocationSource,
    pub target: RelocationTarget,
    pub object: object::Relocation,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RelocationSite<W: WordSize> {
    Section { name: BString, offset: W },
    VirtualAddress(W),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RelocationSource {
    Section { name: BString },
    Dynamic { table: DynamicRelocationTable },
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DynamicRelocationTable {
    General,
    Plt,
    Relative,
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RelocationTarget {
    Symbol {
        table: SymbolTableProvenance,
        index: usize,
        name: Option<BString>,
    },
    Section {
        index: usize,
        name: Option<BString>,
    },
    Absolute,
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SymbolTableProvenance {
    Static,
    Dynamic,
}

impl<'data, Elf> Relocations<'data, Elf>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
{
    pub fn at_address(&self, address: Elf::Word) -> Option<&[Relocation<Elf::Word>]> {
        self.by_address.get(&address).map(Vec::as_slice)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Relocation<Elf::Word>> {
        self.by_address.values().flatten()
    }
}

impl<'data, Elf, R> Analyze<'data, Elf, R>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
    R: ReadRef<'data>,
{
    pub fn relocations(&self) -> &Relocations<'_, Elf> {
        self.relocations.get_or_init(|| {
            let mut by_address = BTreeMap::<Elf::Word, Vec<Relocation<Elf::Word>>>::new();
            let relocation_sections = self.relocation_sections_by_site();

            for section in self.elf.sections() {
                let site_name = section.name_bytes().map(BString::from).unwrap_or_default();
                let mut sources = relocation_sections
                    .get(&section.index().0)
                    .into_iter()
                    .flatten();

                for (offset, object) in section.relocations() {
                    let Some(address) = section
                        .address()
                        .checked_add(offset)
                        .and_then(Elf::Word::from_u64)
                    else {
                        continue;
                    };
                    let Some(offset) = Elf::Word::from_u64(offset) else {
                        continue;
                    };

                    let target = self.static_target(object.target());
                    by_address.entry(address).or_default().push(Relocation {
                        site: RelocationSite::Section {
                            name: site_name.clone(),
                            offset,
                        },
                        source: sources
                            .next()
                            .cloned()
                            .map(|name| RelocationSource::Section { name })
                            .unwrap_or(RelocationSource::Unknown),
                        target,
                        object,
                    });
                }
            }

            let mut tables = self.dynamic_relocation_tables().into_iter();
            if let Some(relocations) = self.elf.dynamic_relocations() {
                for (address, object) in relocations {
                    let Some(address) = Elf::Word::from_u64(address) else {
                        continue;
                    };
                    let target = self.dynamic_target(object.target());
                    let table = tables.next().unwrap_or(DynamicRelocationTable::Unknown);

                    by_address.entry(address).or_default().push(Relocation {
                        site: RelocationSite::VirtualAddress(address),
                        source: RelocationSource::Dynamic { table },
                        target,
                        object,
                    });
                }
            }

            Relocations {
                by_address,
                _pd: PhantomData,
            }
        })
    }

    fn relocation_sections_by_site(&self) -> HashMap<usize, Vec<BString>> {
        let sections = self.elf.elf_section_table();
        let endian = self.elf.endian();
        let mut by_site = HashMap::<usize, Vec<BString>>::new();

        for (_, header) in sections.enumerate() {
            if matches!(header.sh_type(endian), elf::SHT_REL | elf::SHT_RELA)
                && header.sh_info(endian) != 0
                && let Ok(name) = sections.section_name(endian, header)
            {
                let entry_size: u64 = header.sh_entsize(endian).into();
                if entry_size == 0 {
                    continue;
                }
                let count = header.sh_size(endian).into() / entry_size;
                by_site
                    .entry(header.sh_info(endian) as usize)
                    .or_default()
                    .extend((0..count).map(|_| name.into()));
            }
        }
        by_site
    }

    fn dynamic_relocation_tables(&self) -> Vec<DynamicRelocationTable> {
        let sections = self.elf.elf_section_table();
        let endian = self.elf.endian();
        let mut tables = Vec::new();
        let dynamic_symbols = self.elf.elf_dynamic_symbol_table().section();

        for (_, header) in sections.enumerate() {
            if !matches!(header.sh_type(endian), elf::SHT_REL | elf::SHT_RELA)
                || header.link(endian) != dynamic_symbols
            {
                continue;
            }
            let entry_size: u64 = header.sh_entsize(endian).into();
            if entry_size == 0 {
                continue;
            }
            let count = header.sh_size(endian).into() / entry_size;
            let name = sections.section_name(endian, header).unwrap_or_default();
            let classify = || {
                if name.ends_with(b".plt") {
                    DynamicRelocationTable::Plt
                } else {
                    DynamicRelocationTable::General
                }
            };
            tables.extend((0..count).map(|_| classify()));
        }
        tables
    }

    fn static_target(&self, target: ObjectRelocationTarget) -> RelocationTarget {
        match target {
            ObjectRelocationTarget::Symbol(index) => RelocationTarget::Symbol {
                table: SymbolTableProvenance::Static,
                index: index.0,
                name: self
                    .elf
                    .symbol_by_index(index)
                    .ok()
                    .and_then(|symbol| symbol.name_bytes().ok())
                    .filter(|name| !name.is_empty())
                    .map(BString::from),
            },
            ObjectRelocationTarget::Section(index) => RelocationTarget::Section {
                index: index.0,
                name: self
                    .elf
                    .section_by_index(index)
                    .ok()
                    .and_then(|section| section.name_bytes().ok())
                    .filter(|name| !name.is_empty())
                    .map(BString::from),
            },
            ObjectRelocationTarget::Absolute => RelocationTarget::Absolute,
            _ => RelocationTarget::Unknown,
        }
    }

    fn dynamic_target(&self, target: ObjectRelocationTarget) -> RelocationTarget {
        match target {
            ObjectRelocationTarget::Symbol(index) => RelocationTarget::Symbol {
                table: SymbolTableProvenance::Dynamic,
                index: index.0,
                name: self
                    .elf
                    .dynamic_symbol_table()
                    .and_then(|symbols| symbols.symbol_by_index(index).ok())
                    .and_then(|symbol| symbol.name_bytes().ok())
                    .filter(|name| !name.is_empty())
                    .map(BString::from),
            },
            ObjectRelocationTarget::Section(index) => RelocationTarget::Section {
                index: index.0,
                name: self
                    .elf
                    .section_by_index(index)
                    .ok()
                    .and_then(|section| section.name_bytes().ok())
                    .filter(|name| !name.is_empty())
                    .map(BString::from),
            },
            ObjectRelocationTarget::Absolute => RelocationTarget::Absolute,
            _ => RelocationTarget::Unknown,
        }
    }
}
