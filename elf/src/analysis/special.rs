use std::collections::HashMap;

use bstr::BString;
use object::Object;
use object::ReadRef;
use object::SectionIndex;
use object::elf::SHT_FINI_ARRAY;
use object::elf::SHT_INIT_ARRAY;
use object::elf::SHT_PROGBITS;
use object::elf::STT_SECTION;
use object::read::ObjectSection;
use object::read::RelocationTarget;
use object::read::elf::FileHeader;
use object::read::elf::SectionHeader;
use object::read::elf::Sym;
use thiserror::Error;

use crate::WordSize;
use crate::analysis::Analyze;
use crate::analysis::reloc::RelocationSource;
use crate::analysis::reloc::RelocationTarget as IndexedRelocationTarget;
use crate::diag::Defect;
use crate::diag::Suspect;

#[derive(derive_more::Debug)]
pub struct LifecycleSections<Elf>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
{
    pub lifecycle_sections: HashMap<BString, Vec<LifecycleEntry<Elf::Word>>>,
}

/// A view over the contents in the sections conventionally called .ctors,
/// .dtors, .init_array, and .fini_array. These hold function pointers and
/// start-of/end-of list markers, or zeros, if anticipating relocations.
/// Normally these sections are designated as such by metadata in the dynamic
/// section (e.g. DT_INIT_ARRAY), but some toolchains rely on the naming
/// convention to find them.
///
/// Unfortunately, we must be somewhat liberal in what we accept as valid
/// contents for the lifecycle sections, as some toolchains are less strict than
/// others.
#[derive(derive_more::Debug)]
pub struct LifecycleSectionContents<Elf>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
{
    pub entries: Vec<LifecycleEntry<Elf::Word>>,
}

/// Every lifecycle section is an array of word-sized values.
/// We categorize them and tack on metadata from other sections where it adds
/// value.
#[derive(derive_more::Debug, PartialEq, Eq)]
pub enum LifecycleEntry<W>
where
    W: WordSize,
{
    Marker(W),

    Unclassified(W),

    RelocationSlot,

    RelocateToSymbol {
        addend: i64,
        symbol: BString,
    },

    RelocateToFinalLocationOfSection {
        section: BString,
        offset: i64,
    },

    FunctionPointer {
        name: BString,

        #[debug("{address:#x}")]
        address: W,
    },
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MalformedSpecialSection {
    #[error("section {0} declared but missing")]
    MissingSection(BString),

    #[error("section {section} is present but has invalid size {size}")]
    InvalidSectionSize { section: BString, size: usize },

    #[error("cannot read section {0}")]
    CannotReadSection(BString, #[source] object::Error),

    #[error("cannot read from elf")]
    CannotReadElf(#[from] object::Error),
}

impl<'data, Elf, R> Analyze<'data, Elf, R>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
    R: ReadRef<'data>,
{
    pub fn describe_lifecycle_sections(&self) -> &LifecycleSections<Elf> {
        self.lifecycle_sections.get_or_init(|| {
            let mut lifecycle_sections = HashMap::new();

            for sec in self.elf.sections() {
                if let Ok(name) = sec.name_bytes() {
                    for (prefix, anticipated_section_type) in [
                        (".ctors", SHT_PROGBITS),
                        (".dtors", SHT_PROGBITS),
                        (".init_array", SHT_INIT_ARRAY),
                        (".fini_array", SHT_FINI_ARRAY),
                    ] {
                        let prefix = prefix.as_bytes();
                        if name.starts_with(prefix) {
                            match self.read_lifecycle_section(name) {
                                Ok(lc) => {
                                    lifecycle_sections.insert(BString::from(name), lc.entries);
                                }
                                Err(e) => {
                                    self.diagnostics.defect(Defect::MalformedSpecialSection(e));
                                }
                            }

                            let actual_section_type =
                                sec.elf_section_header().sh_type(self.elf.endian());

                            if actual_section_type != anticipated_section_type {
                                self.diagnostics
                                    .suspect(Suspect::UnexpectedSpecialSectionType {
                                        section: BString::from(name),
                                        expected_type: anticipated_section_type,
                                        actual_type: actual_section_type,
                                    });
                            }
                        }
                    }
                }
            }

            LifecycleSections { lifecycle_sections }
        })
    }

    fn read_lifecycle_section(
        &self,
        name: &[u8],
    ) -> Result<LifecycleSectionContents<Elf>, MalformedSpecialSection> {
        let n2s = || BString::from(name);

        let section = self
            .elf
            .section_by_name_bytes(name)
            .ok_or(MalformedSpecialSection::MissingSection(n2s()))?;

        let section_contents = section
            .data()
            .map_err(|e| MalformedSpecialSection::CannotReadSection(n2s(), e))?;

        let stride = std::mem::size_of::<Elf::Word>();

        if section_contents.len() % stride != 0 {
            return Err(MalformedSpecialSection::InvalidSectionSize {
                section: n2s(),
                size: section_contents.len(),
            });
        }

        let entries = section_contents
            .chunks_exact(stride)
            .enumerate()
            .map(|(i, c)| {
                let octetwise_offset = (i * stride) as u64;

                let as_word = Elf::Word::from_bytes(c, self.elf.is_little_endian());
                let indexed_relocations = section
                    .address()
                    .checked_add(octetwise_offset)
                    .and_then(Elf::Word::from_u64)
                    .and_then(|address| self.relocations().at_address(address));

                if let Some((_n, r)) = section
                    .relocations()
                    .find(|(offset, _)| *offset == octetwise_offset)
                {
                    if let RelocationTarget::Symbol(idx) = r.target() {
                        let sym = self.elf.symbol_by_index(idx)?;
                        let sym = sym.elf_symbol();

                        if sym.st_type() == STT_SECTION {
                            let sections = self.elf.elf_section_table();
                            let shndx = sym.st_shndx(self.elf.endian());
                            let header = sections.section(SectionIndex(shndx as usize))?;
                            Ok(LifecycleEntry::RelocateToFinalLocationOfSection {
                                section: sections.section_name(self.elf.endian(), header)?.into(),
                                offset: r.addend(),
                            })
                        } else {
                            let symbol = self
                                .elf
                                .elf_symbol_table()
                                .symbol_name(self.elf.endian(), sym)?;

                            Ok(LifecycleEntry::RelocateToSymbol {
                                symbol: symbol.into(),
                                addend: r.addend(),
                            })
                        }
                    } else {
                        Ok(LifecycleEntry::RelocationSlot)
                    }
                } else if let Some(r) = indexed_relocations.and_then(|relocations| {
                    relocations
                        .iter()
                        .find(|r| matches!(r.source, RelocationSource::Dynamic { .. }))
                }) {
                    match &r.target {
                        IndexedRelocationTarget::Symbol {
                            name: Some(symbol), ..
                        } => Ok(LifecycleEntry::RelocateToSymbol {
                            symbol: symbol.clone(),
                            addend: r.object.addend(),
                        }),
                        IndexedRelocationTarget::Section {
                            name: Some(section),
                            ..
                        } => Ok(LifecycleEntry::RelocateToFinalLocationOfSection {
                            section: section.clone(),
                            offset: r.object.addend(),
                        }),
                        _ => Ok(LifecycleEntry::RelocationSlot),
                    }
                } else if let Some(func_defn) = self.function_definitions().get(as_word)
                    && func_defn.address.into() != 0
                {
                    Ok(LifecycleEntry::FunctionPointer {
                        name: func_defn.name.into(),
                        address: func_defn.address,
                    })
                } else {
                    Ok(LifecycleEntry::new(as_word))
                }
            })
            .collect::<object::Result<_>>()?;

        Ok(LifecycleSectionContents { entries })
    }
}

impl<W> LifecycleEntry<W>
where
    W: WordSize,
{
    pub fn new(v: W) -> Self {
        if v.as_u64() == u64::MAX {
            Self::Marker(v)
        } else {
            Self::Unclassified(v)
        }
    }
}
