use std::marker::PhantomData;

use bstr::BStr;
use object::ReadRef;
use object::read::elf::Dyn;
use object::read::elf::FileHeader;
use object::read::elf::ProgramHeader;

use crate::WordSize;
use crate::analysis::Analyze;
use crate::diag::Informational;

/// Information pertinent to dynamic linking, as stated in the binary.
#[derive(Debug)]
pub struct StatedDynamicLinking<'data, Elf>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
{
    pub interpreter: Option<&'data BStr>,

    pub rpath: Option<&'data BStr>,

    pub runpath: Option<&'data BStr>,

    pub needed_libs: Vec<NeededLibrary<'data>>,

    _pd: PhantomData<Elf>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct NeededLibrary<'data>(pub &'data BStr);

impl<'data, Elf, R> Analyze<'data, Elf, R>
where
    Elf: FileHeader,
    Elf::Word: WordSize,
    R: ReadRef<'data>,
{
    pub fn dynamic_linking(&self) -> &StatedDynamicLinking<'_, Elf> {
        self.stated_dynamic_linking.get_or_init(|| {
            let mut sdl = StatedDynamicLinking {
                interpreter: None,
                rpath: None,
                runpath: None,
                needed_libs: vec![],
                _pd: PhantomData,
            };

            if let Ok(Some((dt_entries, str_tbl_idx))) = self
                .elf
                .elf_section_table()
                .dynamic(self.elf.endian(), self.elf.data())
                && let Ok(st) = self.elf.elf_section_table().strings(
                    self.elf.endian(),
                    self.elf.data(),
                    str_tbl_idx,
                )
            {
                for dt in dt_entries {
                    if let Ok(name) = dt.string(self.elf.endian(), st) {
                        match dt.tag(self.elf.endian()) {
                            object::elf::DT_NEEDED => {
                                sdl.needed_libs.push(NeededLibrary(name.into()));
                            }
                            object::elf::DT_RPATH => {
                                sdl.rpath = Some(name.into());
                            }
                            object::elf::DT_RUNPATH => {
                                sdl.runpath = Some(name.into());
                            }
                            _ => {}
                        }
                    }

                    if dt.tag(self.elf.endian()) == object::elf::DT_INIT {}
                }
            } else {
                self.diagnostics.info(Informational::NoDynamicSections);
            }

            for hdr in self.elf.elf_program_headers() {
                if let Ok(Some(int)) = hdr.interpreter(self.elf.endian(), self.elf.data()) {
                    sdl.interpreter = Some(int.into());
                }
            }

            if sdl.interpreter.is_none() {
                self.diagnostics.info(Informational::MissingInterpreter);
            }

            sdl
        })
    }
}
