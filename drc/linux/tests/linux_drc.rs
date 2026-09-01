use dustbin_drc_linux::LinuxDrc;
use dustbin_elf::analysis::*;
use dustbin_elf_tests::*;

#[test]
fn bash_passes_drc() -> anyhow::Result<()> {
    let a = Analyze64Le::begin(linux_bash_x86_64)?;
    let drc = LinuxDrc::new(a);

    drc.run();

    Ok(())
}
