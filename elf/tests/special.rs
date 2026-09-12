use bstr::B;
use dustbin_elf::analysis::special::LifecycleEntry;
use dustbin_elf::analysis::*;

#[test]
fn test_bsd_crtend_o() -> anyhow::Result<()> {
    let a = Analyze64Le::begin(dustbin_elf_tests::freebsd_15_0_crtend)?;

    let r = a.describe_lifecycle_sections();
    assert_eq!(r.lifecycle_sections.len(), 2);

    let ctors = r.lifecycle_sections.get(B(".ctors")).unwrap();
    let dtors = r.lifecycle_sections.get(B(".dtors")).unwrap();

    assert_eq!(ctors, &[LifecycleEntry::Unclassified(0)]);
    assert_eq!(dtors, &[LifecycleEntry::Unclassified(0)]);

    Ok(())
}
