use dustbin_elf::analysis::text::x86::*;
use dustbin_elf::analysis::*;

#[test]
fn check_bash_main() -> anyhow::Result<()> {
    let a = Analyze64Le::begin(dustbin_elf_tests::linux_bash_x86_64)?;

    let main = a.function_definitions().lookup(b"main").unwrap();

    let df = DecodedFuncDefn::decode(&main).unwrap();

    for i in df.ins.iter() {
        assert!(i.mnemonic() != iced_x86::Mnemonic::Pclmulqdq);
    }

    assert_eq!(main.address, 0x2ae0);

    Ok(())
}
