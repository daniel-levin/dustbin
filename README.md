# dustbin
Dustbin is a collection of Design Rule Checks (DRC) for binaries (ELF only, for now) and a framework for creating them.

## Tenets
1. **Silence is golden, diagnostics are silver.** Rule violations must be obviously useful. Non-violations must be silent.
2. **We jump off cliffs.** If the all the developers of one of our targets are going to jump off a cliff, so are we.
Our goal is conformance with what is, not what ought to be.

## Motivation
The problem is best explained by way of example.

### Problem 1: targeting new operating systems
Suppose we are porting a linker to multiple Unix and Unix-like operating systems, for `x86_64` only, for argument's sake.
To port a linker to a new operating system, we must do the following, at a minimum:

1. Ensure the ELF file itself conforms to the ELF standard.
1. Pick and parametrize the correct runtime linker.
1. Ensure that the operating system's section naming conventions are respected.
1. Ensure that static relocations are processed correctly according to the AMD64 ABI.
1. Ensure that dynamic relocations are performed correctly.
1. Ensure GOT/PLT entries are set up correctly.
1. Ensure to tow in all operating system-specific sections that might exist.

### Problem 2: toolchain flexibility
Suppose that we are working on Illumos, or FreeBSD.
Over time, new needs will demand the use of different toolchains.
We might like to use multiple compilers, or build modules out-of-tree, or in a different language.
We might wish to renovate the build system itself, and retain confidence that our produced artifacts
still work.
To do so, we must, at a minimum:

1. Ensure the compiler has not applied certain aggressive optimizations.
1. Ensure that the compiler's debug information can still be converted faithfully to CTF.
1. Ensure that dynamically loadable modules still work.

### Solution
1. Write assertions using the APIs in `dustbin_elf`.
1. Load binary.
1. Check binary conforms.

## FAQ
Q: Why have you checked binaries into version control?

A: It is the most convenient of all options.
All alternatives require tradeoffs not considered acceptable at this time.
