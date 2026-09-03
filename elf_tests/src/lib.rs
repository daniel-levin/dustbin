#![allow(non_upper_case_globals)]
#![allow(clippy::redundant_static_lifetimes)]

//! ELF binaries used by tests.
//!
//! Each regular file in the workspace's `bins` directory is exported as a byte
//! slice.

include!(concat!(env!("OUT_DIR"), "/bins.rs"));
