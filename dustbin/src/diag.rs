use std::sync::Arc;
use std::sync::RwLock;

use bstr::BString;

#[derive(Debug, Clone)]
pub struct Diagnostics {
    logs: Arc<RwLock<Vec<Diagnostic>>>,
}

#[derive(Debug)]
pub enum Diagnostic {
    Defect(Defect),
    Informational(Informational),
    Suspect(Suspect),
}

/// Informationals are not expected to be dispositive of defects, but they
/// may point you in the right direction.
#[derive(Debug)]
pub enum Informational {
    /// This binary has no sections marked as SHT_DYNAMIC.
    NoDynamicSections,

    /// There is no program header setting this binary's interpreter (i.e.
    /// runtime linker).
    MissingInterpreter,
}

/// Indicates that something is certainly wrong with this binary.
#[derive(Debug)]
pub enum Defect {
    MalformedSpecialSection(crate::analysis::special::MalformedSpecialSection),
}

#[derive(Debug)]
pub enum Suspect {
    UnexpectedSpecialSectionType {
        section: BString,
        expected_type: u32,
        actual_type: u32,
    },
}

impl Default for Diagnostics {
    fn default() -> Self {
        Self::new()
    }
}

impl Diagnostics {
    pub fn new() -> Self {
        Self {
            logs: Default::default(),
        }
    }

    /// Record a possibly noteworthy datum.
    pub fn info(&self, info: Informational) {
        if let Ok(mut wp) = self.logs.write() {
            wp.push(Diagnostic::Informational(info));
        }
    }

    /// Record a definite fault in the binary.
    pub fn defect(&self, defect: Defect) {
        if let Ok(mut wp) = self.logs.write() {
            wp.push(Diagnostic::Defect(defect));
        }
    }

    pub fn suspect(&self, suspect: Suspect) {
        if let Ok(mut wp) = self.logs.write() {
            wp.push(Diagnostic::Suspect(suspect));
        }
    }
}

mod checks {
    static_assertions::assert_impl_all!(super::Diagnostics: Send, Sync);
}
