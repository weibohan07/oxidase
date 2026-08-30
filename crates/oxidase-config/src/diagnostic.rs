use std::fmt;
use std::path::PathBuf;

pub use oxidase_core::Diagnostic;

#[derive(Debug, Clone)]
pub struct CompileError {
    pub diagnostics: Vec<Diagnostic>,
    pub discovered_dependencies: Vec<PathBuf>,
}

impl CompileError {
    #[must_use]
    pub fn one(diagnostic: Diagnostic) -> Self {
        Self {
            diagnostics: vec![diagnostic],
            discovered_dependencies: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_discovered_dependencies(
        mut self,
        dependencies: impl IntoIterator<Item = PathBuf>,
    ) -> Self {
        self.discovered_dependencies.extend(dependencies);
        self.discovered_dependencies.sort();
        self.discovered_dependencies.dedup();
        self
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            if index > 0 {
                writeln!(formatter)?;
            }
            write!(formatter, "{diagnostic}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CompileError {}
