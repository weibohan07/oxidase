use std::fmt;
use std::path::PathBuf;

pub use oxidase_core::Diagnostic;

#[derive(Clone)]
pub struct CompileError {
    pub diagnostics: Vec<Diagnostic>,
    pub discovered_dependencies: Vec<PathBuf>,
}

impl fmt::Debug for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompileError")
            .field("diagnostics", &self.diagnostics)
            .field(
                "discovered_dependency_count",
                &self.discovered_dependencies.len(),
            )
            .finish_non_exhaustive()
    }
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

    pub(crate) fn map_diagnostics(mut self, map: impl FnMut(Diagnostic) -> Diagnostic) -> Self {
        self.diagnostics = self.diagnostics.into_iter().map(map).collect();
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
