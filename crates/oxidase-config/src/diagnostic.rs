use std::fmt;
use std::path::PathBuf;

use oxidase_core::SourceSpan;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub message: String,
    pub source: SourceSpan,
    pub reference_chain: Vec<String>,
    pub help: Option<String>,
}

impl Diagnostic {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>, source: SourceSpan) -> Self {
        Self {
            code,
            message: message.into(),
            source,
            reference_chain: Vec::new(),
            help: None,
        }
    }

    #[must_use]
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    #[must_use]
    pub fn with_reference_chain(mut self, chain: Vec<String>) -> Self {
        self.reference_chain = chain;
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "error[{}]: {}\n  --> {}",
            self.code, self.message, self.source
        )?;
        if !self.reference_chain.is_empty() {
            write!(
                formatter,
                "\n  reference chain: {}",
                self.reference_chain.join(" -> ")
            )?;
        }
        if let Some(help) = &self.help {
            write!(formatter, "\n  help: {help}")?;
        }
        Ok(())
    }
}

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
