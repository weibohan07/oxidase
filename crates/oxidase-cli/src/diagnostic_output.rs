use std::io::{self, Write};

use clap::ValueEnum;
pub(crate) use oxidase_cli::DiagnosticRoot;
use oxidase_cli::{encode_json_diagnostics, sort_diagnostics};
use oxidase_core::Diagnostic;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum DiagnosticFormat {
    #[default]
    Human,
    Json,
}

pub(crate) struct Reporter {
    format: DiagnosticFormat,
}

impl Reporter {
    pub(crate) fn new(format: DiagnosticFormat) -> Self {
        Self { format }
    }

    pub(crate) fn human_stdout(&self, message: impl AsRef<str>) {
        if self.format == DiagnosticFormat::Human {
            println!("{}", message.as_ref());
        }
    }
}

pub(crate) fn render(
    format: DiagnosticFormat,
    root: &DiagnosticRoot,
    mut diagnostics: Vec<Diagnostic>,
) -> io::Result<()> {
    match format {
        DiagnosticFormat::Human => {
            sort_diagnostics(root, &mut diagnostics);
            let mut stderr = io::stderr().lock();
            for (index, diagnostic) in diagnostics.iter().enumerate() {
                if index > 0 {
                    writeln!(stderr)?;
                }
                writeln!(stderr, "{diagnostic}")?;
            }
            stderr.flush()
        }
        DiagnosticFormat::Json => {
            let encoded = encode_json_diagnostics(root, diagnostics)?;
            let mut stdout = io::stdout().lock();
            stdout.write_all(&encoded)?;
            stdout.flush()
        }
    }
}
