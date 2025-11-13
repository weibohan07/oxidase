pub mod context;
pub mod placeholder;
pub mod compiler;
pub mod error;

use std::collections::HashMap;
use regex::Regex;

use context::{
    PatternContext,
    PathCtx,
    HostCtx,
    ValueCtx,
};
use compiler::build_regex_source;
use error::PatternError;


#[derive(Debug, Clone)]
pub struct CompiledPattern {
    re: Regex,
    names: Vec<String>,
    pub raw: String,
}
impl CompiledPattern {
    #[inline]
    pub fn is_match(&self, s: &str) -> bool { self.re.is_match(s) }

    #[inline]
    pub fn regex(&self) -> &Regex { &self.re }

    pub fn captures_map(&self, s: &str) -> Option<HashMap<String, String>> {
        let caps = self.re.captures(s)?;
        let mut out = HashMap::new();
        for n in &self.names {
            if let Some(m) = caps.name(n) { out.insert(n.clone(), m.as_str().to_string()); }
        }
        Some(out)
    }
}

pub fn compile<C: PatternContext>(input: &str, ctx: &C) -> Result<CompiledPattern, PatternError> {
    let (regex_src, names) = build_regex_source(input, ctx)?;
    let re = Regex::new(&regex_src)?;
    Ok(CompiledPattern { re, names, raw: input.to_string() })
}

pub fn compile_path(input: &str)  -> Result<CompiledPattern, PatternError> { compile(input, &PathCtx) }
pub fn compile_host(input: &str)  -> Result<CompiledPattern, PatternError> { compile(input, &HostCtx) }
pub fn compile_value(input: &str) -> Result<CompiledPattern, PatternError> { compile(input, &ValueCtx) }

#[cfg(test)]
mod tests;
