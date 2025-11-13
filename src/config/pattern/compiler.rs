use std::collections::HashSet;
use super::context::PatternContext;
use super::PatternError;
use super::context::Expand;
use super::placeholder::parse_placeholder;

pub fn build_regex_source<C: PatternContext>(
    input: &str, ctx: &C
) -> Result<(String, Vec<String>), PatternError> {
    let mut out = String::from("^");
    let mut names = Vec::new();
    let mut names_seen = HashSet::new();
    let mut chars = input.chars().peekable();
    let mut tail_only_name_seen = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => { // escape next as literal
                if let Some(nxt) = chars.next() {
                    out.push_str(&regex::escape(&nxt.to_string()));
                }
            }
            '<' => {
                if tail_only_name_seen { return Err(PatternError::TailOnlyMustBeLast); }
                let mut buf = String::new();
                let mut esc = false;
                while let Some(c) = chars.next() {
                    if esc { buf.push(c); esc = false; continue; }
                    if c == '\\' { esc = true; continue; }
                    if c == '>' { break; }
                    buf.push(c);
                }
                if esc { return Err(PatternError::Unclosed); }
                if buf.is_empty() { return Err(PatternError::Empty); }

                let ph = parse_placeholder(&buf, ctx)?;
                let is_last_after: bool = chars.peek().is_none();

                let Expand { src, tail_only } = ctx.expand(&ph.ty, is_last_after)?;
                if tail_only { tail_only_name_seen = true; }

                if let Some(name) = ph.name {
                    if !names_seen.insert(name.clone()) { return Err(PatternError::DupName(name)); }
                    out.push_str(&format!("(?P<{}>{})", name, src));
                    names.push(name);
                } else {
                    out.push_str(&format!("(?:{})", src));
                }
            }
            c => {
                if tail_only_name_seen { return Err(PatternError::TailOnlyMustBeLast); }
                out.push_str(&regex::escape(&c.to_string()));
            }
        }
    }

    out.push('$');
    Ok((out, names))
}
