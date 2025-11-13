use super::context::PatternContext;
use super::PatternError;

/// Built-in placeholder types (parse-time)
#[derive(Debug, Clone)]
pub enum TypeSpec {
    Segment,                 // segment (changes by ctx)
    Slug,                    // [A-Za-z0-9_-]+
    Int, Hex, Alnum, Uuid,
    Path,                    // PathCtx only, tail-only
    Label, Labels,           // HostCtx only
    Any,                     // ValueCtx only
    Regex(String),           // in-segment
    RegexPath(String),       // PathCtx only, tail-only
    RegexLabels(String),     // HostCtx only
}

#[derive(Debug, Clone)]
pub struct Placeholder {
    pub name: Option<String>,
    pub ty: TypeSpec,
}

pub fn parse_placeholder<C: PatternContext>(buf: &str, ctx: &C) -> Result<Placeholder, PatternError> {
    let (lhs, ty_raw) = if let Some(colon) = buf.find(':') {
        (&buf[..colon], Some(&buf[colon + 1..]))
    } else { (buf, None) };

    let name = if lhs.is_empty() { None } else { Some(lhs.to_string()) };
    let ty = match ty_raw {
        None => ctx.default_type(),
        Some(t) => parse_type_spec(t, ctx)?,
    };

    Ok(Placeholder { name, ty })
}

pub fn parse_type_spec<C: PatternContext>(s: &str, ctx: &C) -> Result<TypeSpec, PatternError> {
    use TypeSpec::*;

    let s = s.trim();

    Ok(match s {
        "" => ctx.default_type(), "*" => ctx.asterisk_type(),
        "segment" => Segment, "slug" => Slug, "int" => Int, "hex" => Hex, "alnum" => Alnum,
        "uuid" => Uuid, "path" => Path, "label" => Label, "labels" => Labels, "any" => Any,
        _ => {
            if let Some(arg) = parse_arg(s, "regex") { Regex(arg) }
            else if let Some(arg) = parse_arg(s, "regex_path") { RegexPath(arg) }
            else if let Some(arg) = parse_arg(s, "regex_labels") { RegexLabels(arg) }
            else { return Err(PatternError::BadPlaceholder(s.into())); }
        }
    })
}

/// Parse fname("..."), with \" and \\ inside.
pub fn parse_arg(s: &str, fname: &str) -> Option<String> {
    let head = format!("{fname}(");
    if !s.starts_with(&head) || !s.ends_with(')') { return None; }
    
    let inner = &s[head.len()..s.len()-1];
    if !inner.starts_with('"') || !inner.ends_with('"') { return None; }

    let inner = &inner[1..inner.len()-1];
    let mut out = String::new();
    let mut esc = false;

    for ch in inner.chars() {
        if esc { out.push(ch); esc = false; }
        else if ch == '\\' { esc = true; }
        else { out.push(ch); }
    }

    Some(out)
}
