use crate::build::router::CompiledRouterMatch;
use crate::config::router::r#match::Scheme;

use super::ctx::RouterCtx;

#[derive(Debug)]
pub enum MatchResult {
    Match,
    NoMatch,
}

pub fn matches_rule(
    m: &CompiledRouterMatch,
    ctx: &mut RouterCtx,
) -> MatchResult {
    if let Some(host_pat) = &m.host {
        if !host_pat.is_match(&ctx.host) {
            return MatchResult::NoMatch;
        }
        if let Some(caps) = host_pat.captures_map(&ctx.host) {
            ctx.captures.extend(caps);
        }
    }

    if let Some(path_pat) = &m.path {
        if !path_pat.is_match(&ctx.path) {
            return MatchResult::NoMatch;
        }
        if let Some(caps) = path_pat.captures_map(&ctx.path) {
            ctx.captures.extend(caps);
        }
    }

    if let Some(scheme) = &m.scheme {
        let s = ctx.scheme.as_deref().unwrap_or("");
        let expect = match scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        if s != expect {
            return MatchResult::NoMatch;
        }
    }

    if !m.methods.is_empty() {
        if let Some(method) = &ctx.method {
            if !m.methods.iter().any(|mth| mth == method) {
                return MatchResult::NoMatch;
            }
        } else {
            return MatchResult::NoMatch;
        }
    }

    for h in &m.headers {
        let vals = ctx.headers.get(&h.name).cloned().unwrap_or_default();
        let matched = vals.iter().any(|v| h.pattern.is_match(v));
        let ok = if h.not { !matched } else { matched };
        if !ok {
            return MatchResult::NoMatch;
        }
        if let Some(v) = vals.first() {
            if let Some(caps) = h.pattern.captures_map(v) {
                ctx.captures.extend(caps);
            }
        }
    }

    for q in &m.queries {
        let vals = ctx.query.get(&q.key).cloned().unwrap_or_default();
        let matched = vals.iter().any(|v| q.pattern.is_match(v));
        let ok = if q.not { !matched } else { matched };
        if !ok {
            return MatchResult::NoMatch;
        }
        if let Some(v) = vals.first() {
            if let Some(caps) = q.pattern.captures_map(v) {
                ctx.captures.extend(caps);
            }
        }
    }

    for c in &m.cookies {
        let val = ctx.cookies.get(&c.name).cloned().unwrap_or_default();
        let matched = c.pattern.is_match(&val);
        let ok = if c.not { !matched } else { matched };
        if !ok {
            return MatchResult::NoMatch;
        }
        if let Some(caps) = c.pattern.captures_map(&val) {
            ctx.captures.extend(caps);
        }
    }

    MatchResult::Match
}
