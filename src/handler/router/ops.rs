use bytes::Bytes;
use http_body_util::Full;
use hyper::{body, http};

use crate::build::router::{
    CompiledBasicCond,
    CompiledCondNode,
    CompiledTestCond,
    LoadedOp,
};
use crate::config::url_scheme::Scheme;
use crate::handler::ServiceHandler;
use crate::template::expand_template;
use crate::util::http::make_error_resp;

use super::ctx::{apply_ctx_to_request, RouterCtx};

#[derive(Debug)]
pub enum OpOutcome {
    ContinueNextRule,
    Restart,
    Respond(http::Response<Full<Bytes>>),
    UseService(http::Response<Full<Bytes>>),
    Fallthrough,
}

pub async fn run_ops(
    ops: &[LoadedOp],
    ctx: &mut RouterCtx,
    req: &mut http::Request<body::Incoming>,
) -> OpOutcome {
    let mut stack: Vec<(&[LoadedOp], usize)> = vec![(ops, 0)];

    while let Some((ops_slice, mut idx)) = stack.pop() {
        while idx < ops_slice.len() {
            let op = &ops_slice[idx];
            match op {
                LoadedOp::SetScheme(s) => {
                    ctx.scheme = Some(match s {
                        Scheme::Http => "http".to_string(),
                        Scheme::Https => "https".to_string(),
                    });
                }
                LoadedOp::SetHost(tpl) => {
                    match expand_template(tpl, &ctx) {
                        Ok(val) => ctx.host = val,
                        Err(_) => return OpOutcome::Respond(make_error_resp(http::StatusCode::BAD_REQUEST, "template error")),
                    }
                }
                LoadedOp::SetPort(p) => ctx.port = Some(*p),
                LoadedOp::SetPath(tpl) => {
                    let val = match expand_template(tpl, &ctx) {
                        Ok(v) => v,
                        Err(_) => return OpOutcome::Respond(make_error_resp(http::StatusCode::BAD_REQUEST, "template error")),
                    };
                    if !val.starts_with('/') {
                        return OpOutcome::Respond(make_error_resp(http::StatusCode::BAD_REQUEST, "path must start with '/'"));
                    }
                    ctx.path = val;
                }
                LoadedOp::HeaderSet(map) => {
                    let headers = req.headers_mut();
                    for (k, v) in map {
                        let val = match expand_template(v, &ctx) {
                            Ok(v) => v,
                            Err(_) => return OpOutcome::Respond(make_error_resp(http::StatusCode::BAD_REQUEST, "template error")),
                        };
                        if let (Ok(name), Ok(hv)) = (
                            http::HeaderName::try_from(k.as_str()),
                            http::HeaderValue::from_str(&val),
                        ) {
                            headers.insert(name.clone(), hv);
                            ctx.headers.insert(name.as_str().to_ascii_lowercase(), vec![val]);
                        }
                    }
                }
                LoadedOp::HeaderAdd(map) => {
                    let headers = req.headers_mut();
                    for (k, v) in map {
                        let val = match expand_template(v, &ctx) {
                            Ok(v) => v,
                            Err(_) => return OpOutcome::Respond(make_error_resp(http::StatusCode::BAD_REQUEST, "template error")),
                        };
                        if let (Ok(name), Ok(hv)) = (
                            http::HeaderName::try_from(k.as_str()),
                            http::HeaderValue::from_str(&val),
                        ) {
                            headers.append(name.clone(), hv);
                            ctx.headers.entry(name.as_str().to_ascii_lowercase()).or_default().push(val);
                        }
                    }
                }
                LoadedOp::HeaderDelete(keys) => {
                    let headers = req.headers_mut();
                    for k in keys {
                        if let Ok(name) = http::HeaderName::try_from(k.as_str()) {
                            headers.remove(&name);
                            ctx.headers.remove(&name.as_str().to_ascii_lowercase());
                        }
                    }
                }
                LoadedOp::HeaderClear => {
                    req.headers_mut().clear();
                    ctx.headers.clear();
                }
                LoadedOp::QuerySet(map) => {
                    for (k, v) in map {
                        let val = match expand_template(v, &ctx) {
                            Ok(v) => v,
                            Err(_) => return OpOutcome::Respond(make_error_resp(http::StatusCode::BAD_REQUEST, "template error")),
                        };
                        ctx.query.insert(k.clone(), vec![val]);
                    }
                }
                LoadedOp::QueryAdd(map) => {
                    for (k, v) in map {
                        let val = match expand_template(v, &ctx) {
                            Ok(v) => v,
                            Err(_) => return OpOutcome::Respond(make_error_resp(http::StatusCode::BAD_REQUEST, "template error")),
                        };
                        ctx.query.entry(k.clone()).or_default().push(val);
                    }
                }
                LoadedOp::QueryDelete(keys) => {
                    for k in keys {
                        ctx.query.remove(k);
                    }
                }
                LoadedOp::QueryClear => ctx.query.clear(),
                LoadedOp::InternalRewrite => return OpOutcome::Restart,
                LoadedOp::Redirect { status, location } => {
                    let status_code = match status {
                        crate::config::router::op::RedirectCode::_301 => http::StatusCode::MOVED_PERMANENTLY,
                        crate::config::router::op::RedirectCode::_302 => http::StatusCode::FOUND,
                        crate::config::router::op::RedirectCode::_307 => http::StatusCode::TEMPORARY_REDIRECT,
                        crate::config::router::op::RedirectCode::_308 => http::StatusCode::PERMANENT_REDIRECT,
                    };
                    let loc = match expand_template(location, &ctx) {
                        Ok(v) => v,
                        Err(_) => return OpOutcome::Respond(make_error_resp(http::StatusCode::BAD_REQUEST, "template error")),
                    };
                    let resp = http::Response::builder()
                        .status(status_code)
                        .header(http::header::LOCATION, loc.as_str())
                        .body(Full::default())
                        .unwrap_or_else(|_| make_error_resp(http::StatusCode::INTERNAL_SERVER_ERROR, "redirect build failed"));
                    return OpOutcome::Respond(resp);
                }
                LoadedOp::Respond { status, body, headers } => {
                    let mut builder = http::Response::builder().status(*status);
                    for (k, v) in headers {
                        let val = match expand_template(v, &ctx) {
                            Ok(v) => v,
                            Err(_) => return OpOutcome::Respond(make_error_resp(http::StatusCode::BAD_REQUEST, "template error")),
                        };
                        if let (Ok(name), Ok(val)) = (
                            http::HeaderName::try_from(k.as_str()),
                            http::HeaderValue::from_str(&val),
                        ) {
                            builder = builder.header(name, val);
                        }
                    }
                    let body_val = match body {
                        Some(t) => match expand_template(t, &ctx) {
                            Ok(v) => v,
                            Err(_) => return OpOutcome::Respond(make_error_resp(http::StatusCode::BAD_REQUEST, "template error")),
                        },
                        None => String::new(),
                    };
                    let resp = builder
                        .body(Full::from(body_val))
                        .unwrap_or_else(|_| make_error_resp(http::StatusCode::INTERNAL_SERVER_ERROR, "respond build failed"));
                    return OpOutcome::Respond(resp);
                }
                LoadedOp::Use(svc) => {
                    apply_ctx_to_request(ctx, req);
                    let resp = svc.handle_request(req).await;
                    return OpOutcome::UseService(resp);
                }
                LoadedOp::Branch(cond, then_ops, else_ops) => {
                    let pass = eval_cond(cond, ctx);
                    let ops_to_run = if pass { then_ops } else { else_ops };
                    stack.push((ops_slice, idx + 1));
                    stack.push((ops_to_run, 0));
                    break;
                }
            }
            idx += 1;
        }
    }

    OpOutcome::Fallthrough
}

fn eval_cond(node: &CompiledCondNode, ctx: &RouterCtx) -> bool {
    match node {
        CompiledCondNode::All(children) => children.iter().all(|n| eval_cond(n, ctx)),
        CompiledCondNode::Any(children) => children.iter().any(|n| eval_cond(n, ctx)),
        CompiledCondNode::Not(child) => !eval_cond(child, ctx),
        CompiledCondNode::Test(t) => eval_test(t, ctx),
    }
}

fn eval_test(t: &CompiledTestCond, ctx: &RouterCtx) -> bool {
    match &t.cond {
        CompiledBasicCond::Equals(is) => {
            value_of(&t.var, ctx).map_or(false, |v| serde_yaml::Value::String(v) == *is)
        }
        CompiledBasicCond::In(list) => {
            value_of(&t.var, ctx).map_or(false, |v| list.contains(&serde_yaml::Value::String(v)))
        }
        CompiledBasicCond::Present(p) => {
            let has = value_of(&t.var, ctx).is_some();
            has == *p
        }
        CompiledBasicCond::Pattern(pat) => {
            value_of(&t.var, ctx).map_or(false, |v| pat.is_match(&v))
        }
    }
}

fn value_of(var: &str, ctx: &RouterCtx) -> Option<String> {
    match var {
        "method" => ctx.method.as_ref().map(|m| format!("{:?}", m).to_ascii_uppercase()),
        "scheme" => ctx.scheme.clone(),
        "host" => Some(ctx.host.clone()),
        "port" => ctx.port.map(|p| p.to_string()),
        "path" => Some(ctx.path.clone()),
        v if v.starts_with("header.") => {
            let key = v.trim_start_matches("header.").to_ascii_lowercase();
            ctx.headers.get(&key).and_then(|vals| vals.get(0)).cloned()
        }
        v if v.starts_with("query.") => {
            let key = v.trim_start_matches("query.");
            ctx.query.get(key).and_then(|vals| vals.get(0)).cloned()
        }
        v if v.starts_with("cookie.") => {
            let key = v.trim_start_matches("cookie.");
            ctx.cookies.get(key).cloned()
        }
        _ => ctx.captures.get(var).cloned(),
    }
}
