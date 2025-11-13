use super::*;

#[test]
fn path_and_captures() {
    let p = compile_path("/post/<slug:slug>").unwrap();
    assert!(p.is_match("/post/hello-world"));
    assert_eq!(p.captures_map("/post/hello-world").unwrap().get("slug").unwrap(), "hello-world");
    assert!(!p.is_match("/post/"));
}

#[test]
fn host_labels_ok() {
    let p = compile_host("<sub:labels>.example.com").unwrap();
    assert!(p.is_match("x.example.com"));
    assert!(p.is_match("a.b.c.example.com"));
    assert_eq!(p.captures_map("x.example.com").unwrap().get("sub").unwrap(), "x");
}

#[test]
fn value_lazy_then_greedy() {
    let p = compile_value("<:any>bot<:any>").unwrap();
    assert!(p.is_match("xxbotyy"));
    let p2 = compile_value("<:any>\\.json").unwrap();
    assert!(p2.is_match("report.json"));
    assert!(!p2.is_match("report.json.bak"));
}

#[test]
fn regex_inside() {
    let p = compile_path("/u/<id:regex(\"[1-9]\\\\d*\")>").unwrap();
    assert!(p.is_match("/u/42"));
    assert!(!p.is_match("/u/0"));
}

#[test]
fn tail_only_rule() {
    let err = compile_path("/docs/<rest:path>.html").unwrap_err();
    matches!(err, PatternError::TailOnlyMustBeLast);
}

#[test]
fn non_capturing_value() {
    let p = compile_value("curl/<:any>").unwrap();
    assert!(p.is_match("curl/7.86.0"));
    assert!(p.captures_map("curl/7.86.0").unwrap().is_empty());
}
