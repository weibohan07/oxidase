use super::*;
use crate::config::router::RouterRule;
use crate::config::router::r#match::RouterMatch;
use crate::config::router::op::RouterOp;

#[test]
fn compile_simple_rule() {
    let rule = RouterRule {
        when: Some(RouterMatch {
            host: Some("example.com".into()),
            ..RouterMatch::default()
        }),
        ops: vec![RouterOp::SetHost("upstream".into())],
        on_match: OnMatch::default(),
    };

    let compiled = compile_rules(&[rule], std::path::Path::new(".")).expect("compile failed");
    assert_eq!(compiled.len(), 1);
    assert!(compiled[0].when.host.is_some());
    assert_eq!(compiled[0].ops.len(), 1);
}
