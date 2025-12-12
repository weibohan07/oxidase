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

    let compiled_match = compile_match(&rule.when.unwrap());
    assert!(compiled_match.unwrap().host.is_some());
}
