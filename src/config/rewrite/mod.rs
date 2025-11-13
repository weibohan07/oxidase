pub mod r#match;
pub mod op;

use serde::Deserialize;

use super::service::Service;
use r#match::RewriteMatch;
use op::RewriteOp;

#[derive(Debug, Deserialize, Clone)]
pub struct RewriteService {
    pub rules: Vec<RewriteRule>,
    pub next: Box<Service>,
    #[serde(default)]
    pub max_steps: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RewriteRule {
    pub when: RewriteMatch,
    #[serde(default)]
    pub ops: Vec<RewriteOp>,
    #[serde(default)]
    pub on_match: OnMatch,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all="lowercase")]
pub enum OnMatch { #[default] Stop, Continue, Restart }
