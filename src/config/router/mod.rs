pub mod r#match;
pub mod op;

use serde::Deserialize;

use super::service::ServiceRef;
use r#match::RouterMatch;
use op::RouterOp;

#[derive(Debug, Deserialize, Clone)]
pub struct RouterService {
    pub rules: Vec<RouterRule>,
    #[serde(default)]
    pub next: Option<Box<ServiceRef>>,
    #[serde(default)]
    pub max_steps: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouterRule {
    #[serde(default)]
    pub when: Option<RouterMatch>,
    #[serde(default)]
    pub ops: Vec<RouterOp>,
    #[serde(default)]
    pub on_match: OnMatch,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all="lowercase")]
pub enum OnMatch { #[default] Stop, Continue, Restart }
