use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;

use super::super::url_scheme::Scheme;

#[derive(Debug, Clone)]
pub enum RewriteOp {
    Branch(BranchOp),

    SetScheme(Scheme),
    SetHost(String),
    SetPort(u16),
    SetPath(String),

    HeaderSet(BTreeMap<String, String>),
    HeaderAdd(BTreeMap<String, String>),
    HeaderDelete(Vec<String>),
    HeaderClear,

    QuerySet(BTreeMap<String, String>),
    QueryAdd(BTreeMap<String, String>),
    QueryDelete(Vec<String>),
    QueryClear,

    InternalRewrite,
    Redirect { status: RedirectCode, location: String },
    Respond { status: u16, body: Option<String>, headers: BTreeMap<String, String> },
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub enum RedirectCode { _301=301, _302=302, _307=307, _308=308 }

#[derive(Debug, Deserialize, Clone)]
pub struct BranchOp {
    pub r#if: CondNode,
    pub then: Vec<RewriteOp>,
    pub r#else: Vec<RewriteOp>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
enum RewriteOpFull {
    Branch(BranchOp),

    SetScheme(Scheme),
    SetHost(String),
    SetPort(u16),
    SetPath(String),

    HeaderSet(BTreeMap<String, String>),
    HeaderAdd(BTreeMap<String, String>),
    HeaderDelete(Vec<String>),
    HeaderClear,

    QuerySet(BTreeMap<String, String>),
    QueryAdd(BTreeMap<String, String>),
    QueryDelete(Vec<String>),
    QueryClear,

    InternalRewrite,
    Redirect { status: RedirectCode, location: String },
    Respond {
        status: u16,
        #[serde(default)] body: Option<String>,
        #[serde(default)] headers: BTreeMap<String, String>,
    },
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum RewriteOpUnitKeyword {
    HeaderClear,
    QueryClear,
    InternalRewrite,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RewriteOpDe {
    Unit(RewriteOpUnitKeyword),
    Full(RewriteOpFull),
}

impl<'de> Deserialize<'de> for RewriteOp {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        Ok(match RewriteOpDe::deserialize(de)? {
            RewriteOpDe::Unit(u) => match u {
                RewriteOpUnitKeyword::HeaderClear => RewriteOp::HeaderClear,
                RewriteOpUnitKeyword::QueryClear => RewriteOp::QueryClear,
                RewriteOpUnitKeyword::InternalRewrite => RewriteOp::InternalRewrite,
            },
            RewriteOpDe::Full(f) => match f {
                RewriteOpFull::Branch(x) => RewriteOp::Branch(x),
                RewriteOpFull::SetScheme(x) => RewriteOp::SetScheme(x),
                RewriteOpFull::SetHost(x) => RewriteOp::SetHost(x),
                RewriteOpFull::SetPort(x) => RewriteOp::SetPort(x),
                RewriteOpFull::SetPath(x) => RewriteOp::SetPath(x),
                RewriteOpFull::HeaderSet(x) => RewriteOp::HeaderSet(x),
                RewriteOpFull::HeaderAdd(x) => RewriteOp::HeaderAdd(x),
                RewriteOpFull::QuerySet(x) => RewriteOp::QuerySet(x),
                RewriteOpFull::QueryAdd(x) => RewriteOp::QueryAdd(x),
                RewriteOpFull::HeaderDelete(x) => RewriteOp::HeaderDelete(x),
                RewriteOpFull::QueryDelete(x) => RewriteOp::QueryDelete(x),
                RewriteOpFull::HeaderClear => RewriteOp::HeaderClear,
                RewriteOpFull::QueryClear => RewriteOp::QueryClear,
                RewriteOpFull::InternalRewrite => RewriteOp::InternalRewrite,
                RewriteOpFull::Redirect { status, location } =>
                    RewriteOp::Redirect { status, location },
                RewriteOpFull::Respond { status, body, headers } =>
                    RewriteOp::Respond { status, body, headers },
            },
        })
    }
}

// TODO: deny_unknown_fields
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum CondNode {
    All { all: Vec<CondNode> },
    Any { any: Vec<CondNode> },
    Not { not: Box<CondNode> },
    Test(TestCond),
}

#[derive(Debug, Deserialize, Clone)]
pub struct TestCond {
    pub var: String,
    #[serde(flatten)]
    pub cond: BasicCond,
}

// TODO: deny_unknown_fields
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum BasicCond {
    Equals { is: serde_yaml::Value },
    In { r#in: Vec<serde_yaml::Value> },
    Present { present: bool },
    Pattern {
        pattern: String,
        #[serde(default)] ctx: Option<PatternCtxHint>,
    },
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum PatternCtxHint { Path, Host, Value }
