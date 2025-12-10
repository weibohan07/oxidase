use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;

use super::super::url_scheme::Scheme;
use super::super::service::ServiceRef;

#[derive(Debug, Clone)]
pub enum RouterOp {
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

    Use(Box<ServiceRef>),
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub enum RedirectCode { _301=301, _302=302, _307=307, _308=308 }

#[derive(Debug, Deserialize, Clone)]
pub struct BranchOp {
    pub r#if: CondNode,
    pub then: Vec<RouterOp>,
    #[serde(default)]
    pub r#else: Vec<RouterOp>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
enum RouterOpFull {
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

    Use(Box<ServiceRef>),
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum RouterOpUnitKeyword {
    HeaderClear,
    QueryClear,
    InternalRewrite,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RouterOpDe {
    Unit(RouterOpUnitKeyword),
    Full(RouterOpFull),
}

impl<'de> Deserialize<'de> for RouterOp {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        Ok(match RouterOpDe::deserialize(de)? {
            RouterOpDe::Unit(u) => match u {
                RouterOpUnitKeyword::HeaderClear => RouterOp::HeaderClear,
                RouterOpUnitKeyword::QueryClear => RouterOp::QueryClear,
                RouterOpUnitKeyword::InternalRewrite => RouterOp::InternalRewrite,
            },
            RouterOpDe::Full(f) => match f {
                RouterOpFull::Branch(x) => RouterOp::Branch(x),
                RouterOpFull::SetScheme(x) => RouterOp::SetScheme(x),
                RouterOpFull::SetHost(x) => RouterOp::SetHost(x),
                RouterOpFull::SetPort(x) => RouterOp::SetPort(x),
                RouterOpFull::SetPath(x) => RouterOp::SetPath(x),
                RouterOpFull::HeaderSet(x) => RouterOp::HeaderSet(x),
                RouterOpFull::HeaderAdd(x) => RouterOp::HeaderAdd(x),
                RouterOpFull::QuerySet(x) => RouterOp::QuerySet(x),
                RouterOpFull::QueryAdd(x) => RouterOp::QueryAdd(x),
                RouterOpFull::HeaderDelete(x) => RouterOp::HeaderDelete(x),
                RouterOpFull::QueryDelete(x) => RouterOp::QueryDelete(x),
                RouterOpFull::HeaderClear => RouterOp::HeaderClear,
                RouterOpFull::QueryClear => RouterOp::QueryClear,
                RouterOpFull::InternalRewrite => RouterOp::InternalRewrite,
                RouterOpFull::Redirect { status, location } =>
                    RouterOp::Redirect { status, location },
                RouterOpFull::Respond { status, body, headers } =>
                    RouterOp::Respond { status, body, headers },
                RouterOpFull::Use(svc) => RouterOp::Use(svc),
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
