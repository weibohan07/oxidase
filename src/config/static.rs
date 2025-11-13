use serde::Deserialize;

fn default_file_index() -> String { "index.html".into() }
fn default_file_404() -> String { "404.html".into() }
fn default_file_500() -> String { "500.html".into() }

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct StaticService {
    pub source_dir: String,
    #[serde(default = "default_file_index")]
    pub file_index: String,
    #[serde(default = "default_file_404")]
    pub file_404: String,
    #[serde(default = "default_file_500")]
    pub file_500: String,
    #[serde(default = "default_index_strategy")]
    pub index_strategy: IndexStrategy,
    #[serde(default)]
    pub evil_dir_strategy: EvilDirStrategy,
}

fn default_redirect_code() -> u16 { 308 }

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct EvilDirStrategy {
    pub if_index_exists: EvilDirStrategyIndexExists,
    pub if_index_missing: EvilDirStrategyIndexMissing,
}
impl Default for EvilDirStrategy {
    fn default() -> Self {
        Self {
            if_index_exists: EvilDirStrategyIndexExists::Redirect { code: default_redirect_code() },
            if_index_missing: EvilDirStrategyIndexMissing::NotFound,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvilDirStrategyIndexExists {
    ServeIndex,
    Redirect { #[serde(default = "default_redirect_code")] code: u16 },
    NotFound,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvilDirStrategyIndexMissing {
    Redirect { #[serde(default = "default_redirect_code")] code: u16 },
    NotFound,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexStrategy {
    ServeIndex,
    Redirect { #[serde(default = "default_redirect_code")] code: u16 },
    NotFound,
}

fn default_index_strategy() -> IndexStrategy {
    IndexStrategy::Redirect { code: default_redirect_code() }
}
