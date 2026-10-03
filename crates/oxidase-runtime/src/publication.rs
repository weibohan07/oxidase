//! Published runtime identity is stored atomically with the request snapshot.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use oxidase_core::{ContentDigest, ContentDigestBuilder};
use serde::Serialize;

use crate::RuntimeSnapshot;

static EPOCH_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimeOrigin {
    Source,
    Bundle {
        #[serde(serialize_with = "serialize_digest")]
        digest: ContentDigest,
    },
}

fn serialize_digest<S: serde::Serializer>(
    digest: &ContentDigest,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&digest.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServingState {
    Running,
    Draining,
    Drained,
}

/// The sole authority for the currently served program, including its CAS
/// identity. Historical artifact metadata cannot substitute for this value.
#[derive(Debug, Clone)]
pub struct PublishedRuntime {
    pub snapshot: Arc<RuntimeSnapshot>,
    pub runtime_revision: u64,
    pub runtime_epoch: ContentDigest,
    pub origin: RuntimeOrigin,
    pub serving_state: ServingState,
    /// Explicit source authority retained across an operator Bundle switch.
    pub source_origin: Option<PathBuf>,
}

impl PublishedRuntime {
    pub(crate) fn initial(snapshot: RuntimeSnapshot, origin: RuntimeOrigin) -> Self {
        let source_origin = if origin == RuntimeOrigin::Source {
            let path = PathBuf::from(&snapshot.summary().source);
            path.is_absolute().then_some(path)
        } else {
            None
        };
        let mut epoch = ContentDigestBuilder::new("oxidase/runtime-epoch/v1");
        epoch
            .field_u128(
                "time_ns",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
            )
            .field_u64("process", u64::from(std::process::id()))
            .field_u64("sequence", EPOCH_SEQUENCE.fetch_add(1, Ordering::Relaxed));
        Self {
            snapshot: Arc::new(snapshot),
            runtime_revision: 1,
            runtime_epoch: epoch.finish(),
            origin,
            serving_state: ServingState::Running,
            source_origin,
        }
    }

    /// A restart never reuses a prior process's HTTP conditional token.
    #[must_use]
    pub fn etag(&self) -> String {
        format!(
            "\"runtime-{}-{}\"",
            self.runtime_epoch, self.runtime_revision
        )
    }

    #[must_use]
    pub fn bundle_digest(&self) -> Option<ContentDigest> {
        match self.origin {
            RuntimeOrigin::Source => None,
            RuntimeOrigin::Bundle { digest } => Some(digest),
        }
    }

    #[must_use]
    pub fn ready(&self) -> bool {
        self.serving_state == ServingState::Running && !self.snapshot.listeners.is_empty()
    }
}
