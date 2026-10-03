//! Bounded JSONL administration audit delivery, independent of request lifetime.
//!
//! Noise/read events use a nonblocking queue and count drops. A protected
//! mutation reserves both its start and completion slots and awaits the start
//! write before it may enter commit. Once committed, sink failure is reflected
//! in telemetry; it can never retroactively turn publication into "not run".

use std::io::{self, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use oxidase_config::{AdminAuditDestination, AdminAuditSpec};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Serialize)]
pub(crate) struct AdminAuditEvent {
    pub(crate) timestamp_ms: u64,
    pub(crate) request_id: String,
    pub(crate) operation_id: Option<String>,
    pub(crate) authentication: String,
    pub(crate) principal: String,
    pub(crate) action: String,
    pub(crate) target_digest: Option<String>,
    pub(crate) previous_revision: Option<String>,
    pub(crate) new_revision: Option<String>,
    pub(crate) result: String,
    pub(crate) diagnostic_code: Option<String>,
}

impl AdminAuditEvent {
    pub(crate) fn new(
        request_id: &str,
        authentication: &str,
        principal: &str,
        action: &str,
    ) -> Self {
        Self {
            timestamp_ms: epoch_ms(),
            request_id: bounded_id(request_id),
            operation_id: None,
            authentication: bounded_id(authentication),
            principal: bounded_id(principal),
            action: bounded_id(action),
            target_digest: None,
            previous_revision: None,
            new_revision: None,
            result: "accepted".to_owned(),
            diagnostic_code: None,
        }
    }

    fn sanitize(&mut self) {
        self.request_id = bounded_id(&self.request_id);
        self.operation_id = self.operation_id.as_deref().map(bounded_id);
        self.authentication = match self.authentication.as_str() {
            "bearer" | "mtls" | "bearer_and_mtls" | "unsafe_development" | "unauthenticated" => {
                self.authentication.clone()
            }
            _ => "unknown".to_owned(),
        };
        self.principal = if matches!(
            self.principal.as_str(),
            "bearer" | "unsafe-development" | "unauthenticated"
        ) || (self.principal.len() == 64
            && self.principal.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            self.principal.clone()
        } else {
            "unknown".to_owned()
        };
        self.action = match self.action.as_str() {
            "read" | "stage" | "validate" | "activate" | "rollback" | "drain" | "reload_source"
            | "unknown" => self.action.clone(),
            _ => "unknown".to_owned(),
        };
        self.target_digest = self.target_digest.take().filter(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
        self.previous_revision = self.previous_revision.as_deref().map(bounded_id);
        self.new_revision = self.new_revision.as_deref().map(bounded_id);
        self.result = match self.result.as_str() {
            "accepted" | "preparing" | "committed" | "failed" | "cancelled"
            | "recovery_required" | "replayed" | "rejected" => self.result.clone(),
            _ => "failed".to_owned(),
        };
        self.diagnostic_code = self.diagnostic_code.as_deref().map(bounded_id);
    }
}

fn bounded_id(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':' | '"')
        })
        .take(128)
        .collect()
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Default)]
struct AuditStats {
    healthy: AtomicBool,
    dropped: AtomicU64,
    delivered: AtomicU64,
    failed: AtomicU64,
}

#[derive(Clone)]
pub(crate) struct AdminAuditSink {
    sender: mpsc::Sender<Message>,
    stats: Arc<AuditStats>,
}

struct Message {
    event: Option<AdminAuditEvent>,
    protected: bool,
    completion: Option<oneshot::Sender<Result<(), AdminAuditError>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminAuditError {
    Unavailable,
    Capacity,
    Write,
}

impl AdminAuditError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Capacity => "admin.audit_capacity",
            Self::Unavailable | Self::Write => "admin.audit_unavailable",
        }
    }
}

pub(crate) struct AdminAuditPermit {
    permit: Option<mpsc::OwnedPermit<Message>>,
    event: AdminAuditEvent,
}

impl AdminAuditSink {
    #[cfg(test)]
    pub(crate) fn test_completion_failure() -> Self {
        Self::start_output(
            4,
            AuditOutput::Test(TestOutput {
                bytes: Arc::new(std::sync::Mutex::new(Vec::new())),
                fail: Arc::new(AtomicBool::new(false)),
                barrier: None,
                remaining_successful_writes: Some(1),
            }),
        )
        .expect("test audit worker starts")
    }

    /// Opens the sink once at bootstrap. The worker owns blocking writes; no
    /// filesystem flush or logging lock is held by a Tokio request worker.
    pub(crate) fn start(spec: &AdminAuditSpec) -> io::Result<Self> {
        let output = AuditOutput::open(&spec.destination)?;
        Self::start_output(spec.queue_capacity as usize, output)
    }

    fn start_output(capacity: usize, mut output: AuditOutput) -> io::Result<Self> {
        if !(2..=4096).contains(&capacity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit queue capacity must be within 2..=4096",
            ));
        }
        let (sender, mut receiver) = mpsc::channel::<Message>(capacity);
        let stats = Arc::new(AuditStats {
            healthy: AtomicBool::new(true),
            ..AuditStats::default()
        });
        let worker_stats = Arc::clone(&stats);
        std::thread::Builder::new()
            .name("oxidase-admin-audit".to_owned())
            .spawn(move || {
                while let Some(mut message) = receiver.blocking_recv() {
                    let result = if !worker_stats.healthy.load(Ordering::Acquire) {
                        Err(AdminAuditError::Unavailable)
                    } else {
                        if let Some(event) = message.event.as_mut() {
                            event.sanitize();
                        }
                        output
                            .write(message.event.as_ref(), message.protected)
                            .map_err(|_| AdminAuditError::Write)
                    };
                    match result {
                        Ok(()) if message.event.is_some() => {
                            worker_stats.delivered.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(()) => {}
                        Err(_) => {
                            worker_stats.healthy.store(false, Ordering::Release);
                            worker_stats.failed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if let Some(completion) = message.completion {
                        let _ = completion.send(result);
                    }
                }
            })?;
        Ok(Self { sender, stats })
    }

    pub(crate) fn try_record(&self, mut event: AdminAuditEvent) {
        event.sanitize();
        if !self.stats.healthy.load(Ordering::Acquire)
            || self
                .sender
                .try_send(Message {
                    event: Some(event),
                    protected: false,
                    completion: None,
                })
                .is_err()
        {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Call before any protected side effect. Capacity and write failure reject
    /// the mutation here; the reserved completion cannot be crowded out by noise.
    pub(crate) async fn prepare_mutation(
        &self,
        mut event: AdminAuditEvent,
    ) -> Result<AdminAuditPermit, AdminAuditError> {
        event.sanitize();
        if !self.stats.healthy.load(Ordering::Acquire) {
            return Err(AdminAuditError::Unavailable);
        }
        let start = self
            .sender
            .clone()
            .try_reserve_owned()
            .map_err(|_| AdminAuditError::Capacity)?;
        let completion = self
            .sender
            .clone()
            .try_reserve_owned()
            .map_err(|_| AdminAuditError::Capacity)?;
        let permit = AdminAuditPermit {
            permit: Some(completion),
            event: event.clone(),
        };
        let (ack, wait) = oneshot::channel();
        start.send(Message {
            event: Some(event.clone()),
            protected: true,
            completion: Some(ack),
        });
        wait.await.map_err(|_| AdminAuditError::Unavailable)??;
        Ok(permit)
    }

    pub(crate) async fn flush(&self) -> Result<(), AdminAuditError> {
        let (ack, wait) = oneshot::channel();
        self.sender
            .send(Message {
                event: None,
                protected: true,
                completion: Some(ack),
            })
            .await
            .map_err(|_| AdminAuditError::Unavailable)?;
        wait.await.map_err(|_| AdminAuditError::Unavailable)?
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.stats.dropped.load(Ordering::Relaxed)
    }
    pub(crate) fn failed(&self) -> u64 {
        self.stats.failed.load(Ordering::Relaxed)
    }
    pub(crate) fn delivered(&self) -> u64 {
        self.stats.delivered.load(Ordering::Relaxed)
    }
    pub(crate) fn is_healthy(&self) -> bool {
        self.stats.healthy.load(Ordering::Acquire)
    }

    /// A manager acknowledgment deadline cannot stop an in-progress blocking
    /// write. It can stop new protected mutations immediately and expose the
    /// uncertain delivery outcome through the fixed failure counter.
    pub(crate) fn fail_closed(&self) {
        if self.stats.healthy.swap(false, Ordering::AcqRel) {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl AdminAuditPermit {
    pub(crate) fn finish(
        mut self,
        mut event: AdminAuditEvent,
    ) -> oneshot::Receiver<Result<(), AdminAuditError>> {
        event.timestamp_ms = epoch_ms();
        event.sanitize();
        let (ack, wait) = oneshot::channel();
        if let Some(permit) = self.permit.take() {
            permit.send(Message {
                event: Some(event),
                protected: true,
                completion: Some(ack),
            });
        }
        wait
    }
}

impl Drop for AdminAuditPermit {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            let mut event = self.event.clone();
            event.timestamp_ms = epoch_ms();
            event.result = "cancelled".to_owned();
            event.diagnostic_code = Some("admin.operation_cancelled".to_owned());
            permit.send(Message {
                event: Some(event),
                protected: true,
                completion: None,
            });
        }
    }
}

enum AuditOutput {
    Stdout,
    Stderr,
    File(SafeAuditFile),
    #[cfg(test)]
    Test(TestOutput),
}

impl AuditOutput {
    fn open(destination: &AdminAuditDestination) -> io::Result<Self> {
        match destination {
            AdminAuditDestination::Stdout => Ok(Self::Stdout),
            AdminAuditDestination::Stderr => Ok(Self::Stderr),
            AdminAuditDestination::File(path) => Ok(Self::File(SafeAuditFile::open(path)?)),
        }
    }

    fn write(&mut self, event: Option<&AdminAuditEvent>, protected: bool) -> io::Result<()> {
        let mut bytes = if let Some(event) = event {
            serde_json::to_vec(event).map_err(io::Error::other)?
        } else {
            Vec::new()
        };
        if event.is_some() {
            bytes.push(b'\n');
        }
        match self {
            Self::Stdout => {
                let mut writer = io::stdout().lock();
                writer.write_all(&bytes)?;
                writer.flush()
            }
            Self::Stderr => {
                let mut writer = io::stderr().lock();
                writer.write_all(&bytes)?;
                writer.flush()
            }
            Self::File(file) => file.write(&bytes, protected),
            #[cfg(test)]
            Self::Test(output) => output.write(&bytes),
        }
    }
}

#[cfg(unix)]
struct SafeAuditFile {
    file: std::fs::File,
    path: std::path::PathBuf,
    parent: crate::admin::unix_trust::DirectoryIdentity,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl SafeAuditFile {
    fn open(path: &std::path::Path) -> io::Result<Self> {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        let parent =
            crate::admin::unix_trust::TrustedDirectory::open(path.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "audit file has no parent")
            })?)?;
        let path = parent.path().join(path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "audit file has no name")
        })?);
        let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(flags.bits() as i32)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "audit file must be a private, single-link, process-owned regular file",
            ));
        }
        parent.verify()?;
        file.sync_all()?;
        parent.sync()?;
        let result = Self {
            file,
            path,
            parent: parent.identity(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        result.verify()?;
        Ok(result)
    }

    fn verify(&self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;
        self.parent.verify()?;
        let metadata = std::fs::symlink_metadata(&self.path)?;
        if !metadata.is_file()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "audit file identity or permissions changed",
            ));
        }
        Ok(())
    }

    fn write(&mut self, bytes: &[u8], protected: bool) -> io::Result<()> {
        self.verify()?;
        self.file.write_all(bytes)?;
        self.file.flush()?;
        if protected {
            self.file.sync_data()?;
        }
        Ok(())
    }
}

#[cfg(not(unix))]
struct SafeAuditFile;
#[cfg(not(unix))]
impl SafeAuditFile {
    fn open(_: &std::path::Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "safe local-file audit requires Unix; use stdout or stderr",
        ))
    }
    fn write(&mut self, _: &[u8], _: bool) -> io::Result<()> {
        unreachable!("non-Unix file sink cannot be constructed")
    }
}

#[cfg(test)]
struct TestOutput {
    bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    fail: Arc<AtomicBool>,
    barrier: Option<Arc<std::sync::Barrier>>,
    remaining_successful_writes: Option<usize>,
}

#[cfg(test)]
impl TestOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        if let Some(barrier) = self.barrier.take() {
            barrier.wait();
            barrier.wait();
        }
        if self.fail.load(Ordering::Acquire) || self.remaining_successful_writes == Some(0) {
            return Err(io::Error::other("injected sink failure"));
        }
        if let Some(remaining) = &mut self.remaining_successful_writes {
            *remaining -= 1;
        }
        self.bytes
            .lock()
            .expect("test buffer lock")
            .extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(
        capacity: usize,
    ) -> (
        AdminAuditSink,
        Arc<std::sync::Mutex<Vec<u8>>>,
        Arc<AtomicBool>,
    ) {
        let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let fail = Arc::new(AtomicBool::new(false));
        let sink = AdminAuditSink::start_output(
            capacity,
            AuditOutput::Test(TestOutput {
                bytes: Arc::clone(&bytes),
                fail: Arc::clone(&fail),
                barrier: None,
                remaining_successful_writes: None,
            }),
        )
        .expect("audit worker starts");
        (sink, bytes, fail)
    }

    #[tokio::test]
    async fn writes_jsonl_outcomes_and_redacts_uncontrolled_fields() {
        let (sink, bytes, _) = fixture(4);
        let event = AdminAuditEvent::new("request-1", "bearer", "raw-secret-token", "activate");
        let permit = sink
            .prepare_mutation(event.clone())
            .await
            .expect("start delivered before side effects");
        let mut outcome = event;
        outcome.result = "committed".to_owned();
        outcome.new_revision = Some("runtime-2".to_owned());
        permit
            .finish(outcome)
            .await
            .expect("completion worker")
            .expect("completion delivered");
        sink.flush().await.expect("worker flushes");
        let text =
            String::from_utf8(bytes.lock().expect("buffer lock").clone()).expect("JSONL is UTF-8");
        let lines = text
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).expect("each JSON line parses")
            })
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["result"], "accepted");
        assert_eq!(lines[1]["result"], "committed");
        assert!(!text.contains("raw-secret-token"));
        assert_eq!(sink.delivered(), 2);
    }

    #[tokio::test]
    async fn protected_write_failure_closes_future_mutation_admission() {
        let (sink, _, fail) = fixture(4);
        fail.store(true, Ordering::Release);
        let event = AdminAuditEvent::new("request-1", "bearer", "bearer", "activate");
        assert!(matches!(
            sink.prepare_mutation(event.clone()).await,
            Err(AdminAuditError::Write)
        ));
        assert!(!sink.is_healthy());
        assert!(matches!(
            sink.prepare_mutation(event.clone()).await,
            Err(AdminAuditError::Unavailable)
        ));
        sink.try_record(event);
        assert_eq!(sink.failed(), 1);
        assert_eq!(sink.dropped(), 1);
    }

    #[tokio::test]
    async fn manager_ack_deadline_closes_admission_without_reopening_on_repetition() {
        let (sink, _, _) = fixture(4);
        sink.fail_closed();
        sink.fail_closed();
        assert!(!sink.is_healthy());
        assert_eq!(sink.failed(), 1);
        let event = AdminAuditEvent::new("request-1", "bearer", "bearer", "activate");
        assert!(matches!(
            sink.prepare_mutation(event.clone()).await,
            Err(AdminAuditError::Unavailable)
        ));
        sink.try_record(event);
        assert_eq!(sink.dropped(), 1);
    }

    #[tokio::test]
    async fn cancellation_emits_a_final_record_from_the_reserved_slot() {
        let (sink, bytes, _) = fixture(2);
        let event = AdminAuditEvent::new("request-1", "bearer", "bearer", "activate");
        drop(sink.prepare_mutation(event).await.expect("audit admission"));
        sink.flush().await.expect("cancellation delivered");
        let text = String::from_utf8(bytes.lock().expect("buffer lock").clone()).expect("UTF-8");
        assert!(text.contains("\"result\":\"cancelled\""));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overflow_is_bounded_and_cannot_steal_reserved_completion() {
        let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let sink = AdminAuditSink::start_output(
            2,
            AuditOutput::Test(TestOutput {
                bytes,
                fail: Arc::new(AtomicBool::new(false)),
                barrier: Some(Arc::clone(&barrier)),
                remaining_successful_writes: None,
            }),
        )
        .expect("worker starts");
        let event = AdminAuditEvent::new("noise", "unauthenticated", "unauthenticated", "unknown");
        sink.try_record(event.clone());
        barrier.wait();
        sink.try_record(event.clone());
        sink.try_record(event.clone());
        sink.try_record(event.clone());
        assert_eq!(sink.dropped(), 1);
        assert!(matches!(
            sink.prepare_mutation(event).await,
            Err(AdminAuditError::Capacity)
        ));
        barrier.wait();
        sink.flush().await.expect("worker unblocks and flushes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn safe_file_rejects_symlink_permissions_and_path_replacement() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let directory = tempfile::tempdir().expect("tempdir");
        let target = directory.path().join("target");
        std::fs::write(&target, b"secret").expect("target");
        let link = directory.path().join("link");
        symlink(&target, &link).expect("symlink");
        assert!(SafeAuditFile::open(&link).is_err());
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(SafeAuditFile::open(&target).is_err());
        let path = directory.path().join("audit.jsonl");
        let mut file = SafeAuditFile::open(&path).expect("private audit file opens");
        std::fs::remove_file(&path).expect("remove own fixture");
        std::fs::write(&path, b"replacement").expect("replacement");
        assert!(file.write(b"event", true).is_err());
        assert_eq!(
            std::fs::read(&path).expect("read replacement"),
            b"replacement"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn configured_file_sink_delivers_acknowledged_jsonl() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("audit.jsonl");
        let sink = AdminAuditSink::start(&AdminAuditSpec {
            destination: AdminAuditDestination::File(path.clone()),
            queue_capacity: 4,
            source: oxidase_core::SourceSpan::synthetic("admin.audit"),
        })
        .expect("safe configured file opens");
        let mut event = AdminAuditEvent::new("request-1", "bearer", "bearer", "drain");
        let permit = sink
            .prepare_mutation(event.clone())
            .await
            .expect("durable preflight");
        event.result = "committed".to_owned();
        permit
            .finish(event)
            .await
            .expect("worker acknowledges")
            .expect("durable completion");
        let bytes = std::fs::read(path).expect("audit file can be inspected");
        let lines = std::str::from_utf8(&bytes)
            .expect("UTF8")
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid JSONL"))
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["action"], "drain");
        assert_eq!(lines[1]["result"], "committed");
    }
}
