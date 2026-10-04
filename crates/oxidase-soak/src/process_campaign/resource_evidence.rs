//! Bounded evidence writer and continuous operation collector, validation-only.
//! No controller verdict is used by the independent verifier.

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::path::Path;

use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::{SoakError, fail, io_error, json_error};

pub(super) struct JsonLines {
    file: std::fs::File,
    bytes: u64,
    limit: u64,
    sequence: u64,
}

impl JsonLines {
    pub(super) fn create(path: &Path, limit: u64) -> Result<Self, SoakError> {
        Ok(Self {
            file: std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(io_error)?,
            bytes: 0,
            limit,
            sequence: 0,
        })
    }

    pub(super) fn write(&mut self, mut row: Value) -> Result<(), SoakError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| fail("evidence sequence overflow"))?;
        row["writer_seq"] = self.sequence.into();
        let mut bytes = serde_json::to_vec(&row).map_err(json_error)?;
        bytes.push(b'\n');
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| fail("evidence size overflow"))?;
        if self.bytes > self.limit {
            return Err(fail(
                "evidence artifact capacity exhausted; qualification incomplete",
            ));
        }
        self.file.write_all(&bytes).map_err(io_error)?;
        Ok(())
    }

    pub(super) fn flush(&mut self) -> Result<(), SoakError> {
        self.file.flush().map_err(io_error)
    }
}

/// IDs are issued before connection preparation. One terminal per ID, including
/// connection failure. A stop signal cannot discard already-issued work.
pub(super) enum OperationEvent {
    Started {
        worker: usize,
        sequence: u64,
        start_ns: u64,
    },
    Terminal {
        worker: usize,
        sequence: u64,
        start_ns: u64,
        end_ns: u64,
        phase: &'static str,
        lane: &'static str,
        protocol: &'static str,
        recipe: &'static str,
        connection_attempts: u64,
        admitted: bool,
        window_id: Option<String>,
        raw: Value,
    },
}

#[derive(Default)]
struct WorkerBucket {
    first: u64,
    last: u64,
    start_ns: u64,
    end_ns: u64,
    connection_attempts: u64,
    admitted: u64,
    upgrades: u64,
    outcomes: BTreeMap<String, (Value, u64)>,
}

#[derive(Default)]
pub(super) struct Collected {
    pub(super) offered: u64,
    pub(super) connection_attempts: u64,
    pub(super) admitted_http_operations: u64,
    pub(super) admitted_upgrade_operations: u64,
    pub(super) received_operations: u64,
    pub(super) non_complete: u64,
    pub(super) fatal_errors: Vec<String>,
    pub(super) abandoned_operations: Vec<Value>,
    pub(super) artifact_truncated: bool,
    pub(super) workers: BTreeMap<usize, WorkerCounts>,
}

#[derive(Default)]
pub(super) struct WorkerCounts {
    offered: u64,
    received: u64,
    last: u64,
    connections: u64,
    admitted: u64,
    upgrades: u64,
}

impl Collected {
    pub(super) fn json(&self) -> Value {
        json!({"offered":self.offered,"connection_attempts":self.connection_attempts,
            "admitted_http_operations":self.admitted_http_operations,"received_operations":self.received_operations,
            "admitted_upgrade_operations":self.admitted_upgrade_operations,
            "abandoned_operations":self.abandoned_operations,
            "workers":self.workers.iter().map(|(worker,c)|json!({"worker_id":worker,"last_operation_seq":c.last,"offered":c.offered,"received_operations":c.received,"connection_attempts":c.connections,"admitted_http_operations":c.admitted,"admitted_upgrade_operations":c.upgrades})).collect::<Vec<_>>()})
    }
}

fn flush_buckets(
    writer: &mut JsonLines,
    buckets: &mut BTreeMap<usize, WorkerBucket>,
) -> Result<(), SoakError> {
    for (worker, bucket) in std::mem::take(buckets) {
        let count = bucket.last - bucket.first + 1;
        let outcomes: Vec<Value> = bucket
            .outcomes
            .into_values()
            .map(|(mut row, count)| {
                row["count"] = count.into();
                row
            })
            .collect();
        writer.write(json!({"worker_id":worker,"first_operation_seq":bucket.first,
            "last_operation_seq":bucket.last,"bucket_start_ns":bucket.start_ns,"bucket_end_ns":bucket.end_ns,
            "offered":count,"received_operations":count,"connection_attempts":bucket.connection_attempts,
            "admitted_http_operations":bucket.admitted,"admitted_upgrade_operations":bucket.upgrades,"outcomes":outcomes}))?;
    }
    writer.flush()
}

pub(super) async fn collect(
    output: &Path,
    mut events: mpsc::Receiver<OperationEvent>,
    failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<Collected, SoakError> {
    let mut buckets = JsonLines::create(&output.join("buckets.jsonl"), 256 * 1024 * 1024)?;
    let mut errors = JsonLines::create(&output.join("errors.jsonl"), 64 * 1024 * 1024)?;
    let mut pending = HashMap::new();
    let mut rows = BTreeMap::<usize, WorkerBucket>::new();
    let mut result = Collected::default();
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut first_failure = None;
    loop {
        let received = tokio::select! {
            event = events.recv() => event,
            _ = ticker.tick() => {
                if first_failure.is_none() && let Err(error) = flush_buckets(&mut buckets, &mut rows) {
                    failed.store(true,std::sync::atomic::Ordering::Release);
                    first_failure = Some(error);
                }
                continue;
            }
        };
        let Some(event) = received else { break };
        match event {
            OperationEvent::Started {
                worker,
                sequence,
                start_ns,
            } => {
                result.offered += 1;
                let count = result.workers.entry(worker).or_default();
                count.offered += 1;
                if pending.insert(worker, (sequence, start_ns)).is_some()
                    || sequence != count.last + 1
                {
                    failed.store(true, std::sync::atomic::Ordering::Release);
                    first_failure
                        .get_or_insert_with(|| fail("duplicate/noncontiguous started operation"));
                }
            }
            OperationEvent::Terminal {
                worker,
                sequence,
                start_ns,
                end_ns,
                phase,
                lane,
                protocol,
                recipe,
                connection_attempts,
                admitted,
                window_id,
                mut raw,
            } => {
                result.received_operations += 1;
                result.connection_attempts += connection_attempts;
                let upgrade = lane == "upgrade";
                result.admitted_http_operations += u64::from(admitted && !upgrade);
                result.admitted_upgrade_operations += u64::from(admitted && upgrade);
                if pending.remove(&worker) != Some((sequence, start_ns)) || end_ns < start_ns {
                    failed.store(true, std::sync::atomic::Ordering::Release);
                    first_failure.get_or_insert_with(|| {
                        fail("missing/duplicate terminal operation or reversed clock")
                    });
                }
                let count = result.workers.entry(worker).or_default();
                count.last = sequence;
                count.received += 1;
                count.connections += connection_attempts;
                count.admitted += u64::from(admitted && !upgrade);
                count.upgrades += u64::from(admitted && upgrade);
                raw["admitted"] = admitted.into();
                raw["upgrade"] = upgrade.into();
                raw["connection_attempted"] = (connection_attempts != 0).into();
                // These are only raw evidence properties, not fault eligibility
                // or a controller success verdict. The verifier reclassifies.
                let non_complete = raw["eof"] != true
                    || raw["status"] != if upgrade { 101 } else { 200 }
                    || raw["error_code"].as_str().is_some()
                    || raw["diagnostics"]
                        .as_array()
                        .is_some_and(|errors| !errors.is_empty());
                result.non_complete += u64::from(non_complete);
                if first_failure.is_some() {
                    continue;
                }
                if non_complete && let Err(error) = errors.write(json!({"worker_id":worker,"operation_seq":sequence,"start_ns":start_ns,"head_ns":raw["head_ns"],"end_ns":end_ns,"phase":phase,"lane":lane,"protocol":protocol,"recipe":recipe,"target":"upstream","window_id":window_id,"connection_attempts":connection_attempts,"admitted":admitted,"raw":raw})) {
                    failed.store(true,std::sync::atomic::Ordering::Release);
                    first_failure = Some(error);
                    continue;
                }
                // Timing belongs to individual anomaly records and bucket bounds,
                // not the success histogram key (which would create one record
                // per operation and unbounded high-throughput artifacts).
                if let Some(object) = raw.as_object_mut() {
                    for key in ["operation_id", "started_ns", "head_ns", "ended_ns"] {
                        object.remove(key);
                    }
                }
                let row = json!({"lane":lane,"protocol":protocol,"phase":phase,"recipe":recipe,"target":"upstream","window_id":window_id,"raw":raw});
                let key = serde_json::to_string(&row).map_err(json_error)?;
                let bucket = rows.entry(worker).or_default();
                if bucket.first == 0 {
                    bucket.first = sequence;
                    bucket.start_ns = start_ns;
                }
                bucket.last = sequence;
                bucket.end_ns = end_ns;
                bucket.connection_attempts += connection_attempts;
                bucket.admitted += u64::from(admitted && !upgrade);
                bucket.upgrades += u64::from(admitted && upgrade);
                let entry = bucket.outcomes.entry(key).or_insert((row, 0));
                if entry.1 == 0 {
                    entry.0["first_start_ns"] = start_ns.into();
                }
                entry.0["last_start_ns"] = start_ns.into();
                entry.0["last_end_ns"] = end_ns.into();
                entry.1 += 1;
            }
        }
    }
    if let Some(error) = first_failure {
        result.artifact_truncated =
            error.to_string().contains("capacity") || error.to_string().contains("size");
        result.fatal_errors.push(error.to_string());
    } else if let Err(error) = flush_buckets(&mut buckets, &mut rows).and_then(|()| errors.flush())
    {
        result.artifact_truncated = true;
        result.fatal_errors.push(error.to_string());
    }
    if !pending.is_empty() || result.offered != result.received_operations {
        result.abandoned_operations = pending.into_iter().map(|(worker,(sequence,start_ns))|json!({"worker_id":worker,"operation_seq":sequence,"start_ns":start_ns,"classification":"abandoned","connection_attempted":null,"admitted":null})).collect();
        result.fatal_errors.push("started operations were abandoned by load workers; unknown connection/admission state is not fabricated".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_drains_an_already_full_result_channel() {
        let directory = tempfile::tempdir().expect("temporary evidence");
        let (send, receive) = mpsc::channel(1);
        send.send(OperationEvent::Started {
            worker: 0,
            sequence: 1,
            start_ns: 10,
        })
        .await
        .expect("started record");
        let path = directory.path().to_owned();
        let collector = tokio::spawn(async move {
            collect(
                &path,
                receive,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .await
        });
        send.send(OperationEvent::Terminal {
            worker: 0,
            sequence: 1,
            start_ns: 10,
            end_ns: 20,
            phase: "steady",
            lane: "complete",
            protocol: "h2",
            recipe: "download",
            connection_attempts: 1,
            admitted: true,
            window_id: None,
            raw: json!({"eof":true,"status":200}),
        })
        .await
        .expect("terminal record");
        drop(send);
        let result = collector
            .await
            .expect("collector joined")
            .expect("collection");
        assert_eq!(result.offered, 1);
        assert_eq!(result.received_operations, 1);
        assert_eq!(result.connection_attempts, 1);
    }

    #[tokio::test]
    async fn connection_failure_is_not_lost_from_offered_denominator() {
        let directory = tempfile::tempdir().expect("temporary evidence");
        let (send, receive) = mpsc::channel(4);
        send.send(OperationEvent::Started {
            worker: 0,
            sequence: 1,
            start_ns: 10,
        })
        .await
        .expect("started record");
        send.send(OperationEvent::Terminal {
            worker: 0,
            sequence: 1,
            start_ns: 10,
            end_ns: 20,
            phase: "steady",
            lane: "complete",
            protocol: "http1",
            recipe: "download",
            connection_attempts: 1,
            admitted: false,
            window_id: None,
            raw: json!({"eof":false,"error_stage":"connection","error_code":"connect_failure"}),
        })
        .await
        .expect("connection failure record");
        drop(send);
        let result = collect(
            directory.path(),
            receive,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .await
        .expect("collection");
        assert_eq!(result.offered, result.received_operations);
        assert_eq!(result.admitted_http_operations, 0);
        assert_eq!(result.non_complete, 1);
        assert!(
            std::fs::read_to_string(directory.path().join("errors.jsonl"))
                .expect("raw errors")
                .contains("connect_failure")
        );
    }

    #[tokio::test]
    async fn abandoned_or_duplicate_results_fail() {
        for duplicate in [false, true] {
            let directory = tempfile::tempdir().expect("temporary evidence");
            let (send, receive) = mpsc::channel(4);
            send.send(OperationEvent::Started {
                worker: 0,
                sequence: 1,
                start_ns: 10,
            })
            .await
            .expect("started record");
            if duplicate {
                send.send(OperationEvent::Started {
                    worker: 0,
                    sequence: 1,
                    start_ns: 10,
                })
                .await
                .expect("duplicate record");
            }
            drop(send);
            let result = collect(
                directory.path(),
                receive,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .await
            .expect("failure summary");
            assert!(!result.fatal_errors.is_empty());
            assert!(!result.abandoned_operations.is_empty());
        }
    }
}
