//! Bounded evidence writer and continuous operation collector, validation-only.
//! No controller verdict is used by the independent verifier.

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::path::Path;

use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::{RESOURCE_REQUESTS_PER_CONNECTION, SoakError, fail, io_error, json_error};

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
    RetirementStarted {
        worker: usize,
        connection_epoch: u64,
        after_sequence: u64,
        start_ns: u64,
        protocol: &'static str,
        submitted: u64,
    },
    RetirementTerminal {
        worker: usize,
        connection_epoch: u64,
        after_sequence: u64,
        start_ns: u64,
        end_ns: u64,
        protocol: &'static str,
        submitted: u64,
        driver_exit: Value,
    },
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

struct CompactFaultRun {
    row: Value,
    first: u64,
    last: u64,
    first_start_ns: u64,
    last_start_ns: u64,
    last_end_ns: u64,
    min_head_ns: u64,
    max_head_ns: u64,
}

fn normalized_wire(mut raw: Value) -> Value {
    if let Some(object) = raw.as_object_mut() {
        for key in ["operation_id", "started_ns", "head_ns", "ended_ns"] {
            object.remove(key);
        }
    }
    raw
}

#[expect(clippy::too_many_arguments, reason = "complete raw operation boundary")]
fn compact_503_eligible(
    raw: &Value,
    window_id: &Option<String>,
    phase: &str,
    lane: &str,
    protocol: &str,
    admitted: bool,
    start_ns: u64,
    end_ns: u64,
) -> bool {
    phase == "steady"
        && lane == "churn"
        && matches!(protocol, "http1" | "h2")
        && admitted
        && window_id.as_ref().is_some_and(|id| !id.is_empty())
        && raw["status"] == 503
        && raw["eof"] == true
        && raw.get("error_code").is_some_and(Value::is_null)
        && raw.get("error_stage").is_some_and(Value::is_null)
        && raw["cancelled"] == false
        && raw["upgrade"] == false
        && raw["connection_epoch"]
            .as_u64()
            .is_some_and(|epoch| epoch > 0)
        && raw["diagnostics"].as_array().is_some_and(Vec::is_empty)
        && raw["head_ns"]
            .as_u64()
            .is_some_and(|head| start_ns <= head && head <= end_ns)
}

fn flush_compact_worker(
    writer: &mut JsonLines,
    runs: &mut BTreeMap<usize, CompactFaultRun>,
    result: &mut Collected,
    worker: usize,
) -> Result<(), SoakError> {
    let Some(run) = runs.remove(&worker) else {
        return Ok(());
    };
    let count = run
        .last
        .checked_sub(run.first)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| fail("compact fault range overflow"))?;
    let mut row = run.row;
    row["schema_version"] = "oxidase.resource-compact-fault/v1".into();
    row["worker_id"] = worker.into();
    row["first_operation_seq"] = run.first.into();
    row["last_operation_seq"] = run.last.into();
    row["count"] = count.into();
    row["first_start_ns"] = run.first_start_ns.into();
    row["last_start_ns"] = run.last_start_ns.into();
    row["last_end_ns"] = run.last_end_ns.into();
    row["min_head_ns"] = run.min_head_ns.into();
    row["max_head_ns"] = run.max_head_ns.into();
    writer.write(row)?;
    result.compact_503_rows += 1;
    result.compact_503_operations += count;
    Ok(())
}

fn flush_compact(
    writer: &mut JsonLines,
    runs: &mut BTreeMap<usize, CompactFaultRun>,
    result: &mut Collected,
) -> Result<(), SoakError> {
    while let Some(worker) = runs.keys().next().copied() {
        flush_compact_worker(writer, runs, result, worker)?;
    }
    writer.flush()
}

#[expect(clippy::too_many_arguments, reason = "complete raw operation boundary")]
fn append_compact(
    writer: &mut JsonLines,
    runs: &mut BTreeMap<usize, CompactFaultRun>,
    result: &mut Collected,
    worker: usize,
    sequence: u64,
    start_ns: u64,
    head_ns: u64,
    end_ns: u64,
    row: Value,
) -> Result<(), SoakError> {
    if let Some(run) = runs.get_mut(&worker)
        && run.row == row
        && run.last.checked_add(1) == Some(sequence)
        && start_ns >= run.last_end_ns
    {
        run.last = sequence;
        run.last_start_ns = start_ns;
        run.last_end_ns = end_ns;
        run.min_head_ns = run.min_head_ns.min(head_ns);
        run.max_head_ns = run.max_head_ns.max(head_ns);
        return Ok(());
    }
    flush_compact_worker(writer, runs, result, worker)?;
    runs.insert(
        worker,
        CompactFaultRun {
            row,
            first: sequence,
            last: sequence,
            first_start_ns: start_ns,
            last_start_ns: start_ns,
            last_end_ns: end_ns,
            min_head_ns: head_ns,
            max_head_ns: head_ns,
        },
    );
    Ok(())
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
    compact_503_rows: u64,
    compact_503_operations: u64,
    retirement_started: u64,
    retirement_received: u64,
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
            "non_complete":self.non_complete,"compact_503_rows":self.compact_503_rows,
            "compact_503_operations":self.compact_503_operations,
            "client_retirements_started":self.retirement_started,"client_retirements_received":self.retirement_received,
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
    let mut compact = JsonLines::create(
        &output.join("compact-fault-results.jsonl"),
        64 * 1024 * 1024,
    )?;
    let mut compact_runs = BTreeMap::new();
    let mut retirements =
        JsonLines::create(&output.join("client-retirements.jsonl"), 64 * 1024 * 1024)?;
    let mut retiring = HashMap::new();
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
                if first_failure.is_none() && let Err(error) = flush_compact(&mut compact, &mut compact_runs, &mut result)
                    .and_then(|()| flush_buckets(&mut buckets, &mut rows)) {
                    failed.store(true,std::sync::atomic::Ordering::Release);
                    first_failure = Some(error);
                }
                continue;
            }
        };
        let Some(event) = received else { break };
        match event {
            OperationEvent::RetirementStarted {
                worker,
                connection_epoch,
                after_sequence,
                start_ns,
                protocol,
                submitted,
            } => {
                result.retirement_started += 1;
                if retiring
                    .insert(
                        worker,
                        (
                            connection_epoch,
                            after_sequence,
                            start_ns,
                            protocol,
                            submitted,
                        ),
                    )
                    .is_some()
                    || pending.contains_key(&worker)
                    || result
                        .workers
                        .get(&worker)
                        .is_none_or(|count| count.last != after_sequence)
                    || submitted != RESOURCE_REQUESTS_PER_CONNECTION
                {
                    failed.store(true, std::sync::atomic::Ordering::Release);
                    first_failure.get_or_insert_with(|| {
                        fail("invalid or overlapping client retirement boundary")
                    });
                }
                // FIFO places this after terminal N and before started N+1.
                // End only this worker's bucket so the offline oracle can prove
                // actual retirement-before-next-admission without per-op success logs.
                if first_failure.is_none() {
                    let mut boundary = BTreeMap::new();
                    if let Some(bucket) = rows.remove(&worker) {
                        boundary.insert(worker, bucket);
                    }
                    let record = json!({"schema_version":"oxidase.resource-client-retirement/v1","kind":"started","retirement_id":format!("{worker}:{connection_epoch}"),"worker_id":worker,"protocol":protocol,"connection_epoch":connection_epoch,"start_ns":start_ns,"after_operation_seq":after_sequence,"next_operation_seq":after_sequence+1,"request_budget":RESOURCE_REQUESTS_PER_CONNECTION,"submitted_requests":submitted});
                    if let Err(error) = flush_compact(&mut compact, &mut compact_runs, &mut result)
                        .and_then(|()| flush_buckets(&mut buckets, &mut boundary))
                        .and_then(|()| retirements.write(record))
                    {
                        failed.store(true, std::sync::atomic::Ordering::Release);
                        first_failure = Some(error);
                    }
                }
            }
            OperationEvent::RetirementTerminal {
                worker,
                connection_epoch,
                after_sequence,
                start_ns,
                end_ns,
                protocol,
                submitted,
                driver_exit,
            } => {
                result.retirement_received += 1;
                if retiring.remove(&worker)
                    != Some((
                        connection_epoch,
                        after_sequence,
                        start_ns,
                        protocol,
                        submitted,
                    ))
                    || end_ns < start_ns
                    || driver_exit["result"] != "completed"
                    || driver_exit["join_acknowledged"] != true
                {
                    failed.store(true, std::sync::atomic::Ordering::Release);
                    first_failure.get_or_insert_with(|| {
                        fail("client retirement driver was not actually completed/joined")
                    });
                }
                let record = json!({"schema_version":"oxidase.resource-client-retirement/v1","kind":"terminal","retirement_id":format!("{worker}:{connection_epoch}"),"worker_id":worker,"protocol":protocol,"connection_epoch":connection_epoch,"start_ns":start_ns,"end_ns":end_ns,"after_operation_seq":after_sequence,"next_operation_seq":after_sequence+1,"request_budget":RESOURCE_REQUESTS_PER_CONNECTION,"submitted_requests":submitted,"driver_exit":driver_exit});
                // Even failed acknowledgement is kept when writer capacity is
                // still available; fatal receipt cannot masquerade as success.
                if let Err(error) = retirements.write(record) {
                    failed.store(true, std::sync::atomic::Ordering::Release);
                    first_failure.get_or_insert(error);
                }
            }
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
                let evidence = if compact_503_eligible(
                    &raw, &window_id, phase, lane, protocol, admitted, start_ns, end_ns,
                ) {
                    let row = json!({"phase":phase,"lane":lane,"protocol":protocol,"recipe":recipe,
                        "target":"upstream","window_id":window_id,"connection_attempts":connection_attempts,
                        "admitted":admitted,"raw":normalized_wire(raw.clone())});
                    append_compact(
                        &mut compact,
                        &mut compact_runs,
                        &mut result,
                        worker,
                        sequence,
                        start_ns,
                        raw["head_ns"]
                            .as_u64()
                            .expect("eligibility requires actual head time"),
                        end_ns,
                        row,
                    )
                } else {
                    flush_compact_worker(&mut compact,&mut compact_runs,&mut result,worker).and_then(|()| {
                        if non_complete {
                            errors.write(json!({"worker_id":worker,"operation_seq":sequence,"start_ns":start_ns,"head_ns":raw["head_ns"],"end_ns":end_ns,"phase":phase,"lane":lane,"protocol":protocol,"recipe":recipe,"target":"upstream","window_id":window_id,"connection_attempts":connection_attempts,"admitted":admitted,"raw":raw}))
                        } else { Ok(()) }
                    })
                };
                if let Err(error) = evidence {
                    failed.store(true, std::sync::atomic::Ordering::Release);
                    first_failure = Some(error);
                    continue;
                }
                // Timing belongs to individual anomaly records and bucket bounds,
                // not the success histogram key (which would create one record
                // per operation and unbounded high-throughput artifacts).
                raw = normalized_wire(raw);
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
    } else if let Err(error) = flush_compact(&mut compact, &mut compact_runs, &mut result)
        .and_then(|()| flush_buckets(&mut buckets, &mut rows))
        .and_then(|()| errors.flush())
        .and_then(|()| retirements.flush())
    {
        result.artifact_truncated = true;
        result.fatal_errors.push(error.to_string());
    }
    if !pending.is_empty() || result.offered != result.received_operations {
        result.abandoned_operations = pending.into_iter().map(|(worker,(sequence,start_ns))|json!({"worker_id":worker,"operation_seq":sequence,"start_ns":start_ns,"classification":"abandoned","connection_attempted":null,"admitted":null})).collect();
        result.fatal_errors.push("started operations were abandoned by load workers; unknown connection/admission state is not fabricated".into());
    }
    if !retiring.is_empty() || result.retirement_started != result.retirement_received {
        result.fatal_errors.push(
            "started client retirement was abandoned or lacked terminal acknowledgement".into(),
        );
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fault_raw() -> Value {
        json!({"status":503,"eof":true,"protocol":"h2","connection_epoch":1,
            "error_code":null,"error_stage":null,"diagnostics":[],"cancelled":false,
            "body_bytes":19,"body_sha256":"recorded-digest","data_observed":true})
    }

    fn evidence_rows(path: &Path, name: &str) -> Vec<Value> {
        std::fs::read_to_string(path.join(name))
            .expect("written journal")
            .lines()
            .map(|line| serde_json::from_str(line).expect("valid JSON row"))
            .collect()
    }

    #[tokio::test]
    async fn windowed_identical_503s_are_lossless_bounded_ranges_and_stop_drains_queue() {
        let directory = tempfile::tempdir().expect("synthetic fault evidence");
        let (send, receive) = mpsc::channel(1);
        let path = directory.path().to_owned();
        let collector =
            tokio::spawn(async move { collect(&path, receive, std::sync::Arc::default()).await });
        for sequence in 1..=100 {
            send.send(OperationEvent::Started {
                worker: 0,
                sequence,
                start_ns: sequence * 10,
            })
            .await
            .expect("started");
            let mut raw = fault_raw();
            raw["operation_id"] = format!("0:{sequence}").into();
            raw["started_ns"] = (sequence * 10).into();
            raw["head_ns"] = (sequence * 10 + 1).into();
            raw["ended_ns"] = (sequence * 10 + 2).into();
            send.send(OperationEvent::Terminal {
                worker: 0,
                sequence,
                start_ns: sequence * 10,
                end_ns: sequence * 10 + 2,
                phase: "steady",
                lane: "churn",
                protocol: "h2",
                recipe: "download",
                connection_attempts: 0,
                admitted: true,
                window_id: Some("closed-window".into()),
                raw,
            })
            .await
            .expect("terminal");
        }
        drop(send);
        let counted = collector
            .await
            .expect("actual collector join")
            .expect("receipt");
        assert!(counted.fatal_errors.is_empty());
        assert_eq!(
            (
                counted.offered,
                counted.received_operations,
                counted.non_complete
            ),
            (100, 100, 100)
        );
        assert_eq!(counted.compact_503_operations, 100);
        let compact = evidence_rows(directory.path(), "compact-fault-results.jsonl");
        let buckets = evidence_rows(directory.path(), "buckets.jsonl");
        assert_eq!(counted.compact_503_rows, compact.len() as u64);
        assert!(evidence_rows(directory.path(), "errors.jsonl").is_empty());
        assert_eq!(
            compact
                .iter()
                .map(|row| row["count"].as_u64().expect("count"))
                .sum::<u64>(),
            100
        );
        for row in compact {
            let first = row["first_operation_seq"].as_u64().expect("first");
            let last = row["last_operation_seq"].as_u64().expect("last");
            assert_eq!(row["count"], last - first + 1);
            assert_eq!(row["first_start_ns"], first * 10);
            assert_eq!(row["last_start_ns"], last * 10);
            assert_eq!(row["last_end_ns"], last * 10 + 2);
            assert_eq!(row["min_head_ns"], first * 10 + 1);
            assert_eq!(row["max_head_ns"], last * 10 + 1);
            assert!(row["raw"].get("operation_id").is_none());
            assert!(row["raw"].get("head_ns").is_none());
            assert!(
                buckets.iter().any(
                    |bucket| bucket["first_operation_seq"].as_u64().expect("first") <= first
                        && last <= bucket["last_operation_seq"].as_u64().expect("last")
                ),
                "range cannot cross a bucket"
            );
        }
    }

    #[tokio::test]
    async fn normal_and_other_errors_flush_runs_and_unknown_503s_remain_full_records() {
        let directory = tempfile::tempdir().expect("mixed synthetic evidence");
        let (send, receive) = mpsc::channel(1);
        let path = directory.path().to_owned();
        let collector =
            tokio::spawn(async move { collect(&path, receive, std::sync::Arc::default()).await });
        for sequence in 1..=8 {
            let mut raw = fault_raw();
            let mut window_id = Some("closed-window".into());
            let mut lane = "churn";
            if sequence == 3 {
                raw["status"] = 200.into();
            }
            if sequence == 4 {
                raw["eof"] = false.into();
                raw["error_code"] = "body_error".into();
            }
            if sequence == 5 {
                window_id = None;
            }
            if sequence == 6 {
                lane = "healthy";
            }
            if sequence == 7 {
                raw["cancelled"] = true.into();
            }
            raw["head_ns"] = (sequence * 10 + 1).into();
            send.send(OperationEvent::Started {
                worker: 0,
                sequence,
                start_ns: sequence * 10,
            })
            .await
            .expect("started");
            send.send(OperationEvent::Terminal {
                worker: 0,
                sequence,
                start_ns: sequence * 10,
                end_ns: sequence * 10 + 2,
                phase: "steady",
                lane,
                protocol: "h2",
                recipe: "download",
                connection_attempts: 0,
                admitted: true,
                window_id,
                raw,
            })
            .await
            .expect("terminal");
        }
        drop(send);
        let counted = collector.await.expect("join").expect("receipt");
        assert!(counted.fatal_errors.is_empty());
        assert_eq!(
            (
                counted.offered,
                counted.received_operations,
                counted.non_complete
            ),
            (8, 8, 7)
        );
        assert_eq!(counted.compact_503_operations, 3);
        let errors = evidence_rows(directory.path(), "errors.jsonl");
        assert_eq!(
            errors
                .iter()
                .map(|row| row["operation_seq"].as_u64().expect("seq"))
                .collect::<Vec<_>>(),
            vec![4, 5, 6, 7]
        );
        let ranges = evidence_rows(directory.path(), "compact-fault-results.jsonl");
        assert!(
            ranges
                .iter()
                .all(|row| row["last_operation_seq"].as_u64().expect("last") <= 2
                    || row["first_operation_seq"] == 8)
        );
    }

    #[test]
    fn context_window_epoch_gaps_and_bucket_boundary_end_current_runs() {
        let directory = tempfile::tempdir().expect("ranges");
        let mut writer =
            JsonLines::create(&directory.path().join("ranges.jsonl"), 64 * 1024 * 1024)
                .expect("writer");
        let mut runs = BTreeMap::new();
        let mut result = Collected::default();
        let base = json!({"phase":"steady","lane":"churn","protocol":"h2","recipe":"download",
            "target":"upstream","window_id":"one","connection_attempts":0,"admitted":true,"raw":fault_raw()});
        for (sequence, window, epoch, connections) in [
            (1, "one", 1, 0),
            (2, "one", 1, 0),
            (3, "two", 1, 0),
            (4, "two", 2, 0),
            (5, "two", 2, 1),
            (7, "two", 2, 1),
        ] {
            let mut row = base.clone();
            row["window_id"] = window.into();
            row["raw"]["connection_epoch"] = epoch.into();
            row["connection_attempts"] = connections.into();
            append_compact(
                &mut writer,
                &mut runs,
                &mut result,
                0,
                sequence,
                sequence * 10,
                sequence * 10 + 1,
                sequence * 10 + 2,
                row,
            )
            .expect("append");
        }
        flush_compact(&mut writer, &mut runs, &mut result).expect("bucket boundary flush");
        append_compact(&mut writer, &mut runs, &mut result, 0, 8, 80, 81, 82, base)
            .expect("next bucket");
        flush_compact(&mut writer, &mut runs, &mut result).expect("stop flush");
        let rows = evidence_rows(directory.path(), "ranges.jsonl");
        assert_eq!(
            rows.iter()
                .map(|row| (
                    row["first_operation_seq"].as_u64().expect("first"),
                    row["last_operation_seq"].as_u64().expect("last")
                ))
                .collect::<Vec<_>>(),
            vec![(1, 2), (3, 3), (4, 4), (5, 5), (7, 7), (8, 8)]
        );
        assert_eq!(result.compact_503_operations, 7);
        assert!(runs.is_empty());
    }

    #[test]
    fn compact_capacity_failure_is_explicit_and_does_not_fabricate_written_counts() {
        let directory = tempfile::tempdir().expect("capacity evidence");
        let mut writer =
            JsonLines::create(&directory.path().join("tiny.jsonl"), 1).expect("writer");
        let mut runs = BTreeMap::new();
        let mut result = Collected::default();
        append_compact(
            &mut writer,
            &mut runs,
            &mut result,
            0,
            1,
            10,
            11,
            12,
            json!({"raw":fault_raw()}),
        )
        .expect("pending");
        assert!(
            flush_compact(&mut writer, &mut runs, &mut result)
                .expect_err("capacity fail")
                .to_string()
                .contains("capacity")
        );
        assert_eq!(
            (result.compact_503_rows, result.compact_503_operations),
            (0, 0)
        );
        assert!(evidence_rows(directory.path(), "tiny.jsonl").is_empty());
    }

    #[tokio::test]
    async fn compact_ranges_end_at_real_retirement_journal_boundary() {
        let directory = tempfile::tempdir().expect("synthetic collector boundary");
        let (send, receive) = mpsc::channel(1);
        let path = directory.path().to_owned();
        let collector =
            tokio::spawn(async move { collect(&path, receive, std::sync::Arc::default()).await });
        for sequence in 1..=1001 {
            if sequence == 1001 {
                send.send(OperationEvent::RetirementStarted {
                    worker: 0,
                    connection_epoch: 1,
                    after_sequence: 1000,
                    start_ns: 11000,
                    protocol: "h2",
                    submitted: 1000,
                })
                .await
                .expect("retirement started");
                send.send(OperationEvent::RetirementTerminal {
                    worker: 0,
                    connection_epoch: 1,
                    after_sequence: 1000,
                    start_ns: 11000,
                    end_ns: 12000,
                    protocol: "h2",
                    submitted: 1000,
                    driver_exit: json!({"result":"completed","join_acknowledged":true}),
                })
                .await
                .expect("retirement terminal");
            }
            let start_ns = if sequence == 1001 {
                13000
            } else {
                sequence * 10
            };
            let mut raw = fault_raw();
            raw["head_ns"] = (start_ns + 1).into();
            raw["connection_epoch"] = if sequence == 1001 { 2.into() } else { 1.into() };
            send.send(OperationEvent::Started {
                worker: 0,
                sequence,
                start_ns,
            })
            .await
            .expect("started");
            send.send(OperationEvent::Terminal {
                worker: 0,
                sequence,
                start_ns,
                end_ns: start_ns + 2,
                phase: "steady",
                lane: "churn",
                protocol: "h2",
                recipe: "download",
                connection_attempts: u64::from(sequence == 1 || sequence == 1001),
                admitted: true,
                window_id: Some("closed-window".into()),
                raw,
            })
            .await
            .expect("terminal");
        }
        drop(send);
        let counted = collector
            .await
            .expect("actual collector join")
            .expect("receipt");
        assert!(counted.fatal_errors.is_empty());
        assert_eq!(
            (
                counted.offered,
                counted.received_operations,
                counted.compact_503_operations
            ),
            (1001, 1001, 1001)
        );
        assert_eq!(
            (counted.retirement_started, counted.retirement_received),
            (1, 1)
        );
        let ranges = evidence_rows(directory.path(), "compact-fault-results.jsonl");
        let buckets = evidence_rows(directory.path(), "buckets.jsonl");
        for row in ranges {
            let first = row["first_operation_seq"].as_u64().expect("first");
            let last = row["last_operation_seq"].as_u64().expect("last");
            assert!(
                last <= 1000 || first == 1001,
                "range crossed retirement boundary"
            );
            if last <= 1000 {
                assert!(row["last_end_ns"].as_u64().expect("time") < 11000);
            } else {
                assert!(row["first_start_ns"].as_u64().expect("time") >= 12000);
            }
            assert!(
                buckets.iter().any(
                    |bucket| bucket["first_operation_seq"].as_u64().expect("first") <= first
                        && last <= bucket["last_operation_seq"].as_u64().expect("last")
                ),
                "range crossed bucket"
            );
        }
    }

    #[tokio::test]
    async fn normal_retirement_flushes_a_provable_before_next_admission_boundary() {
        let directory = tempfile::tempdir().expect("synthetic collector evidence");
        let (send, receive) = mpsc::channel(8);
        let path = directory.path().to_owned();
        let collector = tokio::spawn(async move {
            collect(
                &path,
                receive,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .await
        });
        for sequence in 1..=1000 {
            send.send(OperationEvent::Started {
                worker: 0,
                sequence,
                start_ns: sequence * 2,
            })
            .await
            .expect("started");
            send.send(OperationEvent::Terminal {
                worker: 0,
                sequence,
                start_ns: sequence * 2,
                end_ns: sequence * 2 + 1,
                phase: "steady",
                lane: "healthy",
                protocol: "h2",
                recipe: "download",
                connection_attempts: u64::from(sequence == 1),
                admitted: true,
                window_id: None,
                raw: json!({"status":200,"eof":true,"connection_epoch":1}),
            })
            .await
            .expect("terminal");
        }
        send.send(OperationEvent::RetirementStarted {
            worker: 0,
            connection_epoch: 1,
            after_sequence: 1000,
            start_ns: 3000,
            protocol: "h2",
            submitted: 1000,
        })
        .await
        .expect("retirement start");
        send.send(OperationEvent::RetirementTerminal {
            worker: 0,
            connection_epoch: 1,
            after_sequence: 1000,
            start_ns: 3000,
            end_ns: 4000,
            protocol: "h2",
            submitted: 1000,
            driver_exit: json!({"result":"completed","join_acknowledged":true}),
        })
        .await
        .expect("actual join");
        send.send(OperationEvent::Started {
            worker: 0,
            sequence: 1001,
            start_ns: 5000,
        })
        .await
        .expect("next started");
        send.send(OperationEvent::Terminal {
            worker: 0,
            sequence: 1001,
            start_ns: 5000,
            end_ns: 6000,
            phase: "steady",
            lane: "healthy",
            protocol: "h2",
            recipe: "download",
            connection_attempts: 1,
            admitted: true,
            window_id: None,
            raw: json!({"status":200,"eof":true,"connection_epoch":2}),
        })
        .await
        .expect("next terminal");
        drop(send);
        let counted = collector.await.expect("joined").expect("counted");
        assert_eq!(counted.offered, 1001);
        assert_eq!(counted.received_operations, 1001);
        assert_eq!(counted.retirement_started, 1);
        assert_eq!(counted.retirement_received, 1);
        assert!(counted.fatal_errors.is_empty());
        let rows = std::fs::read_to_string(directory.path().join("buckets.jsonl"))
            .expect("buckets")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("JSON"))
            .collect::<Vec<_>>();
        let previous = rows
            .iter()
            .find(|row| row["last_operation_seq"] == 1000)
            .expect("flushed old connection");
        let next = rows
            .iter()
            .find(|row| row["first_operation_seq"] == 1001)
            .expect("new connection");
        assert!(previous["bucket_end_ns"].as_u64().expect("time") <= 3000);
        assert!(next["bucket_start_ns"].as_u64().expect("time") >= 4000);
        let raw = std::fs::read_to_string(directory.path().join("client-retirements.jsonl"))
            .expect("independent journal");
        assert_eq!(raw.lines().count(), 2);
    }

    #[tokio::test]
    async fn abandoned_retirement_is_not_a_completed_worker_operation() {
        let directory = tempfile::tempdir().expect("synthetic failure evidence");
        let (send, receive) = mpsc::channel(1);
        let path = directory.path().to_owned();
        let collector = tokio::spawn(async move {
            collect(
                &path,
                receive,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .await
        });
        send.send(OperationEvent::RetirementStarted {
            worker: 0,
            connection_epoch: 1,
            after_sequence: 0,
            start_ns: 3000,
            protocol: "h2",
            submitted: 1000,
        })
        .await
        .expect("started invalid/abandoned cleanup");
        drop(send);
        let counted = collector.await.expect("join").expect("receipt");
        assert_eq!(counted.offered, 0, "cleanup never enters HTTP denominator");
        assert_eq!(counted.retirement_started, 1);
        assert_eq!(counted.retirement_received, 0);
        assert!(!counted.fatal_errors.is_empty());
    }

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
