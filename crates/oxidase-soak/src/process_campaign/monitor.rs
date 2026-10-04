use serde::Serialize;
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub(super) struct Sample {
    pub elapsed_ms: u64,
    pub phase: &'static str,
    pub gateway_pid: u32,
    pub rss_kib: Option<u64>,
    pub open_fds: Option<u64>,
    pub os_threads: Option<u64>,
    pub active_requests: Option<u64>,
    pub active_connections: Option<u64>,
    pub active_streams: Option<u64>,
    pub active_tunnels: Option<u64>,
    pub discovery_tasks: Option<u64>,
    pub health_tasks: Option<u64>,
    pub pools: Option<u64>,
    pub retired_pools: Option<u64>,
    pub old_snapshots: Option<u64>,
    pub cluster_permits: Option<u64>,
    pub retry_permits: Option<u64>,
    pub endpoints: Option<u64>,
    pub retired_admission_counters: Option<u64>,
    pub dns_queries: Option<u64>,
    pub retry_attempts: Option<u64>,
    pub active_health_successes: Option<u64>,
    pub active_health_failures: Option<u64>,
    pub health_transitions: Option<u64>,
}

pub(super) fn sample(
    pid: u32,
    elapsed_ms: u64,
    phase: &'static str,
    metrics: Option<&str>,
    clusters: Option<&Value>,
) -> Sample {
    let proc = std::path::PathBuf::from(format!("/proc/{pid}"));
    let status = std::fs::read_to_string(proc.join("status")).ok();
    let clusters = clusters.and_then(|body| body["clusters"].as_array());
    let sum_json = |name: &str| {
        clusters.and_then(|rows| {
            rows.iter().try_fold(0u64, |sum, cluster| {
                sum.checked_add(cluster[name].as_u64()?)
            })
        })
    };
    let discovery_sum = |name: &str| {
        clusters.and_then(|rows| {
            rows.iter().try_fold(0u64, |sum, cluster| {
                cluster["cluster"].as_str()?;
                cluster["protocol"].as_str()?;
                cluster["policy"].as_str()?;
                match cluster.get("discovery") {
                    None | Some(Value::Null) => Some(sum),
                    Some(Value::Object(discovery)) => {
                        sum.checked_add(discovery.get(name)?.as_u64()?)
                    }
                    Some(_) => None,
                }
            })
        })
    };
    let endpoint_sum = |name: &str| {
        clusters.and_then(|rows| {
            rows.iter().try_fold(0u64, |sum, cluster| {
                cluster["endpoints"]
                    .as_array()?
                    .iter()
                    .try_fold(sum, |sum, endpoint| {
                        sum.checked_add(endpoint[name].as_u64()?)
                    })
            })
        })
    };
    Sample {
        elapsed_ms,
        phase,
        gateway_pid: pid,
        rss_kib: status.as_deref().and_then(|s| status_number(s, "VmRSS:")),
        open_fds: count_entries(&proc.join("fd")),
        os_threads: status.as_deref().and_then(|s| status_number(s, "Threads:")),
        active_requests: metrics.and_then(|m| metric_sum(m, "oxidase_active_requests")),
        active_connections: metrics.and_then(|m| metric_sum(m, "oxidase_active_connections")),
        active_streams: metrics.and_then(|m| metric_sum(m, "oxidase_http2_active_streams")),
        active_tunnels: metrics.and_then(|m| metric_sum(m, "oxidase_active_tunnels")),
        discovery_tasks: metrics
            .and_then(|m| metric_sum(m, "oxidase_discovery_active_supervisors")),
        // Actual scheduled/running supervisor futures, actual Client clone
        // families, and retired snapshot instances; never manager/map lengths.
        // Missing/disabled observations stay unavailable, not fake zero.
        health_tasks: metrics.and_then(|m| {
            selected_metric(m, "oxidase_resource_live", &["kind=\"health_supervisor\""])
        }),
        pools: metrics.and_then(|m| {
            selected_metric(m, "oxidase_resource_live", &["kind=\"proxy_pool_family\""])?
                .checked_add(selected_metric(
                    m,
                    "oxidase_resource_live",
                    &["kind=\"health_pool_family\""],
                )?)
        }),
        retired_pools: metrics.and_then(|m| {
            selected_metric(
                m,
                "oxidase_resource_state",
                &["kind=\"proxy_pool_family\"", "state=\"retired\""],
            )?
            .checked_add(selected_metric(
                m,
                "oxidase_resource_state",
                &["kind=\"health_pool_family\"", "state=\"retired\""],
            )?)
        }),
        old_snapshots: metrics.and_then(|m| {
            selected_metric(
                m,
                "oxidase_resource_state",
                &["kind=\"snapshot\"", "state=\"retired\""],
            )
        }),
        cluster_permits: sum_json("active_requests"),
        retry_permits: sum_json("active_retries"),
        endpoints: discovery_sum("endpoint_count"),
        retired_admission_counters: discovery_sum("retired_admission_counters"),
        dns_queries: metrics.and_then(|m| metric_sum(m, "oxidase_discovery_queries_total")),
        retry_attempts: sum_json("retry_attempts"),
        active_health_successes: endpoint_sum("active_health_successes"),
        active_health_failures: endpoint_sum("active_health_failures"),
        health_transitions: endpoint_sum("health_transitions"),
    }
}

fn count_entries(path: &Path) -> Option<u64> {
    std::fs::read_dir(path)
        .ok()?
        .try_fold(0u64, |count, entry| {
            entry.ok()?;
            count.checked_add(1)
        })
}

fn status_number(text: &str, name: &str) -> Option<u64> {
    text.lines()
        .find(|line| line.starts_with(name))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn selected_metric(text: &str, name: &str, selectors: &[&str]) -> Option<u64> {
    let mut rows = text
        .lines()
        .filter(|line| {
            line.starts_with(name)
                && line.as_bytes().get(name.len()) == Some(&b'{')
                && selectors.iter().all(|selector| line.contains(selector))
        })
        .peekable();
    rows.peek()?;
    rows.try_fold(0u64, |sum, line| {
        sum.checked_add(line.split_whitespace().last()?.parse::<u64>().ok()?)
    })
}

pub(super) fn metric_sum(text: &str, name: &str) -> Option<u64> {
    let mut values = text
        .lines()
        .filter(|line| {
            line.starts_with(name)
                && line
                    .as_bytes()
                    .get(name.len())
                    .is_some_and(|c| *c == b' ' || *c == b'{')
        })
        .peekable();
    values.peek()?;
    values.try_fold(0u64, |sum, line| {
        sum.checked_add(line.split_whitespace().last()?.parse::<u64>().ok()?)
    })
}

pub(super) fn body_terminations(text: &str, reason: &str) -> Option<u64> {
    let selector = format!("reason=\"{reason}\"");
    let mut rows = text
        .lines()
        .filter(|line| {
            line.starts_with("oxidase_response_body_terminations_total{")
                && line.contains(&selector)
        })
        .peekable();
    rows.peek()?;
    rows.try_fold(0u64, |sum, line| {
        sum.checked_add(line.split_whitespace().last()?.parse::<u64>().ok()?)
    })
}

pub(super) fn curve(samples: &[Sample], value: impl Fn(&Sample) -> Option<u64>) -> Value {
    let baseline = samples
        .iter()
        .filter(|s| s.phase == "steady")
        .find_map(&value);
    let peak = samples.iter().filter_map(&value).max();
    let final_live = samples.last().and_then(&value);
    let points = samples
        .iter()
        .filter(|s| s.phase == "steady")
        .filter_map(|s| value(s).map(|v| (s.elapsed_ms as f64 / 1000., v as f64)))
        .collect::<Vec<_>>();
    let slope = if points.len() > 1 {
        let n = points.len() as f64;
        let sx = points.iter().map(|v| v.0).sum::<f64>();
        let sy = points.iter().map(|v| v.1).sum::<f64>();
        let denominator = n * points.iter().map(|v| v.0 * v.0).sum::<f64>() - sx * sx;
        (denominator > 0.)
            .then(|| (n * points.iter().map(|v| v.0 * v.1).sum::<f64>() - sx * sy) / denominator)
    } else {
        None
    };
    serde_json::json!({"baseline_after_warmup":baseline,"peak":peak,"final_live":final_live,"steady_slope_per_second":slope})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_pid_and_unavailable_metrics_remain_null() {
        let value = sample(u32::MAX, 0, "steady", None, None);
        assert!(value.rss_kib.is_none());
        assert!(value.open_fds.is_none());
        assert!(value.active_requests.is_none());
        assert!(value.health_tasks.is_none());
    }
    #[test]
    fn real_lifetime_units_require_all_their_exact_series() {
        let metrics = "oxidase_resource_live{kind=\"health_supervisor\"} 2\noxidase_resource_live{kind=\"health_probe\"} 99\noxidase_resource_live{kind=\"proxy_pool_family\"} 3\noxidase_resource_live{kind=\"health_pool_family\"} 4\noxidase_resource_live{kind=\"proxy_pool_entry\"} 100\noxidase_resource_state{kind=\"snapshot\",state=\"retired\"} 1\noxidase_resource_state{kind=\"snapshot\",state=\"current\"} 9\n";
        let value = sample(u32::MAX, 0, "steady", Some(metrics), None);
        assert_eq!(value.health_tasks, Some(2));
        assert_eq!(value.pools, Some(7));
        assert_eq!(value.old_snapshots, Some(1));
        let incomplete =
            metrics.replace("oxidase_resource_live{kind=\"health_pool_family\"} 4\n", "");
        assert!(
            sample(u32::MAX, 0, "steady", Some(&incomplete), None)
                .pools
                .is_none()
        );
    }
    #[test]
    fn missing_fields_and_overflow_are_unknown_not_fabricated_zero() {
        let incomplete = sample(
            u32::MAX,
            0,
            "steady",
            None,
            Some(&serde_json::json!({"clusters":[{"discovery":{}}]})),
        );
        assert!(incomplete.cluster_permits.is_none());
        assert!(incomplete.retry_permits.is_none());
        assert!(incomplete.endpoints.is_none());
        assert!(incomplete.retired_admission_counters.is_none());
        let empty = sample(
            u32::MAX,
            0,
            "steady",
            None,
            Some(&serde_json::json!({"clusters":[]})),
        );
        assert_eq!(empty.cluster_permits, Some(0));
        assert_eq!(empty.endpoints, Some(0));
        let static_only = sample(
            u32::MAX,
            0,
            "steady",
            None,
            Some(
                &serde_json::json!({"clusters":[{"cluster":"static","protocol":"http1","policy":"round_robin","active_requests":1,"active_retries":0,"discovery":null}]}),
            ),
        );
        assert_eq!(static_only.cluster_permits, Some(1));
        assert_eq!(static_only.endpoints, Some(0));
        assert!(
            sample(
                u32::MAX,
                0,
                "steady",
                None,
                Some(&serde_json::json!({"clusters":[{}]}))
            )
            .endpoints
            .is_none()
        );
        let overflow = sample(
            u32::MAX,
            0,
            "steady",
            None,
            Some(
                &serde_json::json!({"clusters":[{"active_requests":u64::MAX},{"active_requests":1}]}),
            ),
        );
        assert!(overflow.cluster_permits.is_none());
    }
    #[test]
    fn parser_requires_exact_metric_name_and_reads_linux_units() {
        assert_eq!(
            status_number("Name: gateway\nVmRSS:\t512 kB\nThreads:\t4\n", "VmRSS:"),
            Some(512)
        );
        assert_eq!(
            metric_sum("metric 2\nmetric{a=\"b\"} 3\nmetric_suffix 99\n", "metric"),
            Some(5)
        );
        assert_eq!(metric_sum("different 2\n", "metric"), None);
        assert_eq!(
            metric_sum("metric 1\nmetric{a=\"b\"} invalid\n", "metric"),
            None
        );
        assert_eq!(
            metric_sum(&format!("metric {}\nmetric 1\n", u64::MAX), "metric"),
            None
        );
    }
    #[test]
    fn curve_uses_steady_samples_and_does_not_invent_process_exit_zero() {
        let mut first = sample(u32::MAX, 1000, "steady", None, None);
        first.rss_kib = Some(10);
        let mut second = first.clone();
        second.elapsed_ms = 2000;
        second.rss_kib = Some(20);
        let mut cool = second.clone();
        cool.phase = "cooldown";
        cool.rss_kib = Some(15);
        let value = curve(&[first.clone(), second.clone(), cool], |s| s.rss_kib);
        assert_eq!(value["steady_slope_per_second"], 10.);
        assert_eq!(value["final_live"], 15);
        let unknown = sample(u32::MAX, 3000, "cooldown", None, None);
        assert!(curve(&[first, second, unknown], |s| s.rss_kib)["final_live"].is_null());
    }
}
