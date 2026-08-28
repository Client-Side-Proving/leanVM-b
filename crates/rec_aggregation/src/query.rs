//! Versioned application queries and workload-independent tree planning.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const QUERY_SCHEMA_VERSION: u32 = 1;

fn default_arities() -> Vec<usize> {
    (2..=16).collect()
}

fn default_rates() -> Vec<usize> {
    (1..=4).collect()
}

fn default_rate_precision() -> f64 {
    0.05
}

fn default_remote_fraction() -> f64 {
    1.0
}

fn default_bandwidth_window() -> f64 {
    1.0
}

fn default_processes() -> usize {
    1
}

/// Complete reproducible input to one benchmark search.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkQuery {
    pub schema_version: u32,
    pub workload: WorkloadConfig,
    pub arrivals: ArrivalConfig,
    pub root_policy: RootPolicy,
    pub root_lifecycle: RootLifecycle,
    pub hardware_limits: HardwareLimits,
    #[serde(default)]
    pub deadlines: DeadlineLimits,
    pub network: NetworkConfig,
    #[serde(default)]
    pub search: SearchConfig,
}

impl BenchmarkQuery {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|error| format!("read benchmark query {}: {error}", path.display()))?;
        let query: Self = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse benchmark query {}: {error}", path.display()))?;
        query.validate()?;
        Ok(query)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != QUERY_SCHEMA_VERSION {
            return Err(format!(
                "benchmark query schema_version must be {QUERY_SCHEMA_VERSION}, got {}",
                self.schema_version
            ));
        }
        self.workload.validate()?;
        self.arrivals.validate()?;
        self.root_policy.validate()?;
        if self.workload.adapter == "xmss"
            && matches!(
                self.root_policy,
                RootPolicy::Periodic {
                    empty_tick: EmptyTickPolicy::AdapterProof,
                    ..
                }
            )
        {
            return Err("the XMSS workload adapter cannot produce a proof for an empty periodic tick".into());
        }
        self.hardware_limits.validate()?;
        self.deadlines.validate()?;
        self.network.validate()?;
        self.search.validate()?;
        if matches!(self.root_lifecycle, RootLifecycle::Rolling)
            && self
                .workload
                .leaf_log_inv_rates
                .iter()
                .any(|rate| !self.search.parent_log_inv_rates.contains(rate))
        {
            return Err(
                "rolling roots require every allowed incoming WHIR rate to also be an allowed parent WHIR rate".into(),
            );
        }
        if matches!(self.arrivals.model, ArrivalModel::Trace) {
            let first = self.arrivals.events.first().expect("validated nonempty trace");
            let last = self.arrivals.events.last().expect("validated nonempty trace");
            if self.arrivals.events.len() < 2 || last.seconds <= first.seconds {
                return Err(
                    "an arrival trace needs at least two events separated in time to define its mean input rate".into(),
                );
            }
            let trace_rate = (self.arrivals.events.len() - 1) as f64 / (last.seconds - first.seconds);
            let tolerance = trace_rate.abs().max(1.0) * 1e-9;
            if (self.search.min_arrival_rate - trace_rate).abs() > tolerance
                || (self.search.max_arrival_rate - trace_rate).abs() > tolerance
            {
                return Err(format!(
                    "an exact arrival trace has a mean rate of {trace_rate} inputs/s between its first and last event; search min_arrival_rate and max_arrival_rate must both equal that rate"
                ));
            }
        }
        Ok(())
    }
}

/// Workload-specific proof source behind the common benchmark interface.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadConfig {
    pub adapter: String,
    pub adapter_schema_version: u32,
    pub proof_source: ProofSource,
    pub adapter_config: Value,
    #[serde(default = "default_rates")]
    pub leaf_log_inv_rates: Vec<usize>,
}

/// How the workload adapter obtains valid leaf proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProofSource {
    Generated,
    SerializedCorpus { path: String },
    Trace { path: String },
}

impl WorkloadConfig {
    fn validate(&self) -> Result<(), String> {
        if self.adapter.trim().is_empty() {
            return Err("workload adapter must not be empty".into());
        }
        if self.adapter_schema_version == 0 {
            return Err("workload adapter_schema_version must be positive".into());
        }
        match &self.proof_source {
            ProofSource::Generated => {}
            ProofSource::SerializedCorpus { path } | ProofSource::Trace { path } if path.trim().is_empty() => {
                return Err("workload proof source path must not be empty".into());
            }
            ProofSource::SerializedCorpus { .. } | ProofSource::Trace { .. } => {}
        }
        if self.adapter == "xmss" && !matches!(self.proof_source, ProofSource::Generated) {
            return Err("the XMSS workload adapter in this checkout supports generated leaf proofs only".into());
        }
        validate_rates("workload leaf_log_inv_rates", &self.leaf_log_inv_rates)
    }
}

/// One source in a mixed arrival stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArrivalSource {
    pub name: String,
    pub rate_fraction: f64,
    #[serde(default)]
    pub workload_variant: Value,
}

/// One explicitly timestamped arrival.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceArrival {
    pub seconds: f64,
    #[serde(default)]
    pub source: usize,
}

/// An application-supplied change in offered rate.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArrivalPhase {
    pub duration_seconds: f64,
    pub rate_multiplier: f64,
}

/// Arrival-time model. Candidate rates scale the fixed-interval and Poisson
/// models. A trace is replayed exactly.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArrivalModel {
    FixedInterval,
    Poisson,
    Trace,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArrivalConfig {
    #[serde(rename = "kind")]
    pub model: ArrivalModel,
    #[serde(default)]
    pub events: Vec<TraceArrival>,
    #[serde(default)]
    pub sources: Vec<ArrivalSource>,
    #[serde(default)]
    pub phases: Vec<ArrivalPhase>,
    #[serde(default = "default_seed")]
    pub seed: u64,
}

fn default_seed() -> u64 {
    7
}

impl ArrivalConfig {
    fn validate(&self) -> Result<(), String> {
        if !self.sources.is_empty() {
            let mut total = 0.0;
            for source in &self.sources {
                if source.name.trim().is_empty() {
                    return Err("arrival source name must not be empty".into());
                }
                if !source.rate_fraction.is_finite() || source.rate_fraction <= 0.0 {
                    return Err("arrival source rate_fraction must be finite and positive".into());
                }
                total += source.rate_fraction;
            }
            if (total - 1.0).abs() > 1e-9 {
                return Err(format!("arrival source rate fractions must sum to 1, got {total}"));
            }
        }
        for phase in &self.phases {
            if !phase.duration_seconds.is_finite() || phase.duration_seconds <= 0.0 {
                return Err("arrival phase duration_seconds must be finite and positive".into());
            }
            if !phase.rate_multiplier.is_finite() || phase.rate_multiplier <= 0.0 {
                return Err("arrival phase rate_multiplier must be finite and positive".into());
            }
        }
        if matches!(self.model, ArrivalModel::Trace) {
            if self.events.is_empty() {
                return Err("an arrival trace must contain at least one event".into());
            }
            let source_count = self.sources.len().max(1);
            let mut prior = -1.0;
            for event in &self.events {
                if !event.seconds.is_finite() || event.seconds < 0.0 || event.seconds < prior {
                    return Err("arrival trace seconds must be finite, nonnegative, and ordered".into());
                }
                if event.source >= source_count {
                    return Err(format!(
                        "arrival trace source {} is outside 0..{source_count}",
                        event.source
                    ));
                }
                prior = event.seconds;
            }
            if !self.phases.is_empty() {
                return Err("arrival phases cannot be combined with an explicit trace".into());
            }
        } else if !self.events.is_empty() {
            return Err("arrival events are valid only when kind is trace".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RootPolicy {
    FixedCount {
        inputs_per_root: usize,
    },
    Periodic {
        period_seconds: f64,
        #[serde(default)]
        empty_tick: EmptyTickPolicy,
    },
    Timeout {
        timeout_seconds: f64,
        #[serde(default)]
        max_inputs: Option<usize>,
    },
}

impl RootPolicy {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::FixedCount { inputs_per_root } if *inputs_per_root == 0 => {
                Err("fixed_count inputs_per_root must be positive".into())
            }
            Self::Periodic { period_seconds, .. } if !period_seconds.is_finite() || *period_seconds <= 0.0 => {
                Err("periodic period_seconds must be finite and positive".into())
            }
            Self::Timeout {
                timeout_seconds,
                max_inputs,
            } if !timeout_seconds.is_finite()
                || *timeout_seconds <= 0.0
                || max_inputs.is_some_and(|value| value == 0) =>
            {
                Err("timeout_seconds and max_inputs must be positive".into())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmptyTickPolicy {
    #[default]
    Skip,
    ReusePreviousRoot,
    AdapterProof,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootLifecycle {
    Independent,
    Rolling,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareLimits {
    pub performance_workers: usize,
    #[serde(default)]
    pub efficiency_workers: usize,
    #[serde(default = "default_processes")]
    pub proving_processes: usize,
    pub prover_ram_bytes: u64,
}

impl HardwareLimits {
    fn validate(&self) -> Result<(), String> {
        if self.performance_workers == 0 || self.proving_processes == 0 || self.prover_ram_bytes == 0 {
            return Err("performance_workers, proving_processes, and prover_ram_bytes must be positive".into());
        }
        if self.proving_processes > self.performance_workers {
            return Err("proving_processes cannot exceed performance_workers because each process needs one".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineBoundary {
    #[default]
    ProofProduced,
    Serialized,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadlineLimits {
    #[serde(default)]
    pub p99_input_to_root_seconds: Option<f64>,
    #[serde(default)]
    pub max_root_interval_seconds: Option<f64>,
    #[serde(default)]
    pub max_tick_lateness_seconds: Option<f64>,
    #[serde(default)]
    pub boundary: DeadlineBoundary,
}

impl DeadlineLimits {
    fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("p99_input_to_root_seconds", self.p99_input_to_root_seconds),
            ("max_root_interval_seconds", self.max_root_interval_seconds),
            ("max_tick_lateness_seconds", self.max_tick_lateness_seconds),
        ] {
            if value.is_some_and(|seconds| !seconds.is_finite() || seconds <= 0.0) {
                return Err(format!("deadline {name} must be finite and positive"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub connected_peers: usize,
    #[serde(default = "default_remote_fraction")]
    pub remote_input_fraction: f64,
    pub root_proof_recipients: usize,
    #[serde(default)]
    pub intermediate_proof_recipients: usize,
    pub ingress_budget_bytes_per_second: f64,
    pub egress_budget_bytes_per_second: f64,
    #[serde(default = "default_bandwidth_window")]
    pub rolling_window_seconds: f64,
}

impl NetworkConfig {
    fn validate(&self) -> Result<(), String> {
        if !self.remote_input_fraction.is_finite() || !(0.0..=1.0).contains(&self.remote_input_fraction) {
            return Err("network remote_input_fraction must be in 0..=1".into());
        }
        for (name, value) in [
            ("ingress_budget_bytes_per_second", self.ingress_budget_bytes_per_second),
            ("egress_budget_bytes_per_second", self.egress_budget_bytes_per_second),
            ("rolling_window_seconds", self.rolling_window_seconds),
        ] {
            if !value.is_finite() || value <= 0.0 {
                return Err(format!("network {name} must be finite and positive"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParentMeasurementMode {
    #[default]
    Full,
    Adaptive,
}

fn default_thread_scaling_arities() -> Vec<usize> {
    vec![4, 16]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchConfig {
    #[serde(default = "default_arities")]
    pub arities: Vec<usize>,
    #[serde(default = "default_rates")]
    pub parent_log_inv_rates: Vec<usize>,
    pub min_arrival_rate: f64,
    pub max_arrival_rate: f64,
    #[serde(default = "default_rate_precision")]
    pub rate_precision_fraction: f64,
    #[serde(default)]
    pub parent_measurement_mode: ParentMeasurementMode,
    #[serde(default = "default_thread_scaling_arities")]
    pub thread_scaling_arities: Vec<usize>,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            arities: default_arities(),
            parent_log_inv_rates: default_rates(),
            min_arrival_rate: 0.01,
            max_arrival_rate: 1.0,
            rate_precision_fraction: default_rate_precision(),
            parent_measurement_mode: ParentMeasurementMode::Full,
            thread_scaling_arities: default_thread_scaling_arities(),
        }
    }
}

impl SearchConfig {
    fn validate(&self) -> Result<(), String> {
        if self.arities.is_empty() || self.arities.iter().any(|arity| !(2..=16).contains(arity)) {
            return Err("search arities must be nonempty and each in 2..=16".into());
        }
        validate_rates("search parent_log_inv_rates", &self.parent_log_inv_rates)?;
        if !self.min_arrival_rate.is_finite()
            || !self.max_arrival_rate.is_finite()
            || self.min_arrival_rate <= 0.0
            || self.max_arrival_rate < self.min_arrival_rate
        {
            return Err("search arrival-rate bounds must be finite, positive, and ordered".into());
        }
        if !self.rate_precision_fraction.is_finite()
            || self.rate_precision_fraction <= 0.0
            || self.rate_precision_fraction >= 1.0
        {
            return Err("search rate_precision_fraction must be in 0..1".into());
        }
        if self.parent_measurement_mode == ParentMeasurementMode::Adaptive
            && (self.thread_scaling_arities.is_empty()
                || self
                    .thread_scaling_arities
                    .iter()
                    .any(|arity| !self.arities.contains(arity)))
        {
            return Err(
                "adaptive parent measurement needs nonempty thread_scaling_arities drawn from search arities".into(),
            );
        }
        Ok(())
    }
}

fn validate_rates(label: &str, rates: &[usize]) -> Result<(), String> {
    if rates.is_empty() || rates.iter().any(|rate| !(1..=4).contains(rate)) {
        return Err(format!("{label} must be nonempty and each rate must be in 1..=4"));
    }
    Ok(())
}

/// One generated proof arrival.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ArrivalEvent {
    pub input_index: usize,
    pub seconds: f64,
    pub source: usize,
}

/// Generate ordered arrivals for a candidate aggregate rate.
pub fn arrival_events(config: &ArrivalConfig, rate: f64, count: usize) -> Result<Vec<ArrivalEvent>, String> {
    if !rate.is_finite() || rate <= 0.0 {
        return Err("candidate arrival rate must be finite and positive".into());
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    if matches!(config.model, ArrivalModel::Trace) {
        if count > config.events.len() {
            return Err(format!(
                "arrival trace contains {} events, but {count} were requested",
                config.events.len()
            ));
        }
        return Ok(config
            .events
            .iter()
            .take(count)
            .enumerate()
            .map(|(input_index, event)| ArrivalEvent {
                input_index,
                seconds: event.seconds,
                source: event.source,
            })
            .collect());
    }

    let source_fractions = if config.sources.is_empty() {
        vec![1.0]
    } else {
        config.sources.iter().map(|source| source.rate_fraction).collect()
    };
    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut next: Vec<f64> = vec![0.0; source_fractions.len()];
    let mut output = Vec::with_capacity(count);
    for input_index in 0..count {
        let source = next
            .iter()
            .enumerate()
            .min_by(|left, right| left.1.total_cmp(right.1))
            .map(|(index, _)| index)
            .expect("at least one source");
        let seconds = next[source];
        output.push(ArrivalEvent {
            input_index,
            seconds,
            source,
        });
        let multiplier = phase_multiplier(&config.phases, seconds);
        let source_rate = rate * source_fractions[source] * multiplier;
        let delta = match config.model {
            ArrivalModel::FixedInterval => 1.0 / source_rate,
            ArrivalModel::Poisson => {
                let uniform = rng.random_range(f64::EPSILON..1.0);
                -uniform.ln() / source_rate
            }
            ArrivalModel::Trace => unreachable!("trace returned above"),
        };
        next[source] += delta;
    }
    output.sort_by(|left, right| {
        left.seconds
            .total_cmp(&right.seconds)
            .then(left.source.cmp(&right.source))
    });
    for (input_index, event) in output.iter_mut().enumerate() {
        event.input_index = input_index;
    }
    Ok(output)
}

fn phase_multiplier(phases: &[ArrivalPhase], seconds: f64) -> f64 {
    let mut end = 0.0;
    for phase in phases {
        end += phase.duration_seconds;
        if seconds < end {
            return phase.rate_multiplier;
        }
    }
    1.0
}

/// Inputs assigned to one finite root.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RootBatch {
    pub root_index: usize,
    pub input_indices: Vec<usize>,
    pub close_seconds: f64,
    pub scheduled_tick_seconds: Option<f64>,
}

pub fn close_root_batches(events: &[ArrivalEvent], policy: &RootPolicy) -> Result<Vec<RootBatch>, String> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    let mut batches = Vec::new();
    match policy {
        RootPolicy::FixedCount { inputs_per_root } => {
            for chunk in events.chunks(*inputs_per_root) {
                if chunk.len() < *inputs_per_root {
                    break;
                }
                batches.push(RootBatch {
                    root_index: batches.len(),
                    input_indices: chunk.iter().map(|event| event.input_index).collect(),
                    close_seconds: chunk.last().expect("nonempty chunk").seconds,
                    scheduled_tick_seconds: None,
                });
            }
        }
        RootPolicy::Periodic {
            period_seconds,
            empty_tick,
        } => {
            let mut tick = *period_seconds;
            let mut pending = Vec::new();
            for event in events {
                while event.seconds > tick {
                    if !pending.is_empty() {
                        batches.push(RootBatch {
                            root_index: batches.len(),
                            input_indices: std::mem::take(&mut pending),
                            close_seconds: tick,
                            scheduled_tick_seconds: Some(tick),
                        });
                    } else if *empty_tick != EmptyTickPolicy::Skip {
                        batches.push(RootBatch {
                            root_index: batches.len(),
                            input_indices: Vec::new(),
                            close_seconds: tick,
                            scheduled_tick_seconds: Some(tick),
                        });
                    }
                    tick += period_seconds;
                }
                pending.push(event.input_index);
            }
            if !pending.is_empty() {
                while events.last().expect("events exist").seconds > tick {
                    tick += period_seconds;
                }
                batches.push(RootBatch {
                    root_index: batches.len(),
                    input_indices: pending,
                    close_seconds: tick,
                    scheduled_tick_seconds: Some(tick),
                });
            }
        }
        RootPolicy::Timeout {
            timeout_seconds,
            max_inputs,
        } => {
            let mut start = 0;
            while start < events.len() {
                let deadline = events[start].seconds + timeout_seconds;
                let mut end = start + 1;
                while end < events.len()
                    && events[end].seconds <= deadline
                    && max_inputs.is_none_or(|maximum| end - start < maximum)
                {
                    end += 1;
                }
                let capped = max_inputs.is_some_and(|maximum| end - start >= maximum);
                let close_seconds = if capped { events[end - 1].seconds } else { deadline };
                batches.push(RootBatch {
                    root_index: batches.len(),
                    input_indices: events[start..end].iter().map(|event| event.input_index).collect(),
                    close_seconds,
                    scheduled_tick_seconds: None,
                });
                start = end;
            }
        }
    }
    Ok(batches)
}

/// Measured or provisional cost of one homogeneous parent job.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JobCost {
    pub child_count: usize,
    pub child_log_inv_rate: usize,
    pub parent_log_inv_rate: usize,
    pub service_seconds: f64,
    pub peak_rss_bytes: u64,
    pub output_bytes: usize,
    /// True when this cost was validated with the candidate's exact upper-level child proof shapes.
    pub directly_measured: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TreeLevelPlan {
    pub input_count: usize,
    pub output_count: usize,
    pub child_log_inv_rate: usize,
    pub parent_log_inv_rate: usize,
    pub child_counts: Vec<usize>,
    pub estimated_service_seconds: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TreePlan {
    pub leaf_count: usize,
    pub leaf_log_inv_rate: usize,
    pub root_log_inv_rate: usize,
    pub levels: Vec<TreeLevelPlan>,
    pub total_jobs: usize,
    pub estimated_service_seconds: f64,
    pub estimated_peak_rss_bytes: u64,
    pub all_job_costs_directly_measured: bool,
}

#[derive(Clone)]
struct PartialPlan {
    cost: f64,
    peak_rss: u64,
    all_measured: bool,
    levels: Vec<TreeLevelPlan>,
}

#[derive(Clone)]
struct PartialLevel {
    cost: f64,
    peak_rss: u64,
    all_measured: bool,
    child_counts: Vec<usize>,
}

/// Plan a sequential tree from the supplied parent proving costs.
pub fn plan_tree(
    leaf_count: usize,
    leaf_log_inv_rate: usize,
    arities: &[usize],
    parent_rates: &[usize],
    costs: &[JobCost],
) -> Result<TreePlan, String> {
    if leaf_count == 0 {
        return Err("tree planning needs at least one leaf".into());
    }
    validate_rates("tree leaf rate", &[leaf_log_inv_rate])?;
    if arities.is_empty() || arities.iter().any(|arity| !(2..=16).contains(arity)) {
        return Err("tree arities must be in 2..=16".into());
    }
    validate_rates("tree parent rates", parent_rates)?;
    if leaf_count == 1 {
        return Ok(TreePlan {
            leaf_count,
            leaf_log_inv_rate,
            root_log_inv_rate: leaf_log_inv_rate,
            levels: Vec::new(),
            total_jobs: 0,
            estimated_service_seconds: 0.0,
            estimated_peak_rss_bytes: 0,
            all_job_costs_directly_measured: true,
        });
    }
    let cost_map = costs
        .iter()
        .map(|cost| {
            (
                (cost.child_count, cost.child_log_inv_rate, cost.parent_log_inv_rate),
                cost,
            )
        })
        .collect::<HashMap<_, _>>();
    let mut memo = HashMap::new();
    let best = plan_state(
        leaf_count,
        leaf_log_inv_rate,
        arities,
        parent_rates,
        &cost_map,
        &mut memo,
    )
    .ok_or_else(|| format!("no tree can reduce {leaf_count} leaves with the supplied arities and job costs"))?;
    let root_log_inv_rate = best
        .levels
        .last()
        .map_or(leaf_log_inv_rate, |level| level.parent_log_inv_rate);
    Ok(TreePlan {
        leaf_count,
        leaf_log_inv_rate,
        root_log_inv_rate,
        total_jobs: best
            .levels
            .iter()
            .map(|level| level.child_counts.iter().filter(|count| **count > 1).count())
            .sum(),
        estimated_service_seconds: best.cost,
        estimated_peak_rss_bytes: best.peak_rss,
        all_job_costs_directly_measured: best.all_measured,
        levels: best.levels,
    })
}

fn plan_state<'a>(
    count: usize,
    child_rate: usize,
    arities: &[usize],
    parent_rates: &[usize],
    costs: &HashMap<(usize, usize, usize), &'a JobCost>,
    memo: &mut HashMap<(usize, usize), Option<PartialPlan>>,
) -> Option<PartialPlan> {
    if count == 1 {
        return Some(PartialPlan {
            cost: 0.0,
            peak_rss: 0,
            all_measured: true,
            levels: Vec::new(),
        });
    }
    if let Some(cached) = memo.get(&(count, child_rate)) {
        return cached.clone();
    }
    let mut best: Option<PartialPlan> = None;
    for &parent_rate in parent_rates {
        for (output_count, level_plan) in level_partitions(count, child_rate, parent_rate, arities, costs) {
            let Some(mut upper) = plan_state(output_count, parent_rate, arities, parent_rates, costs, memo) else {
                continue;
            };
            let level = TreeLevelPlan {
                input_count: count,
                output_count,
                child_log_inv_rate: child_rate,
                parent_log_inv_rate: parent_rate,
                child_counts: level_plan.child_counts,
                estimated_service_seconds: level_plan.cost,
            };
            let mut levels = vec![level];
            levels.append(&mut upper.levels);
            let candidate = PartialPlan {
                cost: level_plan.cost + upper.cost,
                peak_rss: level_plan.peak_rss.max(upper.peak_rss),
                all_measured: level_plan.all_measured && upper.all_measured,
                levels,
            };
            if best.as_ref().is_none_or(|current| {
                candidate.cost < current.cost
                    || (candidate.cost == current.cost && candidate.peak_rss < current.peak_rss)
            }) {
                best = Some(candidate);
            }
        }
    }
    memo.insert((count, child_rate), best.clone());
    best
}

fn level_partitions<'a>(
    count: usize,
    child_rate: usize,
    parent_rate: usize,
    arities: &[usize],
    costs: &HashMap<(usize, usize, usize), &'a JobCost>,
) -> Vec<(usize, PartialLevel)> {
    let mut sizes = arities
        .iter()
        .copied()
        .filter(|size| costs.contains_key(&(*size, child_rate, parent_rate)))
        .collect::<Vec<_>>();
    if parent_rate == child_rate {
        sizes.push(1);
    }
    sizes.sort_unstable_by(|left, right| right.cmp(left));
    sizes.dedup();
    let stride = count + 1;
    let mut states = vec![None::<PartialLevel>; stride * stride];
    states[0] = Some(PartialLevel {
        cost: 0.0,
        peak_rss: 0,
        all_measured: true,
        child_counts: Vec::new(),
    });
    for used in 0..count {
        for outputs in 0..count {
            let Some(current) = states[used * stride + outputs].clone() else {
                continue;
            };
            for &size in &sizes {
                if used + size > count {
                    continue;
                }
                let mut candidate = current.clone();
                candidate.child_counts.push(size);
                if size > 1 {
                    let job = costs
                        .get(&(size, child_rate, parent_rate))
                        .expect("available group size has a job cost");
                    candidate.cost += job.service_seconds;
                    candidate.peak_rss = candidate.peak_rss.max(job.peak_rss_bytes);
                    candidate.all_measured &= job.directly_measured;
                }
                let slot = &mut states[(used + size) * stride + outputs + 1];
                if slot.as_ref().is_none_or(|current| {
                    candidate.cost < current.cost
                        || (candidate.cost == current.cost && candidate.peak_rss < current.peak_rss)
                }) {
                    *slot = Some(candidate);
                }
            }
        }
    }
    (1..count)
        .filter_map(|outputs| states[count * stride + outputs].take().map(|plan| (outputs, plan)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_costs(arities: &[usize]) -> Vec<JobCost> {
        let mut costs = Vec::new();
        for &child_count in arities {
            for child_rate in 1..=4 {
                for parent_rate in 1..=4 {
                    costs.push(JobCost {
                        child_count,
                        child_log_inv_rate: child_rate,
                        parent_log_inv_rate: parent_rate,
                        service_seconds: child_count as f64,
                        peak_rss_bytes: child_count as u64 * 100,
                        output_bytes: 1000,
                        directly_measured: true,
                    });
                }
            }
        }
        costs
    }

    #[test]
    fn query_validation_separates_peers_from_proof_recipients() {
        let query: BenchmarkQuery = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "workload": {
                "adapter": "xmss",
                "adapter_schema_version": 1,
                "proof_source": {"kind": "generated"},
                "adapter_config": {"signatures_per_child": 1},
                "leaf_log_inv_rates": [1, 2, 3, 4]
            },
            "arrivals": {"kind": "fixed_interval", "seed": 7},
            "root_policy": {"kind": "fixed_count", "inputs_per_root": 7},
            "root_lifecycle": "independent",
            "hardware_limits": {
                "performance_workers": 4,
                "efficiency_workers": 0,
                "proving_processes": 1,
                "prover_ram_bytes": 1000000000u64
            },
            "deadlines": {"p99_input_to_root_seconds": 30.0},
            "network": {
                "connected_peers": 100,
                "remote_input_fraction": 1.0,
                "root_proof_recipients": 3,
                "intermediate_proof_recipients": 0,
                "ingress_budget_bytes_per_second": 1000000.0,
                "egress_budget_bytes_per_second": 1000000.0,
                "rolling_window_seconds": 1.0
            },
            "search": {
                "arities": [2, 3, 4],
                "parent_log_inv_rates": [1, 2, 3, 4],
                "min_arrival_rate": 0.1,
                "max_arrival_rate": 10.0,
                "rate_precision_fraction": 0.05
            }
        }))
        .unwrap();
        query.validate().unwrap();
        assert_eq!(query.network.connected_peers, 100);
        assert_eq!(query.network.root_proof_recipients, 3);

        let mut unsupported_source = query.clone();
        unsupported_source.workload.proof_source = ProofSource::SerializedCorpus {
            path: "proofs.bin".into(),
        };
        assert!(
            unsupported_source
                .validate()
                .unwrap_err()
                .contains("generated leaf proofs only")
        );

        let mut unsupported_empty_tick = query;
        unsupported_empty_tick.root_policy = RootPolicy::Periodic {
            period_seconds: 1.0,
            empty_tick: EmptyTickPolicy::AdapterProof,
        };
        assert!(
            unsupported_empty_tick
                .validate()
                .unwrap_err()
                .contains("empty periodic tick")
        );
    }

    #[test]
    fn arrival_configuration_rejects_unknown_fields() {
        let result = serde_json::from_value::<ArrivalConfig>(serde_json::json!({
            "kind": "fixed_interval",
            "seed": 7,
            "unexpected": true
        }));
        assert!(result.is_err());
    }

    #[test]
    fn property_every_input_is_covered_without_padding() {
        let arities = (2..=16).collect::<Vec<_>>();
        let costs = all_costs(&arities);
        let leaf_counts = (2..=32).chain([37, 43, 47, 53, 61, 63]);
        for leaf_count in leaf_counts {
            let plan = plan_tree(leaf_count, 2, &arities, &[1, 2, 3, 4], &costs).unwrap();
            let mut count = leaf_count;
            for level in &plan.levels {
                assert_eq!(level.input_count, count);
                assert_eq!(level.child_counts.iter().sum::<usize>(), count);
                assert!(level.child_counts.iter().all(|size| (1..=16).contains(size)));
                count = level.output_count;
            }
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn one_level_can_use_different_parent_child_counts() {
        let arities = vec![2, 16];
        let plan = plan_tree(18, 2, &arities, &[2], &all_costs(&arities)).unwrap();
        assert!(
            plan.levels
                .iter()
                .any(|level| level.child_counts.contains(&2) && level.child_counts.contains(&16))
        );
    }

    #[test]
    fn rate_change_does_not_create_a_unary_proving_job() {
        let costs = all_costs(&(2..=16).collect::<Vec<_>>());
        let plan = plan_tree(17, 1, &(2..=16).collect::<Vec<_>>(), &[2], &costs).unwrap();
        assert!(plan.levels.iter().all(|level| !level.child_counts.contains(&1)));
    }

    #[test]
    fn planner_accepts_every_supported_whir_rate_transition() {
        let arities = (2..=16).collect::<Vec<_>>();
        let costs = all_costs(&arities);
        for child_rate in 1..=4 {
            for parent_rate in 1..=4 {
                let plan = plan_tree(17, child_rate, &arities, &[parent_rate], &costs).unwrap();
                assert_eq!(plan.levels[0].child_log_inv_rate, child_rate);
                assert_eq!(plan.levels[0].parent_log_inv_rate, parent_rate);
                if child_rate != parent_rate {
                    assert!(!plan.levels[0].child_counts.contains(&1));
                }
            }
        }
    }

    #[test]
    fn fixed_periodic_and_timeout_policies_close_different_roots() {
        let arrivals = arrival_events(
            &ArrivalConfig {
                model: ArrivalModel::FixedInterval,
                events: Vec::new(),
                sources: Vec::new(),
                phases: Vec::new(),
                seed: 7,
            },
            2.0,
            8,
        )
        .unwrap();
        let fixed = close_root_batches(&arrivals, &RootPolicy::FixedCount { inputs_per_root: 4 }).unwrap();
        let periodic = close_root_batches(
            &arrivals,
            &RootPolicy::Periodic {
                period_seconds: 1.0,
                empty_tick: EmptyTickPolicy::Skip,
            },
        )
        .unwrap();
        let timeout = close_root_batches(
            &arrivals,
            &RootPolicy::Timeout {
                timeout_seconds: 0.75,
                max_inputs: None,
            },
        )
        .unwrap();
        assert_eq!(
            fixed.iter().map(|batch| batch.input_indices.len()).collect::<Vec<_>>(),
            [4, 4]
        );
        assert_ne!(periodic, fixed);
        assert_ne!(timeout, fixed);
    }

    #[test]
    fn periodic_empty_tick_policy_is_explicit() {
        let events = vec![
            ArrivalEvent {
                input_index: 0,
                seconds: 0.0,
                source: 0,
            },
            ArrivalEvent {
                input_index: 1,
                seconds: 3.1,
                source: 0,
            },
        ];
        let skipped = close_root_batches(
            &events,
            &RootPolicy::Periodic {
                period_seconds: 1.0,
                empty_tick: EmptyTickPolicy::Skip,
            },
        )
        .unwrap();
        let reused = close_root_batches(
            &events,
            &RootPolicy::Periodic {
                period_seconds: 1.0,
                empty_tick: EmptyTickPolicy::ReusePreviousRoot,
            },
        )
        .unwrap();
        assert_eq!(skipped.len(), 2);
        assert_eq!(reused.iter().filter(|batch| batch.input_indices.is_empty()).count(), 2);
    }

    #[test]
    fn multiple_sources_preserve_total_rate_and_source_identity() {
        let arrivals = arrival_events(
            &ArrivalConfig {
                model: ArrivalModel::FixedInterval,
                events: Vec::new(),
                sources: vec![
                    ArrivalSource {
                        name: "large".into(),
                        rate_fraction: 0.25,
                        workload_variant: Value::Null,
                    },
                    ArrivalSource {
                        name: "small".into(),
                        rate_fraction: 0.75,
                        workload_variant: Value::Null,
                    },
                ],
                phases: Vec::new(),
                seed: 7,
            },
            4.0,
            12,
        )
        .unwrap();
        assert!(arrivals.iter().any(|event| event.source == 0));
        assert!(arrivals.iter().any(|event| event.source == 1));
        assert!(arrivals.windows(2).all(|pair| pair[0].seconds <= pair[1].seconds));
    }

    #[test]
    fn fixed_interval_poisson_and_trace_arrivals_are_reproducible() {
        let fixed = arrival_events(
            &ArrivalConfig {
                model: ArrivalModel::FixedInterval,
                events: Vec::new(),
                sources: Vec::new(),
                phases: Vec::new(),
                seed: 9,
            },
            2.0,
            4,
        )
        .unwrap();
        assert_eq!(
            fixed.iter().map(|event| event.seconds).collect::<Vec<_>>(),
            [0.0, 0.5, 1.0, 1.5]
        );

        let poisson_config = ArrivalConfig {
            model: ArrivalModel::Poisson,
            events: Vec::new(),
            sources: Vec::new(),
            phases: Vec::new(),
            seed: 9,
        };
        let poisson = arrival_events(&poisson_config, 2.0, 8).unwrap();
        assert_eq!(poisson, arrival_events(&poisson_config, 2.0, 8).unwrap());
        assert!(poisson.windows(2).all(|pair| pair[0].seconds <= pair[1].seconds));
        assert_ne!(poisson[1].seconds, fixed[1].seconds);

        let trace = vec![
            TraceArrival {
                seconds: 0.25,
                source: 0,
            },
            TraceArrival {
                seconds: 1.75,
                source: 0,
            },
        ];
        let replayed = arrival_events(
            &ArrivalConfig {
                model: ArrivalModel::Trace,
                events: trace,
                sources: Vec::new(),
                phases: Vec::new(),
                seed: 9,
            },
            999.0,
            2,
        )
        .unwrap();
        assert_eq!(
            replayed.iter().map(|event| event.seconds).collect::<Vec<_>>(),
            [0.25, 1.75]
        );
    }

    #[test]
    fn arrival_phase_multiplier_returns_to_the_candidate_rate_after_the_last_phase() {
        let phases = [
            ArrivalPhase {
                duration_seconds: 2.0,
                rate_multiplier: 1.05,
            },
            ArrivalPhase {
                duration_seconds: 3.0,
                rate_multiplier: 0.5,
            },
        ];
        assert_eq!(phase_multiplier(&phases, 1.0), 1.05);
        assert_eq!(phase_multiplier(&phases, 3.0), 0.5);
        assert_eq!(phase_multiplier(&phases, 6.0), 1.0);
    }

    #[test]
    fn exact_trace_query_accepts_only_its_observed_mean_rate() {
        let mut query: BenchmarkQuery = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "workload": {
                "adapter": "xmss",
                "adapter_schema_version": 1,
                "proof_source": {"kind": "generated"},
                "adapter_config": {"signatures_per_child": 1},
                "leaf_log_inv_rates": [2]
            },
            "arrivals": {
                "kind": "trace",
                "events": [
                    {"seconds": 1.0},
                    {"seconds": 1.5},
                    {"seconds": 2.0}
                ]
            },
            "root_policy": {"kind": "fixed_count", "inputs_per_root": 2},
            "root_lifecycle": "independent",
            "hardware_limits": {
                "performance_workers": 1,
                "prover_ram_bytes": 1000000000u64
            },
            "network": {
                "connected_peers": 1,
                "root_proof_recipients": 1,
                "ingress_budget_bytes_per_second": 1000000.0,
                "egress_budget_bytes_per_second": 1000000.0
            },
            "search": {
                "arities": [2],
                "parent_log_inv_rates": [2],
                "min_arrival_rate": 2.0,
                "max_arrival_rate": 2.0
            }
        }))
        .unwrap();
        query.validate().unwrap();
        query.search.max_arrival_rate = 3.0;
        assert!(query.validate().unwrap_err().contains("exact arrival trace"));
    }
}
