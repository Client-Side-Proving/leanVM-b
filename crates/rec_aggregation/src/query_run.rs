//! End-to-end execution of one application-query point with real proofs.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use primitives::bench::{Plan, process_usage};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::capacity::run_metadata;
use crate::query::{
    ArrivalEvent, BenchmarkQuery, DeadlineBoundary, EmptyTickPolicy, JobCost, ProofSource, RootBatch, RootLifecycle,
    RootPolicy, TreePlan, arrival_events, close_root_batches, plan_tree,
};
use crate::workload::{ProofMetadata, WorkloadAdapter, WorkloadDescription, XmssLeafSpec, XmssWorkloadAdapter};

const QUERY_RUN_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum XmssSignerRelationship {
    #[default]
    Disjoint,
    Repeated,
    Trace,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WeightedSignatureCount {
    signatures: usize,
    weight: f64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct XmssAdapterConfig {
    #[serde(default)]
    signatures_per_child: Option<usize>,
    #[serde(default)]
    signature_distribution: Vec<WeightedSignatureCount>,
    #[serde(default)]
    signer_relationship: XmssSignerRelationship,
    #[serde(default)]
    signer_starts: Vec<usize>,
}

impl XmssAdapterConfig {
    fn from_query(query: &BenchmarkQuery) -> Result<Self, String> {
        if query.workload.adapter != "xmss" || query.workload.adapter_schema_version != 1 {
            return Err(format!(
                "this executable provides workload adapter xmss schema 1, got {} schema {}",
                query.workload.adapter, query.workload.adapter_schema_version
            ));
        }
        let config: Self = serde_json::from_value(query.workload.adapter_config.clone())
            .map_err(|error| format!("parse XMSS adapter_config: {error}"))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        match (self.signatures_per_child, self.signature_distribution.is_empty()) {
            (None, true) => {
                return Err("XMSS adapter_config needs signatures_per_child or signature_distribution".into());
            }
            (Some(_), false) => {
                return Err(
                    "XMSS adapter_config must choose either signatures_per_child or signature_distribution".into(),
                );
            }
            _ => {}
        }
        if self.signatures_per_child == Some(0) {
            return Err("XMSS signatures_per_child must be positive".into());
        }
        let mut total_weight = 0.0;
        for entry in &self.signature_distribution {
            if entry.signatures == 0 || !entry.weight.is_finite() || entry.weight <= 0.0 {
                return Err("XMSS signature_distribution entries need positive signatures and weights".into());
            }
            total_weight += entry.weight;
        }
        if !self.signature_distribution.is_empty() && (!total_weight.is_finite() || total_weight <= 0.0) {
            return Err("XMSS signature_distribution total weight must be positive".into());
        }
        if matches!(self.signer_relationship, XmssSignerRelationship::Trace) && self.signer_starts.is_empty() {
            return Err("XMSS traced signer relationship needs signer_starts".into());
        }
        Ok(())
    }

    fn signatures(&self, rng: &mut StdRng, source_variant: &serde_json::Value) -> Result<usize, String> {
        if let Some(value) = source_variant.get("signatures_per_child") {
            return value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| "source workload_variant signatures_per_child must be a positive integer".to_owned());
        }
        if let Some(signatures) = self.signatures_per_child {
            return Ok(signatures);
        }
        let total = self
            .signature_distribution
            .iter()
            .map(|entry| entry.weight)
            .sum::<f64>();
        let mut selected = rng.random_range(0.0..total);
        for entry in &self.signature_distribution {
            if selected < entry.weight {
                return Ok(entry.signatures);
            }
            selected -= entry.weight;
        }
        Ok(self
            .signature_distribution
            .last()
            .expect("validated distribution")
            .signatures)
    }

    fn leaf_specs(&self, query: &BenchmarkQuery, events: &[ArrivalEvent]) -> Result<Vec<XmssLeafSpec>, String> {
        let mut rng = StdRng::seed_from_u64(query.arrivals.seed ^ 0x584d_5353);
        let mut next_disjoint = 0usize;
        events
            .iter()
            .enumerate()
            .map(|(index, event)| {
                let variant = query
                    .arrivals
                    .sources
                    .get(event.source)
                    .map_or(&serde_json::Value::Null, |source| &source.workload_variant);
                let signatures = self.signatures(&mut rng, variant)?;
                let signer_start = match self.signer_relationship {
                    XmssSignerRelationship::Disjoint => {
                        let start = next_disjoint;
                        next_disjoint = next_disjoint
                            .checked_add(signatures)
                            .ok_or_else(|| "XMSS disjoint signer range overflows".to_owned())?;
                        start
                    }
                    XmssSignerRelationship::Repeated => 0,
                    XmssSignerRelationship::Trace => *self
                        .signer_starts
                        .get(index)
                        .ok_or_else(|| format!("XMSS signer_starts has no entry for input {index}"))?,
                };
                Ok(XmssLeafSpec {
                    signer_start,
                    signatures,
                })
            })
            .collect()
    }

    fn possible_signature_counts(&self, query: &BenchmarkQuery) -> Result<Vec<usize>, String> {
        let mut counts = std::collections::BTreeSet::new();
        if let Some(signatures) = self.signatures_per_child {
            counts.insert(signatures);
        }
        counts.extend(self.signature_distribution.iter().map(|entry| entry.signatures));
        for source in &query.arrivals.sources {
            if let Some(value) = source.workload_variant.get("signatures_per_child") {
                let signatures = value
                    .as_u64()
                    .and_then(|value| usize::try_from(value).ok())
                    .filter(|value| *value > 0)
                    .ok_or_else(|| {
                        "source workload_variant signatures_per_child must be a positive integer".to_owned()
                    })?;
                counts.insert(signatures);
            }
        }
        Ok(counts.into_iter().collect())
    }
}

#[derive(Clone)]
struct LeafTiming {
    input_index: usize,
    arrival_seconds: f64,
    batch_collection_seconds: f64,
    internal_child_wait_seconds: f64,
    queue_seconds: f64,
    proving_seconds: f64,
    proof_metadata_seconds: f64,
}

impl LeafTiming {
    fn at_root_close(input_index: usize, arrival_seconds: f64, close_seconds: f64) -> Self {
        Self {
            input_index,
            arrival_seconds,
            batch_collection_seconds: close_seconds - arrival_seconds,
            internal_child_wait_seconds: 0.0,
            queue_seconds: 0.0,
            proving_seconds: 0.0,
            proof_metadata_seconds: 0.0,
        }
    }
}

struct PendingProof<P> {
    proof: P,
    metadata: ProofMetadata,
    ready: Instant,
    leaves: Vec<LeafTiming>,
}

#[derive(Clone, Debug, Serialize)]
struct ParentJobSample {
    level: usize,
    node: usize,
    child_count: usize,
    children: Vec<ProofMetadata>,
    parent: ProofMetadata,
    service_seconds: f64,
    user_cpu_seconds: f64,
    system_cpu_seconds: f64,
    effective_cpu_cores: f64,
    process_peak_rss_bytes: u64,
    metadata_seconds: f64,
}

#[derive(Clone, Debug, Serialize)]
struct Distribution {
    count: usize,
    mean: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
}

impl Distribution {
    fn from(mut values: Vec<f64>) -> Self {
        if values.is_empty() {
            return Self {
                count: 0,
                mean: 0.0,
                p50: 0.0,
                p95: 0.0,
                p99: 0.0,
                max: 0.0,
            };
        }
        values.sort_by(f64::total_cmp);
        Self {
            count: values.len(),
            mean: values.iter().sum::<f64>() / values.len() as f64,
            p50: nearest_rank(&values, 0.50),
            p95: nearest_rank(&values, 0.95),
            p99: nearest_rank(&values, 0.99),
            max: *values.last().expect("nonempty values"),
        }
    }
}

fn nearest_rank(sorted: &[f64], fraction: f64) -> f64 {
    let rank = ((sorted.len() as f64 * fraction).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

#[derive(Clone, Debug, Serialize)]
struct RootSample {
    root_index: usize,
    input_indices: Vec<usize>,
    input_count: usize,
    close_seconds: f64,
    scheduled_tick_seconds: Option<f64>,
    service_start_seconds: f64,
    proof_completion_seconds: f64,
    serialization_completion_seconds: f64,
    tick_lateness_seconds: Option<f64>,
    tree: TreePlan,
    root: ProofMetadata,
    parent_jobs: Vec<ParentJobSample>,
    input_to_root_seconds: Vec<f64>,
    batch_collection_seconds: Vec<f64>,
    internal_child_wait_seconds: Vec<f64>,
    queue_seconds: Vec<f64>,
    proving_seconds: Vec<f64>,
    proof_metadata_seconds: Vec<f64>,
    serialization_seconds: f64,
    native_verification_seconds: f64,
}

#[derive(Clone, Debug, Serialize)]
struct BacklogPoint {
    seconds: f64,
    inputs: usize,
}

#[derive(Clone, Debug, Serialize)]
struct ProofBandwidth {
    ingress_bytes: f64,
    exact_ingress_event_count: usize,
    conservatively_sized_ingress_event_count: usize,
    root_egress_bytes: u64,
    intermediate_egress_bytes: u64,
    average_ingress_bytes_per_second: f64,
    average_egress_bytes_per_second: f64,
    maximum_rolling_ingress_bytes_per_second: f64,
    maximum_rolling_egress_bytes_per_second: f64,
    rolling_window_seconds: f64,
    ingress_events: Vec<(f64, f64)>,
    egress_events: Vec<(f64, f64)>,
}

#[derive(Serialize)]
struct QueryRunRecord {
    schema_version: u32,
    run: crate::capacity::RunMetadata,
    query: BenchmarkQuery,
    workload: WorkloadDescription,
    requested_arrival_rate: f64,
    leaf_log_inv_rate: usize,
    root_target: usize,
    root_shard_index: usize,
    root_shard_count: usize,
    measured_started_unix_seconds: f64,
    leaf_preparation_seconds: f64,
    leaf_metadata_seconds: f64,
    child_deserialization_seconds: Option<f64>,
    elapsed_seconds: f64,
    completed_roots: usize,
    completed_inputs: usize,
    root_samples: Vec<RootSample>,
    input_to_root_seconds: Distribution,
    batch_collection_seconds: Distribution,
    internal_child_wait_seconds: Distribution,
    queue_seconds: Distribution,
    proving_seconds: Distribution,
    proof_metadata_seconds: Distribution,
    root_interarrival_seconds: Distribution,
    tick_lateness_seconds: Distribution,
    backlog: Vec<BacklogPoint>,
    maximum_backlog_inputs: usize,
    effective_cpu_cores: f64,
    peak_rss_bytes: u64,
    proof_bandwidth: ProofBandwidth,
    all_roots_verified: bool,
    stopped_reason: Option<String>,
}

struct TreeExecution<P> {
    root: P,
    root_metadata: ProofMetadata,
    leaves: Vec<LeafTiming>,
    all_parent_transmissions: Vec<(f64, usize)>,
    parent_jobs: Vec<ParentJobSample>,
}

fn execute_tree<A: WorkloadAdapter>(
    adapter: &A,
    mut current: Vec<PendingProof<A::Proof>>,
    plan: &TreePlan,
    started: Instant,
) -> Result<TreeExecution<A::Proof>, String> {
    let mut transmissions = Vec::new();
    let mut parent_jobs = Vec::new();
    for (level_index, level) in plan.levels.iter().enumerate() {
        if current.len() != level.input_count {
            return Err(format!(
                "tree level expected {} inputs, executor has {}",
                level.input_count,
                current.len()
            ));
        }
        let mut next = Vec::with_capacity(level.output_count);
        let mut offset = 0usize;
        for (node_index, &child_count) in level.child_counts.iter().enumerate() {
            let mut group = current.drain(offset..offset + child_count).collect::<Vec<_>>();
            offset = 0;
            if child_count == 1 {
                next.push(group.pop().expect("one carried proof"));
                continue;
            }
            let child_ready = group.iter().map(|item| item.ready).max().expect("nonempty proof group");
            for item in &mut group {
                let wait = child_ready.duration_since(item.ready).as_secs_f64();
                for leaf in &mut item.leaves {
                    leaf.internal_child_wait_seconds += wait;
                }
            }
            let service_started = Instant::now();
            let queue_seconds = service_started.duration_since(child_ready).as_secs_f64();
            for item in &mut group {
                for leaf in &mut item.leaves {
                    leaf.queue_seconds += queue_seconds;
                }
            }
            let proofs = group.iter().map(|item| item.proof.clone()).collect::<Vec<_>>();
            let child_metadata = group.iter().map(|item| item.metadata.clone()).collect::<Vec<_>>();
            let usage_before = process_usage();
            let parent = adapter.aggregate(&proofs, level.parent_log_inv_rate)?;
            let completed = Instant::now();
            let usage_after = process_usage();
            let service_seconds = completed.duration_since(service_started).as_secs_f64();
            let user_cpu_seconds = (usage_after.user_cpu_seconds - usage_before.user_cpu_seconds).max(0.0);
            let system_cpu_seconds = (usage_after.system_cpu_seconds - usage_before.system_cpu_seconds).max(0.0);
            let mut leaves = group.into_iter().flat_map(|item| item.leaves).collect::<Vec<_>>();
            for leaf in &mut leaves {
                leaf.proving_seconds += service_seconds;
            }
            let metadata_started = Instant::now();
            let metadata = adapter.metadata(&parent)?;
            let metadata_completed = Instant::now();
            let metadata_seconds = metadata_completed.duration_since(metadata_started).as_secs_f64();
            for leaf in &mut leaves {
                leaf.proof_metadata_seconds += metadata_seconds;
            }
            let bytes = metadata.full_proof_bytes;
            transmissions.push((metadata_completed.duration_since(started).as_secs_f64(), bytes));
            parent_jobs.push(ParentJobSample {
                level: level_index + 1,
                node: node_index + 1,
                child_count,
                children: child_metadata,
                parent: metadata.clone(),
                service_seconds,
                user_cpu_seconds,
                system_cpu_seconds,
                effective_cpu_cores: (user_cpu_seconds + system_cpu_seconds) / service_seconds.max(f64::EPSILON),
                process_peak_rss_bytes: usage_after.peak_rss_bytes,
                metadata_seconds,
            });
            next.push(PendingProof {
                proof: parent,
                metadata,
                ready: metadata_completed,
                leaves,
            });
        }
        current = next;
    }
    if current.len() != 1 {
        return Err(format!(
            "tree execution ended with {} proofs instead of one",
            current.len()
        ));
    }
    let result = current.pop().expect("one root");
    Ok(TreeExecution {
        root: result.proof,
        root_metadata: result.metadata,
        leaves: result.leaves,
        all_parent_transmissions: transmissions,
        parent_jobs,
    })
}

fn read_costs(path: &Path) -> Result<Vec<JobCost>, String> {
    let bytes = fs::read(path).map_err(|error| format!("read job costs {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse job costs {}: {error}", path.display()))
}

fn event_count_for_roots(query: &BenchmarkQuery, rate: f64, root_target: usize) -> Result<usize, String> {
    match &query.root_policy {
        RootPolicy::FixedCount { inputs_per_root } => inputs_per_root
            .checked_mul(root_target)
            .ok_or_else(|| "fixed root event count overflows".into()),
        RootPolicy::Periodic { period_seconds, .. } => {
            Ok(((rate * period_seconds * root_target as f64 * 1.5).ceil() as usize).max(root_target))
        }
        RootPolicy::Timeout {
            timeout_seconds,
            max_inputs,
        } => Ok(max_inputs
            .unwrap_or_else(|| (rate * timeout_seconds).ceil() as usize + 1)
            .saturating_mul(root_target)
            .saturating_mul(2)
            .max(root_target)),
    }
}

fn batches_for_target(
    query: &BenchmarkQuery,
    rate: f64,
    root_target: usize,
) -> Result<(Vec<ArrivalEvent>, Vec<RootBatch>), String> {
    let mut count = event_count_for_roots(query, rate, root_target)?;
    loop {
        let events = arrival_events(&query.arrivals, rate, count)?;
        let batches = close_root_batches(&events, &query.root_policy)?;
        if batches.len() >= root_target {
            let selected = batches.into_iter().take(root_target).collect::<Vec<_>>();
            let final_input = selected
                .iter()
                .flat_map(|batch| batch.input_indices.iter())
                .copied()
                .max()
                .unwrap_or(0);
            return Ok((events.into_iter().take(final_input + 1).collect(), selected));
        }
        match query.arrivals.model {
            crate::query::ArrivalModel::Trace => {
                return Err(format!(
                    "arrival trace closes {} roots, fewer than requested {root_target}",
                    batches.len()
                ));
            }
            _ => {
                count = count
                    .checked_mul(2)
                    .filter(|value| *value <= 1_000_000)
                    .ok_or_else(|| "could not generate enough arrivals for the requested roots".to_owned())?;
            }
        }
    }
}

fn backlog_points(events: &[ArrivalEvent], roots: &[RootSample], use_serialized: bool) -> Vec<BacklogPoint> {
    let mut changes = events
        .iter()
        .map(|event| (event.seconds, 1isize))
        .chain(roots.iter().map(|root| {
            (
                if use_serialized {
                    root.serialization_completion_seconds
                } else {
                    root.proof_completion_seconds
                },
                -(root.input_count as isize),
            )
        }))
        .collect::<Vec<_>>();
    changes.sort_by(|left, right| left.0.total_cmp(&right.0).then(left.1.cmp(&right.1)));
    let mut count = 0isize;
    changes
        .into_iter()
        .map(|(seconds, change)| {
            count += change;
            BacklogPoint {
                seconds,
                inputs: count.max(0) as usize,
            }
        })
        .collect()
}

fn events_for_root_shard(
    events: &[ArrivalEvent],
    policy: &RootPolicy,
    elapsed_seconds: f64,
    shard_index: usize,
    shard_count: usize,
) -> Result<Vec<ArrivalEvent>, String> {
    if shard_count == 1 {
        return Ok(events.to_vec());
    }
    let batches = close_root_batches(events, policy)?;
    let completed = batches
        .iter()
        .filter(|batch| batch.close_seconds <= elapsed_seconds)
        .collect::<Vec<_>>();
    let mut assigned = std::collections::HashSet::new();
    let mut completed_inputs = std::collections::HashSet::new();
    for batch in &completed {
        for index in &batch.input_indices {
            completed_inputs.insert(*index);
            if batch.root_index % shard_count == shard_index {
                assigned.insert(*index);
            }
        }
    }
    let next_root_index = completed.len();
    if next_root_index % shard_count == shard_index {
        for event in events {
            if !completed_inputs.contains(&event.input_index) {
                assigned.insert(event.input_index);
            }
        }
    }
    Ok(events
        .iter()
        .filter(|event| assigned.contains(&event.input_index))
        .cloned()
        .collect())
}

fn rolling_peak(events: &[(f64, f64)], window: f64) -> f64 {
    let mut start = 0usize;
    let mut bytes = 0.0;
    let mut peak: f64 = 0.0;
    for end in 0..events.len() {
        bytes += events[end].1;
        while events[end].0 - events[start].0 > window {
            bytes -= events[start].1;
            start += 1;
        }
        peak = peak.max(bytes / window);
    }
    peak
}

fn parent_rates_for_lifecycle(lifecycle: RootLifecycle, leaf_log_inv_rate: usize, configured: &[usize]) -> Vec<usize> {
    if matches!(lifecycle, RootLifecycle::Rolling) {
        vec![leaf_log_inv_rate]
    } else {
        configured.to_vec()
    }
}

/// Execute one directly measured arrival-rate point and emit one JSON record.
pub fn run_query_case(
    query_path: &Path,
    costs_path: &Path,
    arrival_rate: f64,
    leaf_log_inv_rate: usize,
    root_target: usize,
    run_id: String,
    root_shard_index: usize,
    root_shard_count: usize,
    barrier_dir: Option<&Path>,
) -> Result<(), String> {
    let query = BenchmarkQuery::from_path(query_path)?;
    if !matches!(query.workload.proof_source, ProofSource::Generated) {
        return Err("the current XMSS workload adapter supports generated leaf proofs only".into());
    }
    if matches!(
        query.root_policy,
        RootPolicy::Periodic {
            empty_tick: EmptyTickPolicy::AdapterProof,
            ..
        }
    ) {
        return Err("the current XMSS workload adapter cannot produce a root for an empty periodic tick".into());
    }
    if root_target == 0 {
        return Err("query run root_target must be positive".into());
    }
    if root_shard_count == 0 || root_shard_index >= root_shard_count {
        return Err("root shard index must be smaller than a positive root shard count".into());
    }
    if root_shard_count > 1
        && (matches!(query.root_lifecycle, RootLifecycle::Rolling)
            || matches!(
                query.root_policy,
                RootPolicy::Periodic {
                    empty_tick: EmptyTickPolicy::ReusePreviousRoot,
                    ..
                }
            ))
    {
        return Err("rolling roots and reused empty periodic roots require one proving process".into());
    }
    if !query.workload.leaf_log_inv_rates.contains(&leaf_log_inv_rate) {
        return Err(format!(
            "leaf rate {leaf_log_inv_rate} is outside the query's allowed leaf rates"
        ));
    }
    let costs = read_costs(costs_path)?;
    let parent_rates = parent_rates_for_lifecycle(
        query.root_lifecycle,
        leaf_log_inv_rate,
        &query.search.parent_log_inv_rates,
    );
    let adapter_config = XmssAdapterConfig::from_query(&query)?;
    let adapter = XmssWorkloadAdapter;
    let (events, all_batches) = batches_for_target(&query, arrival_rate, root_target)?;
    let batches = all_batches
        .into_iter()
        .filter(|batch| batch.root_index % root_shard_count == root_shard_index)
        .collect::<Vec<_>>();
    if batches.is_empty() {
        return Err("the selected root shard received no roots".into());
    }
    let all_leaf_specs = adapter_config.leaf_specs(&query, &events)?;
    let selected_input_indices = batches
        .iter()
        .flat_map(|batch| batch.input_indices.iter().copied())
        .collect::<Vec<_>>();
    let leaf_specs = selected_input_indices
        .iter()
        .map(|index| all_leaf_specs[*index].clone())
        .collect::<Vec<_>>();

    let selected_leaf_count = leaf_specs.len();
    let mut preparation_specs = leaf_specs.clone();
    let present_counts = leaf_specs
        .iter()
        .map(|spec| spec.signatures)
        .collect::<std::collections::HashSet<_>>();
    for signatures in adapter_config.possible_signature_counts(&query)? {
        if !present_counts.contains(&signatures) {
            preparation_specs.push(XmssLeafSpec {
                signer_start: 0,
                signatures,
            });
        }
    }

    lean_vm::init_prover_pool();
    let leaf_preparation_started = Instant::now();
    let prepared_leaf_proofs = adapter.prepare_leaves(&preparation_specs, leaf_log_inv_rate)?;
    let leaf_preparation_seconds = leaf_preparation_started.elapsed().as_secs_f64();
    let leaf_metadata_started = Instant::now();
    let prepared_leaf_metadata = prepared_leaf_proofs
        .iter()
        .map(|proof| adapter.metadata(proof))
        .collect::<Result<Vec<_>, _>>()?;
    let leaf_metadata_seconds = leaf_metadata_started.elapsed().as_secs_f64();
    let mut leaf_wire_bytes_by_signature_count = std::collections::HashMap::new();
    for (spec, metadata) in preparation_specs.iter().zip(&prepared_leaf_metadata) {
        leaf_wire_bytes_by_signature_count
            .entry(spec.signatures)
            .and_modify(|bytes: &mut usize| *bytes = (*bytes).max(metadata.full_proof_bytes))
            .or_insert(metadata.full_proof_bytes);
    }
    let leaf_proofs = prepared_leaf_proofs[..selected_leaf_count].to_vec();
    let leaf_metadata = prepared_leaf_metadata[..selected_leaf_count].to_vec();
    let leaf_wire_bytes_by_input_index = selected_input_indices
        .iter()
        .copied()
        .zip(leaf_metadata.iter().map(|metadata| metadata.full_proof_bytes))
        .collect::<std::collections::HashMap<_, _>>();
    let leaf_positions = selected_input_indices
        .iter()
        .enumerate()
        .map(|(position, index)| (*index, position))
        .collect::<std::collections::HashMap<_, _>>();

    if let Some(directory) = barrier_dir {
        fs::create_dir_all(directory).map_err(|error| format!("create barrier directory: {error}"))?;
        fs::write(directory.join(format!("ready-{root_shard_index}")), b"ready")
            .map_err(|error| format!("write benchmark readiness file: {error}"))?;
        let start_path = directory.join("start");
        let start_unix_seconds = loop {
            match fs::read_to_string(&start_path) {
                Ok(value) => {
                    break value
                        .trim()
                        .parse::<f64>()
                        .map_err(|error| format!("parse barrier start: {error}"))?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(format!("read benchmark barrier start: {error}")),
            }
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
            .as_secs_f64();
        if start_unix_seconds > now {
            thread::sleep(Duration::from_secs_f64(start_unix_seconds - now));
        }
    }

    let before = process_usage();
    let measured_started_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
        .as_secs_f64();
    let started = Instant::now();
    let mut roots = Vec::with_capacity(batches.len());
    let mut previous_root: Option<(crate::aggregation::AggregateSignature, ProofMetadata)> = None;
    let mut egress_events = Vec::new();
    let mut root_egress_bytes = 0u64;
    let mut intermediate_egress_bytes = 0u64;
    let mut stopped_reason = None;

    for batch in &batches {
        let close = started + Duration::from_secs_f64(batch.close_seconds);
        let now = Instant::now();
        if close > now {
            thread::sleep(close.duration_since(now));
        }
        let service_started = Instant::now();
        let mut proofs = batch
            .input_indices
            .iter()
            .map(|index| PendingProof {
                proof: leaf_proofs[*leaf_positions
                    .get(index)
                    .expect("selected root input has a prepared proof")]
                .clone(),
                metadata: leaf_metadata[*leaf_positions.get(index).expect("selected root input has metadata")].clone(),
                ready: close,
                leaves: vec![LeafTiming::at_root_close(
                    *index,
                    events[*index].seconds,
                    batch.close_seconds,
                )],
            })
            .collect::<Vec<_>>();
        if matches!(query.root_lifecycle, RootLifecycle::Rolling)
            && !proofs.is_empty()
            && let Some((root, metadata)) = previous_root.as_ref()
        {
            proofs.insert(
                0,
                PendingProof {
                    proof: root.clone(),
                    metadata: metadata.clone(),
                    ready: close,
                    leaves: Vec::new(),
                },
            );
        }
        let (tree, mut execution) = if proofs.is_empty() {
            let root = match &query.root_policy {
                RootPolicy::Periodic {
                    empty_tick: EmptyTickPolicy::ReusePreviousRoot,
                    ..
                } => previous_root
                    .as_ref()
                    .map(|(root, _)| root.clone())
                    .ok_or_else(|| "an empty periodic tick has no preceding root to reuse".to_owned())?,
                RootPolicy::Periodic {
                    empty_tick: EmptyTickPolicy::AdapterProof,
                    ..
                } => adapter.empty_root(leaf_log_inv_rate)?.ok_or_else(|| {
                    "the workload adapter did not provide a root for an empty periodic tick".to_owned()
                })?,
                RootPolicy::Periodic {
                    empty_tick: EmptyTickPolicy::Skip,
                    ..
                }
                | RootPolicy::FixedCount { .. }
                | RootPolicy::Timeout { .. } => {
                    return Err("a root without inputs reached a policy that cannot emit it".into());
                }
            };
            let rate = adapter.metadata(&root)?.log_inv_rate;
            let metadata = adapter.metadata(&root)?;
            (
                plan_tree(1, rate, &query.search.arities, &parent_rates, &costs)?,
                TreeExecution {
                    root,
                    root_metadata: metadata,
                    leaves: Vec::new(),
                    all_parent_transmissions: Vec::new(),
                    parent_jobs: Vec::new(),
                },
            )
        } else {
            let tree = plan_tree(
                proofs.len(),
                leaf_log_inv_rate,
                &query.search.arities,
                &parent_rates,
                &costs,
            )?;
            if tree.estimated_peak_rss_bytes > query.hardware_limits.prover_ram_bytes {
                stopped_reason = Some(format!(
                    "estimated parent RSS {} exceeds configured prover RAM {}",
                    tree.estimated_peak_rss_bytes, query.hardware_limits.prover_ram_bytes
                ));
                break;
            }
            let execution = execute_tree(&adapter, proofs, &tree, started)?;
            (tree, execution)
        };
        let proof_completed = Instant::now();
        let root_metadata = execution.root_metadata.clone();
        if matches!(query.root_lifecycle, RootLifecycle::Rolling) && !root_metadata.can_be_used_recursively {
            stopped_reason = Some(format!(
                "rolling root {} has stacked witness log size {}, outside the recursive input range",
                batch.root_index, root_metadata.stacked_witness_log_size
            ));
        }
        let serialization_started = Instant::now();
        let serialized_root = adapter.serialize(&execution.root);
        let serialized_root_bytes = serialized_root.len();
        std::hint::black_box(serialized_root);
        let serialization_seconds = serialization_started.elapsed().as_secs_f64();
        let serialization_completed = Instant::now();
        let verification_started = Instant::now();
        adapter.verify(&execution.root)?;
        let native_verification_seconds = verification_started.elapsed().as_secs_f64();
        let root_time = serialization_completed.duration_since(started).as_secs_f64();
        let root_bytes = serialized_root_bytes as u64 * query.network.root_proof_recipients as u64;
        root_egress_bytes = root_egress_bytes.saturating_add(root_bytes);
        egress_events.push((root_time, root_bytes as f64));

        if let Some((_, root_parent_bytes)) = execution.all_parent_transmissions.pop() {
            debug_assert_eq!(root_parent_bytes, serialized_root_bytes);
        }
        for (seconds, bytes) in &execution.all_parent_transmissions {
            let transmitted = *bytes as u64 * query.network.intermediate_proof_recipients as u64;
            intermediate_egress_bytes = intermediate_egress_bytes.saturating_add(transmitted);
            egress_events.push((*seconds, transmitted as f64));
        }
        egress_events.sort_by(|left, right| left.0.total_cmp(&right.0));

        let boundary = match query.deadlines.boundary {
            DeadlineBoundary::ProofProduced => proof_completed,
            DeadlineBoundary::Serialized => serialization_completed,
        };
        let mut input_to_root_seconds = Vec::with_capacity(execution.leaves.len());
        let mut batch_collection_seconds = Vec::with_capacity(execution.leaves.len());
        let mut internal_child_wait_seconds = Vec::with_capacity(execution.leaves.len());
        let mut queue_seconds = Vec::with_capacity(execution.leaves.len());
        let mut proving_seconds = Vec::with_capacity(execution.leaves.len());
        let mut proof_metadata_seconds = Vec::with_capacity(execution.leaves.len());
        execution.leaves.sort_by_key(|leaf| leaf.input_index);
        for leaf in &execution.leaves {
            input_to_root_seconds.push(boundary.duration_since(started).as_secs_f64() - leaf.arrival_seconds);
            batch_collection_seconds.push(leaf.batch_collection_seconds);
            internal_child_wait_seconds.push(leaf.internal_child_wait_seconds);
            queue_seconds.push(leaf.queue_seconds);
            proving_seconds.push(leaf.proving_seconds);
            proof_metadata_seconds.push(leaf.proof_metadata_seconds);
        }
        let scheduled_tick_seconds = batch.scheduled_tick_seconds;
        roots.push(RootSample {
            root_index: batch.root_index,
            input_indices: batch.input_indices.clone(),
            input_count: batch.input_indices.len(),
            close_seconds: batch.close_seconds,
            scheduled_tick_seconds,
            service_start_seconds: service_started.duration_since(started).as_secs_f64(),
            proof_completion_seconds: proof_completed.duration_since(started).as_secs_f64(),
            serialization_completion_seconds: serialization_completed.duration_since(started).as_secs_f64(),
            tick_lateness_seconds: scheduled_tick_seconds
                .map(|tick| boundary.duration_since(started).as_secs_f64() - tick),
            tree,
            root: root_metadata,
            parent_jobs: execution.parent_jobs,
            input_to_root_seconds,
            batch_collection_seconds,
            internal_child_wait_seconds,
            queue_seconds,
            proving_seconds,
            proof_metadata_seconds,
            serialization_seconds,
            native_verification_seconds,
        });
        if matches!(query.root_lifecycle, RootLifecycle::Rolling)
            || matches!(
                query.root_policy,
                RootPolicy::Periodic {
                    empty_tick: EmptyTickPolicy::ReusePreviousRoot,
                    ..
                }
            )
        {
            previous_root = Some((execution.root.clone(), execution.root_metadata));
        }
        if stopped_reason.is_some() {
            break;
        }
    }

    let finished = Instant::now();
    let after = process_usage();
    let elapsed_seconds = finished.duration_since(started).as_secs_f64();
    let mut observed_count = events.len().max(1);
    let all_observed_events = loop {
        let generated = arrival_events(&query.arrivals, arrival_rate, observed_count)?;
        let covers_interval = generated.last().is_some_and(|event| event.seconds > elapsed_seconds);
        if covers_interval || matches!(query.arrivals.model, crate::query::ArrivalModel::Trace) {
            break generated
                .into_iter()
                .take_while(|event| event.seconds <= elapsed_seconds)
                .collect::<Vec<_>>();
        }
        observed_count = observed_count
            .checked_mul(2)
            .filter(|count| *count <= 1_000_000)
            .ok_or_else(|| "arrival stream exceeded one million events during the measured interval".to_owned())?;
    };
    let observed_events = events_for_root_shard(
        &all_observed_events,
        &query.root_policy,
        elapsed_seconds,
        root_shard_index,
        root_shard_count,
    )?;
    let observed_leaf_specs = adapter_config.leaf_specs(&query, &all_observed_events)?;
    let exact_ingress_event_count = observed_events
        .iter()
        .filter(|event| leaf_wire_bytes_by_input_index.contains_key(&event.input_index))
        .count();
    let conservatively_sized_ingress_event_count = observed_events.len() - exact_ingress_event_count;
    let ingress_events = observed_events
        .iter()
        .map(|event| {
            let signatures = observed_leaf_specs[event.input_index].signatures;
            let serialized_bytes = leaf_wire_bytes_by_input_index
                .get(&event.input_index)
                .copied()
                .unwrap_or_else(|| {
                    *leaf_wire_bytes_by_signature_count
                        .get(&signatures)
                        .expect("every configured XMSS signature count was prepared")
                });
            (
                event.seconds,
                serialized_bytes as f64 * query.network.remote_input_fraction,
            )
        })
        .collect::<Vec<_>>();
    let use_serialized = matches!(query.deadlines.boundary, DeadlineBoundary::Serialized);
    let backlog = backlog_points(&observed_events, &roots, use_serialized);
    let maximum_backlog_inputs = backlog.iter().map(|point| point.inputs).max().unwrap_or(0);
    let all_input_to_root = roots
        .iter()
        .flat_map(|root| root.input_to_root_seconds.iter().copied())
        .collect::<Vec<_>>();
    let all_batch_collection = roots
        .iter()
        .flat_map(|root| root.batch_collection_seconds.iter().copied())
        .collect::<Vec<_>>();
    let all_internal_wait = roots
        .iter()
        .flat_map(|root| root.internal_child_wait_seconds.iter().copied())
        .collect::<Vec<_>>();
    let all_queue = roots
        .iter()
        .flat_map(|root| root.queue_seconds.iter().copied())
        .collect::<Vec<_>>();
    let all_proving = roots
        .iter()
        .flat_map(|root| root.proving_seconds.iter().copied())
        .collect::<Vec<_>>();
    let all_proof_metadata = roots
        .iter()
        .flat_map(|root| root.proof_metadata_seconds.iter().copied())
        .collect::<Vec<_>>();
    let completion = |root: &RootSample| {
        if use_serialized {
            root.serialization_completion_seconds
        } else {
            root.proof_completion_seconds
        }
    };
    let root_interarrival = roots
        .windows(2)
        .map(|pair| completion(&pair[1]) - completion(&pair[0]))
        .collect::<Vec<_>>();
    let tick_lateness = roots
        .iter()
        .filter_map(|root| root.tick_lateness_seconds)
        .collect::<Vec<_>>();
    let ingress_bytes = ingress_events.iter().map(|(_, bytes)| bytes).sum::<f64>();
    let total_egress_bytes = root_egress_bytes.saturating_add(intermediate_egress_bytes);
    let record = QueryRunRecord {
        schema_version: QUERY_RUN_SCHEMA_VERSION,
        run: run_metadata(&Plan::new(1, 0), &run_id),
        query: query.clone(),
        workload: adapter.description(),
        requested_arrival_rate: arrival_rate,
        leaf_log_inv_rate,
        root_target,
        root_shard_index,
        root_shard_count,
        measured_started_unix_seconds,
        leaf_preparation_seconds,
        leaf_metadata_seconds,
        child_deserialization_seconds: None,
        elapsed_seconds,
        completed_roots: roots.len(),
        completed_inputs: roots.iter().map(|root| root.input_count).sum(),
        input_to_root_seconds: Distribution::from(all_input_to_root),
        batch_collection_seconds: Distribution::from(all_batch_collection),
        internal_child_wait_seconds: Distribution::from(all_internal_wait),
        queue_seconds: Distribution::from(all_queue),
        proving_seconds: Distribution::from(all_proving),
        proof_metadata_seconds: Distribution::from(all_proof_metadata),
        root_interarrival_seconds: Distribution::from(root_interarrival),
        tick_lateness_seconds: Distribution::from(tick_lateness),
        backlog,
        maximum_backlog_inputs,
        effective_cpu_cores: ((after.user_cpu_seconds - before.user_cpu_seconds)
            + (after.system_cpu_seconds - before.system_cpu_seconds))
            / elapsed_seconds.max(f64::EPSILON),
        peak_rss_bytes: after.peak_rss_bytes,
        proof_bandwidth: ProofBandwidth {
            ingress_bytes,
            exact_ingress_event_count,
            conservatively_sized_ingress_event_count,
            root_egress_bytes,
            intermediate_egress_bytes,
            average_ingress_bytes_per_second: ingress_bytes / elapsed_seconds.max(f64::EPSILON),
            average_egress_bytes_per_second: total_egress_bytes as f64 / elapsed_seconds.max(f64::EPSILON),
            maximum_rolling_ingress_bytes_per_second: rolling_peak(
                &ingress_events,
                query.network.rolling_window_seconds,
            ),
            maximum_rolling_egress_bytes_per_second: rolling_peak(&egress_events, query.network.rolling_window_seconds),
            rolling_window_seconds: query.network.rolling_window_seconds,
            ingress_events,
            egress_events,
        },
        all_roots_verified: true,
        stopped_reason,
        root_samples: roots,
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &record).map_err(|error| format!("serialize query run: {error}"))?;
    writeln!(stdout).map_err(|error| format!("write query run: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_close_does_not_count_worker_queue_time() {
        let timing = LeafTiming::at_root_close(7, 2.0, 5.0);
        assert_eq!(timing.batch_collection_seconds, 3.0);
        assert_eq!(timing.queue_seconds, 0.0);
    }

    #[test]
    fn nearest_rank_percentiles_have_the_documented_meaning() {
        let distribution = Distribution::from((1..=100).map(f64::from).collect());
        assert_eq!(distribution.p50, 50.0);
        assert_eq!(distribution.p95, 95.0);
        assert_eq!(distribution.p99, 99.0);
    }

    #[test]
    fn rolling_bandwidth_uses_the_configured_window() {
        let events = [(0.0, 100.0), (0.25, 100.0), (2.0, 50.0)];
        assert_eq!(rolling_peak(&events, 1.0), 200.0);
        assert_eq!(rolling_peak(&events, 0.25), 800.0);
    }

    #[test]
    fn rolling_updates_keep_one_whir_rate_so_the_carried_root_matches_new_inputs() {
        assert_eq!(
            parent_rates_for_lifecycle(RootLifecycle::Rolling, 3, &[1, 2, 3, 4]),
            [3]
        );
        assert_eq!(
            parent_rates_for_lifecycle(RootLifecycle::Independent, 3, &[1, 2, 4]),
            [1, 2, 4]
        );
    }

    #[test]
    fn backlog_counts_arrivals_and_completed_root_inputs() {
        let events = vec![
            ArrivalEvent {
                input_index: 0,
                seconds: 0.0,
                source: 0,
            },
            ArrivalEvent {
                input_index: 1,
                seconds: 1.0,
                source: 0,
            },
        ];
        let root = RootSample {
            root_index: 0,
            input_indices: vec![0, 1],
            input_count: 2,
            close_seconds: 1.0,
            scheduled_tick_seconds: None,
            service_start_seconds: 1.0,
            proof_completion_seconds: 2.0,
            serialization_completion_seconds: 2.1,
            tick_lateness_seconds: None,
            tree: TreePlan {
                leaf_count: 2,
                leaf_log_inv_rate: 2,
                root_log_inv_rate: 2,
                levels: Vec::new(),
                total_jobs: 1,
                estimated_service_seconds: 1.0,
                estimated_peak_rss_bytes: 1,
                all_job_costs_directly_measured: true,
            },
            root: ProofMetadata {
                program: "test".into(),
                fiat_shamir_seed: [[0; 3]; 2],
                log_bytecode: 1,
                log_mem: 1,
                table_log_rows: Vec::new(),
                stacked_witness_log_size: 22,
                log_inv_rate: 2,
                full_proof_bytes: 1,
                proof_without_public_data_bytes: 1,
                public_data_bytes: 0,
                public_data_items: 1,
                can_be_used_recursively: true,
            },
            parent_jobs: Vec::new(),
            input_to_root_seconds: Vec::new(),
            batch_collection_seconds: Vec::new(),
            internal_child_wait_seconds: Vec::new(),
            queue_seconds: Vec::new(),
            proving_seconds: Vec::new(),
            proof_metadata_seconds: Vec::new(),
            serialization_seconds: 0.1,
            native_verification_seconds: 0.1,
        };
        let points = backlog_points(&events, &[root], false);
        assert_eq!(points.iter().map(|point| point.inputs).collect::<Vec<_>>(), [1, 2, 0]);
    }

    #[test]
    fn root_shards_partition_whole_roots_without_losing_inputs() {
        let events = (0..8)
            .map(|input_index| ArrivalEvent {
                input_index,
                seconds: input_index as f64,
                source: 0,
            })
            .collect::<Vec<_>>();
        let policy = RootPolicy::FixedCount { inputs_per_root: 2 };
        let left = events_for_root_shard(&events, &policy, 10.0, 0, 2).unwrap();
        let right = events_for_root_shard(&events, &policy, 10.0, 1, 2).unwrap();
        let left_indices = left
            .iter()
            .map(|event| event.input_index)
            .collect::<std::collections::HashSet<_>>();
        let right_indices = right
            .iter()
            .map(|event| event.input_index)
            .collect::<std::collections::HashSet<_>>();
        assert!(left_indices.is_disjoint(&right_indices));
        assert_eq!(
            left_indices
                .union(&right_indices)
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            8
        );
        assert_eq!(left_indices, [0, 1, 4, 5].into_iter().collect());

        for policy in [
            RootPolicy::Periodic {
                period_seconds: 2.0,
                empty_tick: EmptyTickPolicy::Skip,
            },
            RootPolicy::Timeout {
                timeout_seconds: 2.0,
                max_inputs: None,
            },
        ] {
            let left = events_for_root_shard(&events, &policy, 20.0, 0, 2).unwrap();
            let right = events_for_root_shard(&events, &policy, 20.0, 1, 2).unwrap();
            let left = left
                .iter()
                .map(|event| event.input_index)
                .collect::<std::collections::HashSet<_>>();
            let right = right
                .iter()
                .map(|event| event.input_index)
                .collect::<std::collections::HashSet<_>>();
            assert!(left.is_disjoint(&right));
            assert_eq!(
                left.union(&right)
                    .copied()
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                8
            );
        }
    }
}
