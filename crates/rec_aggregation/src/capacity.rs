//! Isolated parent-proof measurements used by the application query benchmark.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use primitives::bench::{Plan, process_usage};
use serde::{Deserialize, Serialize};

use crate::aggregation::{AggregateSignature, MAX_CHILDREN, MU_MAX, MU_MIN};
use crate::workload::{ProofMetadata, WorkloadAdapter, XmssLeafSpec, XmssWorkloadAdapter};

const CAPACITY_SCHEMA_VERSION: u32 = 1;
const LEAF_CACHE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LeafCacheKey {
    schema_version: u32,
    signer_start: usize,
    signatures: usize,
    log_inv_rate: usize,
}

fn leaf_cache_path(key: &LeafCacheKey) -> Result<PathBuf, String> {
    let encoded = bincode::serialize(key).map_err(|error| format!("serialize leaf cache key: {error}"))?;
    let digest = primitives::blake2s::hash(&encoded);
    let name = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/recursion-query-leaf-cache")
        .join(format!("{name}.bin")))
}

fn load_or_prepare_leaf(
    adapter: &XmssWorkloadAdapter,
    spec: XmssLeafSpec,
    log_inv_rate: usize,
) -> Result<AggregateSignature, String> {
    let key = LeafCacheKey {
        schema_version: LEAF_CACHE_SCHEMA_VERSION,
        signer_start: spec.signer_start,
        signatures: spec.signatures,
        log_inv_rate,
    };
    let path = leaf_cache_path(&key)?;
    if let Ok(bytes) = fs::read(&path)
        && let Some(proof) = AggregateSignature::from_bytes(&bytes)
        && adapter.verify(&proof).is_ok()
        && adapter
            .metadata(&proof)
            .is_ok_and(|metadata| metadata.log_inv_rate == log_inv_rate)
    {
        return Ok(proof);
    }

    let proof = adapter
        .prepare_leaves(&[spec], log_inv_rate)?
        .pop()
        .expect("one leaf specification produces one proof");
    let parent = path.parent().expect("leaf cache path has a parent");
    fs::create_dir_all(parent).map_err(|error| format!("create leaf cache: {error}"))?;
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&temporary, proof.to_bytes()).map_err(|error| format!("write leaf cache: {error}"))?;
    fs::rename(&temporary, &path).map_err(|error| format!("install leaf cache: {error}"))?;
    Ok(proof)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ProofShapeRecord {
    fs_seed: [[u64; 3]; 2],
    log_bytecode: usize,
    log_mem: usize,
    taus: Vec<usize>,
    m: usize,
    log_inv_rate: usize,
    stacked_witness_capacity: usize,
}

impl From<&ProofMetadata> for ProofShapeRecord {
    fn from(metadata: &ProofMetadata) -> Self {
        Self {
            fs_seed: metadata.fiat_shamir_seed,
            log_bytecode: metadata.log_bytecode,
            log_mem: metadata.log_mem,
            taus: metadata.table_log_rows.clone(),
            m: metadata.stacked_witness_log_size,
            log_inv_rate: metadata.log_inv_rate,
            stacked_witness_capacity: 1usize << metadata.stacked_witness_log_size,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct WhirLevelRecord {
    log_inv_rate: usize,
    log_msg_cols: usize,
    log_num_interleaved: usize,
    folds: usize,
    eta: f64,
    queries: usize,
    query_grinding_bits: usize,
    fold_grinding_bits: usize,
    ood_samples: usize,
    block_len: usize,
    merkle_depth: usize,
}

#[derive(Clone, Debug, Serialize)]
struct WhirScheduleRecord {
    analysis_version: String,
    target_security_bits: usize,
    residual_log_size: usize,
    levels: Vec<WhirLevelRecord>,
}

fn whir_schedule(metadata: &ProofMetadata) -> Result<WhirScheduleRecord, String> {
    let config = pcs::whir::WhirSecurityConfig::derive_config_with_log_inv_rate(
        metadata.stacked_witness_log_size + pcs::LOG_PACKING,
        metadata.log_inv_rate,
    )?;
    let levels = config
        .levels
        .iter()
        .map(|level| {
            let block_len = 1usize << (level.log_msg_cols + level.log_inv_rate);
            WhirLevelRecord {
                log_inv_rate: level.log_inv_rate,
                log_msg_cols: level.log_msg_cols,
                log_num_interleaved: level.log_num_interleaved,
                folds: level.k,
                eta: level.eta,
                queries: level.queries,
                query_grinding_bits: level.grinding_bits,
                fold_grinding_bits: level.fold_grinding_bits,
                ood_samples: level.ood_samples,
                block_len,
                merkle_depth: block_len.trailing_zeros() as usize,
            }
        })
        .collect();
    Ok(WhirScheduleRecord {
        analysis_version: config.analysis_version,
        target_security_bits: config.target_security_bits,
        residual_log_size: config.final_block.yr_log_n,
        levels,
    })
}

#[derive(Clone, Debug, Serialize)]
struct AggregationSample {
    wall_seconds: f64,
    user_cpu_seconds: f64,
    system_cpu_seconds: f64,
    peak_rss_before_bytes: u64,
    peak_rss_after_bytes: u64,
}

#[derive(Serialize)]
struct CapacityConfiguration {
    arity: usize,
    xmss_per_child: usize,
    child_log_inv_rate: usize,
    parent_log_inv_rate: usize,
    signer_starts: Vec<usize>,
}

#[derive(Serialize)]
struct CapacitySummary {
    mean_service_seconds: f64,
    mean_cpu_seconds: f64,
    mean_effective_cpu_cores: f64,
    peak_rss_bytes: u64,
    child_inputs_per_second: f64,
    net_proof_reductions_per_second: f64,
}

#[derive(Serialize)]
struct SizeRecord {
    full_aggregate_bytes: usize,
}

#[derive(Serialize)]
struct CapacityRecord {
    schema_version: u32,
    run: RunMetadata,
    configuration: CapacityConfiguration,
    child_shape: ProofShapeRecord,
    parent_shape: ProofShapeRecord,
    parent_whir: WhirScheduleRecord,
    child_preparation_seconds: f64,
    aggregation_samples: Vec<AggregationSample>,
    parent_verification_seconds: Vec<f64>,
    parent_serialization_seconds: f64,
    sizes: SizeRecord,
    summary: CapacitySummary,
    can_be_child: bool,
}

/// Measure one parent-proof configuration and write one JSON record to stdout.
pub fn run_capacity_case(
    arity: usize,
    xmss_per_child: usize,
    child_log_inv_rate: usize,
    parent_log_inv_rate: usize,
    signer_starts: Vec<usize>,
    run_id: String,
    plan: Plan,
) -> Result<(), String> {
    if !(1..=MAX_CHILDREN).contains(&arity) {
        return Err(format!("parent child count must be in 1..={MAX_CHILDREN}"));
    }
    if xmss_per_child == 0 {
        return Err("each child needs at least one XMSS signature".into());
    }
    if !(1..=4).contains(&child_log_inv_rate) || !(1..=4).contains(&parent_log_inv_rate) {
        return Err("WHIR inverse-rate logarithms must be in 1..=4".into());
    }
    let signer_starts = if signer_starts.is_empty() {
        (0..arity).map(|index| index * xmss_per_child).collect::<Vec<_>>()
    } else {
        signer_starts
    };
    if signer_starts.len() != arity {
        return Err(format!(
            "the signer-start list needs {arity} entries, got {}",
            signer_starts.len()
        ));
    }

    lean_vm::init_prover_pool();
    let adapter = XmssWorkloadAdapter;
    let preparation_started = Instant::now();
    let children = signer_starts
        .iter()
        .map(|signer_start| {
            load_or_prepare_leaf(
                &adapter,
                XmssLeafSpec {
                    signer_start: *signer_start,
                    signatures: xmss_per_child,
                },
                child_log_inv_rate,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let child_preparation_seconds = preparation_started.elapsed().as_secs_f64();
    let child_metadata = adapter.metadata(&children[0])?;
    let child_shape = ProofShapeRecord::from(&child_metadata);
    if children
        .iter()
        .skip(1)
        .map(|proof| adapter.metadata(proof))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .map(ProofShapeRecord::from)
        .any(|shape| shape != child_shape)
    {
        return Err("capacity children do not have one proof shape".into());
    }

    drop(adapter.aggregate(&children, parent_log_inv_rate)?);
    let mut samples = Vec::with_capacity(plan.repeat);
    let mut parent = None;
    for pass in 0..plan.repeat {
        if !plan.cooldown.is_zero() {
            std::thread::sleep(plan.cooldown);
        }
        drop(parent.take());
        let before = process_usage();
        let started = Instant::now();
        let proof = adapter.aggregate(&children, parent_log_inv_rate)?;
        let wall_seconds = started.elapsed().as_secs_f64();
        let after = process_usage();
        samples.push(AggregationSample {
            wall_seconds,
            user_cpu_seconds: (after.user_cpu_seconds - before.user_cpu_seconds).max(0.0),
            system_cpu_seconds: (after.system_cpu_seconds - before.system_cpu_seconds).max(0.0),
            peak_rss_before_bytes: before.peak_rss_bytes,
            peak_rss_after_bytes: after.peak_rss_bytes,
        });
        if pass + 1 == plan.repeat {
            parent = Some(proof);
        }
    }
    let parent = parent.expect("the plan has at least one measured pass");
    let (_, verification) = Plan::new(plan.repeat, 0).measure_quiet(|_| adapter.verify(&parent).unwrap());
    let parent_metadata = adapter.metadata(&parent)?;
    let serialization_started = Instant::now();
    let parent_bytes = adapter.serialize(&parent);
    let parent_serialization_seconds = serialization_started.elapsed().as_secs_f64();

    let sample_count = samples.len() as f64;
    let mean_service_seconds = samples.iter().map(|sample| sample.wall_seconds).sum::<f64>() / sample_count;
    let mean_cpu_seconds = samples
        .iter()
        .map(|sample| sample.user_cpu_seconds + sample.system_cpu_seconds)
        .sum::<f64>()
        / sample_count;
    let mean_effective_cpu_cores = samples
        .iter()
        .map(|sample| (sample.user_cpu_seconds + sample.system_cpu_seconds) / sample.wall_seconds)
        .sum::<f64>()
        / sample_count;
    let peak_rss_bytes = samples
        .iter()
        .map(|sample| sample.peak_rss_after_bytes)
        .max()
        .unwrap_or(0);
    let record = CapacityRecord {
        schema_version: CAPACITY_SCHEMA_VERSION,
        run: run_metadata(&plan, &run_id),
        configuration: CapacityConfiguration {
            arity,
            xmss_per_child,
            child_log_inv_rate,
            parent_log_inv_rate,
            signer_starts,
        },
        child_shape,
        parent_shape: ProofShapeRecord::from(&parent_metadata),
        parent_whir: whir_schedule(&parent_metadata)?,
        child_preparation_seconds,
        aggregation_samples: samples,
        parent_verification_seconds: verification.samples().to_vec(),
        parent_serialization_seconds,
        sizes: SizeRecord {
            full_aggregate_bytes: parent_bytes.len(),
        },
        summary: CapacitySummary {
            mean_service_seconds,
            mean_cpu_seconds,
            mean_effective_cpu_cores,
            peak_rss_bytes,
            child_inputs_per_second: arity as f64 / mean_service_seconds,
            net_proof_reductions_per_second: arity.saturating_sub(1) as f64 / mean_service_seconds,
        },
        can_be_child: (MU_MIN..=MU_MAX).contains(&parent_metadata.stacked_witness_log_size),
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &record).map_err(|error| format!("serialize capacity record: {error}"))?;
    writeln!(stdout).map_err(|error| format!("write capacity record: {error}"))?;
    Ok(())
}

#[derive(Serialize)]
pub(crate) struct RunMetadata {
    run_id: String,
    revision: String,
    working_tree_dirty: bool,
    arena_enabled: bool,
    allocator: String,
    profile: &'static str,
    rustc: String,
    os: &'static str,
    arch: &'static str,
    cpu: String,
    logical_cpus: usize,
    physical_memory_bytes: Option<u64>,
    performance_threads: usize,
    efficiency_threads: usize,
    threads: usize,
    power_mode: String,
    thermal_policy: String,
    repeat: usize,
    cooldown_seconds: f64,
    measured_at_unix_seconds: f64,
}

pub(crate) fn run_metadata(plan: &Plan, run_id: &str) -> RunMetadata {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let revision = command_output("git", &["-C", root.to_str().unwrap_or("."), "rev-parse", "HEAD"]);
    let working_tree_dirty = Command::new("git")
        .args(["-C", root.to_str().unwrap_or("."), "status", "--porcelain"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| !output.stdout.is_empty());
    let cpu = if cfg!(target_os = "macos") {
        let brand = command_output("sysctl", &["-n", "machdep.cpu.brand_string"]);
        if brand == "unknown" {
            command_output("system_profiler", &["SPHardwareDataType"])
                .lines()
                .find_map(|line| line.trim().strip_prefix("Chip: "))
                .unwrap_or("unknown")
                .to_owned()
        } else {
            brand
        }
    } else {
        command_output("sh", &["-c", "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2-"])
    };
    let topology = parallel::topology();
    let arena_enabled = std::env::var_os("LEANVM_NO_ARENA").is_none();
    RunMetadata {
        run_id: run_id.to_owned(),
        revision,
        working_tree_dirty,
        arena_enabled,
        allocator: if arena_enabled { "proving_arena" } else { "system" }.into(),
        profile: if cfg!(debug_assertions) { "debug" } else { "release" },
        rustc: command_output("rustc", &["--version"]),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        cpu,
        logical_cpus: std::thread::available_parallelism().map_or(1, |count| count.get()),
        physical_memory_bytes: physical_memory_bytes(),
        performance_threads: topology.perf,
        efficiency_threads: topology.efficiency,
        threads: parallel::num_threads(),
        power_mode: std::env::var("LEANVM_POWER_MODE").unwrap_or_else(|_| "unknown".into()),
        thermal_policy: std::env::var("LEANVM_THERMAL_POLICY")
            .unwrap_or_else(|_| format!("{} second cooldown", plan.cooldown.as_secs_f64())),
        repeat: plan.repeat,
        cooldown_seconds: plan.cooldown.as_secs_f64(),
        measured_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |duration| duration.as_secs_f64()),
    }
}

fn physical_memory_bytes() -> Option<u64> {
    if cfg!(target_os = "macos") {
        if let Ok(bytes) = command_output("sysctl", &["-n", "hw.memsize"]).parse() {
            return Some(bytes);
        }
        return command_output("system_profiler", &["SPHardwareDataType"])
            .lines()
            .find_map(|line| line.trim().strip_prefix("Memory: "))
            .and_then(parse_memory_size);
    }
    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    let kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    kib.checked_mul(1024)
}

fn parse_memory_size(value: &str) -> Option<u64> {
    let mut fields = value.split_whitespace();
    let amount = fields.next()?.parse::<u64>().ok()?;
    let multiplier = match fields.next()? {
        "KB" => 1u64 << 10,
        "MB" => 1u64 << 20,
        "GB" => 1u64 << 30,
        "TB" => 1u64 << 40,
        _ => return None,
    };
    amount.checked_mul(multiplier)
}

fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
        .filter(|output| !output.is_empty())
        .unwrap_or_else(|| "unknown".into())
}
