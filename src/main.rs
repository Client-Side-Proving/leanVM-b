//! Benchmark CLI for the two flagship workloads (plus the Fibonacci demo): one
//! leaf of an aggregation tree, and an n→1 recursion step over such leaves.
//!
//! ```text
//! cargo run --release -- xmss --n-signatures 820
//! cargo run --release -- xmss --n-signatures 820 --log-inv-rate 2
//! cargo run --release -- xmss --n-signatures 820 --repeat 5
//! cargo run --release -- recursion --n 2 --xmss-per-leaf 900
//! cargo run --release -- fibonacci --n 2000000
//! cargo run --release -- --tracing fibonacci --n 2000000
//! ```
//!
//! Every workload discards one warmup pass before measuring, so a reported
//! duration is steady-state proving rather than a cold first run. `--repeat n`
//! averages `n` measured passes and reports a 95% confidence half-width alongside
//! the mean. `--cooldown` (seconds, default 2) idles before each pass so a
//! thermally limited laptop does not report its power budget as proving cost.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
struct Cli {
    /// WHIR inverse-rate logarithm: 1, 2, 3, or 4 selects rate 1/2,
    /// 1/4, 1/8, or 1/16 respectively.
    #[arg(
        long,
        global = true,
        default_value_t = 1,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=4)
    )]
    log_inv_rate: usize,

    /// Enable hierarchical timing traces. Use RUST_LOG to adjust verbosity.
    #[arg(long, global = true)]
    tracing: bool,

    /// Measured proving passes to average, after the warmup pass. Reported with
    /// a 95% confidence half-width once above 1.
    #[arg(
        long,
        global = true,
        default_value_t = 1,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..)
    )]
    repeat: usize,

    /// Idle seconds before each measured pass. On a thermally limited host (any
    /// Apple laptop) back-to-back proving throttles the SoC and measures the power
    /// budget instead of the prover. The default recovers most of that; use 6 when
    /// comparing two builds, and 0 on a server-class host, which needs none.
    #[arg(long, global = true, default_value_t = 2)]
    cooldown: u64,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Aggregate XMSS signatures inside the VM and verify the proof.
    Xmss {
        /// Number of signatures to aggregate.
        #[arg(long, default_value = "820")]
        n_signatures: usize,
    },
    /// Aggregate n previously aggregated signatures into one proof.
    Recursion {
        /// Number of child aggregates.
        #[arg(long, default_value = "2")]
        n: usize,
        /// Signatures in each child. Sets the child proof's committed size,
        /// which is what the recursion cost should be quoted against.
        #[arg(long, default_value = "900")]
        xmss_per_leaf: usize,
    },
    /// One isolated parent-proof measurement used by the query benchmark.
    #[command(hide = true)]
    RecursionCapacityCase {
        #[arg(long)]
        arity: usize,
        #[arg(long)]
        xmss_per_child: usize,
        #[arg(long)]
        child_log_inv_rate: usize,
        #[arg(long)]
        parent_log_inv_rate: usize,
        #[arg(long, value_delimiter = ',')]
        signer_starts: Vec<usize>,
        #[arg(long)]
        run_id: String,
    },
    /// One isolated privacy-pool parent-proof measurement.
    #[command(hide = true)]
    PrivacyPoolCapacityCase {
        #[arg(long)]
        query: PathBuf,
        #[arg(long)]
        arity: usize,
        #[arg(long)]
        child_log_inv_rate: usize,
        #[arg(long)]
        parent_log_inv_rate: usize,
        #[arg(long)]
        role: String,
        #[arg(long, default_value_t = 1)]
        repeat: usize,
        #[arg(long, default_value_t = 1)]
        performance_workers: usize,
        #[arg(long)]
        leaf_cache_dir: Option<PathBuf>,
        #[arg(long)]
        workload_case: Option<PathBuf>,
        #[arg(long)]
        workload_case_digest: Option<String>,
    },
    /// Resolve one schema-2 tree from measured parent costs.
    #[command(hide = true)]
    PrivacyPoolPlan {
        #[arg(long)]
        query: PathBuf,
        #[arg(long)]
        costs: PathBuf,
        #[arg(long)]
        inputs_per_root: usize,
        #[arg(long)]
        leaf_log_inv_rate: usize,
        #[arg(long)]
        root_log_inv_rate: usize,
        #[arg(long, default_value_t = 1)]
        performance_workers: usize,
    },
    /// One measured application-query point, launched by the Python runner.
    #[command(hide = true)]
    RecursionBenchmarkCase {
        #[arg(long)]
        query: PathBuf,
        #[arg(long)]
        costs: Option<PathBuf>,
        #[arg(long)]
        arrival_rate: Option<f64>,
        #[arg(long)]
        inputs_per_root: Option<usize>,
        #[arg(long, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=4))]
        leaf_log_inv_rate: usize,
        #[arg(long, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        root_target: usize,
        #[arg(long, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=4))]
        root_log_inv_rate: Option<usize>,
        #[arg(long)]
        leaf_cache_dir: Option<PathBuf>,
        #[arg(long)]
        fixed_plan: Option<PathBuf>,
        #[arg(long)]
        run_id: String,
        #[arg(long, default_value_t = 0)]
        root_shard_index: usize,
        #[arg(long, default_value_t = 1)]
        root_shard_count: usize,
        #[arg(long)]
        barrier_dir: Option<PathBuf>,
    },
    /// Validate an application query without starting the prover.
    #[command(hide = true)]
    RecursionBenchmarkValidate {
        #[arg(long)]
        query: PathBuf,
    },
    /// Prove and verify Fibonacci in the exponent (demo).
    Fibonacci {
        /// Number of recurrence steps.
        #[arg(long, default_value = "2000000")]
        n: usize,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Command::RecursionBenchmarkValidate { query } = &cli.command {
        rec_aggregation::BenchmarkQuery::from_path(query).expect("recursion benchmark query is valid");
        println!("valid recursion benchmark query");
        return;
    }
    // Pinned worker pool plus the proving arena, for every workload below. Both
    // are process-wide policy, which is why they are set here and not inside the
    // library entry points.
    lean_vm::init_prover();
    let plan = primitives::bench::Plan::new(cli.repeat, cli.cooldown);
    match &cli.command {
        Command::Xmss { n_signatures } => {
            if cli.tracing {
                primitives::init_tracing();
            }
            rec_aggregation::run_xmss_aggregation(*n_signatures, cli.log_inv_rate, plan);
        }
        // `run_recursion` initializes tracing itself, after the guest compile it
        // does not want traced.
        Command::Recursion { n, xmss_per_leaf } => {
            rec_aggregation::run_recursion(*n, *xmss_per_leaf, cli.log_inv_rate, cli.tracing, plan);
        }
        Command::RecursionCapacityCase {
            arity,
            xmss_per_child,
            child_log_inv_rate,
            parent_log_inv_rate,
            signer_starts,
            run_id,
        } => {
            rec_aggregation::run_recursion_capacity_case(
                *arity,
                *xmss_per_child,
                *child_log_inv_rate,
                *parent_log_inv_rate,
                signer_starts.clone(),
                run_id.clone(),
                plan,
            )
            .expect("parent-proof measurement succeeds");
        }
        Command::PrivacyPoolCapacityCase {
            query,
            arity,
            child_log_inv_rate,
            parent_log_inv_rate,
            role,
            repeat,
            performance_workers,
            leaf_cache_dir,
            workload_case,
            workload_case_digest,
        } => {
            let query_digest =
                rec_aggregation::privacy_pool::file_blake2s_digest(query).expect("capacity query is readable");
            let loaded = rec_aggregation::BenchmarkQuery::from_path(query).expect("capacity query is valid");
            if let Some(case_path) = workload_case {
                if let Some(expected_digest) = workload_case_digest {
                    let actual_digest = rec_aggregation::privacy_pool::file_blake2s_digest(case_path)
                        .expect("workload case is readable");
                    if expected_digest != &actual_digest {
                        panic!("workload case digest does not match the supplied manifest");
                    }
                }
                let case_text = std::fs::read_to_string(case_path).expect("workload case is readable");
                let case: serde_json::Value = serde_json::from_str(&case_text).expect("workload case is JSON");
                if case.get("query_blake2s").and_then(serde_json::Value::as_str) != Some(&query_digest) {
                    panic!("workload case query digest does not match the supplied query");
                }
            }
            let result = rec_aggregation::run_privacy_pool_capacity_case(
                &loaded,
                &query_digest,
                *arity,
                *child_log_inv_rate,
                *parent_log_inv_rate,
                role,
                *repeat,
                *performance_workers,
                leaf_cache_dir.as_deref(),
                workload_case.as_deref(),
            )
            .expect("privacy-pool parent measurement succeeds");
            println!(
                "{}",
                serde_json::to_string(&result).expect("capacity record serializes")
            );
        }
        Command::PrivacyPoolPlan {
            query,
            costs,
            inputs_per_root,
            leaf_log_inv_rate,
            root_log_inv_rate,
            performance_workers,
        } => {
            let loaded = rec_aggregation::BenchmarkQuery::from_path(query).expect("recursion benchmark query is valid");
            let costs_text = std::fs::read_to_string(costs).expect("capacity records are readable");
            let costs_value: serde_json::Value = serde_json::from_str(&costs_text).expect("capacity records are JSON");
            let records = costs_value
                .get("parent_jobs")
                .and_then(serde_json::Value::as_array)
                .expect("capacity records contain parent_jobs");
            let raw_job_costs = records
                .iter()
                .filter_map(|record| {
                    let configuration = record.get("configuration")?;
                    Some(rec_aggregation::query::JobCost {
                        child_count: configuration.get("arity")?.as_u64()? as usize,
                        child_log_inv_rate: configuration.get("child_log_inv_rate")?.as_u64()? as usize,
                        parent_log_inv_rate: configuration.get("parent_log_inv_rate")?.as_u64()? as usize,
                        service_seconds: record.get("mean_service_seconds")?.as_f64()?,
                        peak_rss_bytes: record
                            .get("observed_peak_rss_bytes")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or(0),
                        output_bytes: record.get("proof_bytes")?.as_u64()? as usize,
                        // Capacity records in this table use representative
                        // one-withdrawal children. Upper-level plan jobs have
                        // different child proof shapes and remain provisional.
                        directly_measured: false,
                        performance_workers: record
                            .get("performance_workers")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or(1) as usize,
                    })
                })
                .collect::<Vec<_>>();
            let mut consolidated =
                std::collections::HashMap::<(usize, usize, usize, usize), rec_aggregation::query::JobCost>::new();
            for cost in raw_job_costs {
                let key = (
                    cost.child_count,
                    cost.child_log_inv_rate,
                    cost.parent_log_inv_rate,
                    cost.performance_workers,
                );
                consolidated
                    .entry(key)
                    .and_modify(|current| {
                        current.service_seconds = current.service_seconds.max(cost.service_seconds);
                        current.peak_rss_bytes = current.peak_rss_bytes.max(cost.peak_rss_bytes);
                        current.output_bytes = current.output_bytes.max(cost.output_bytes);
                    })
                    .or_insert(cost);
            }
            let mut job_costs = consolidated
                .values()
                .filter(|cost| cost.performance_workers == *performance_workers)
                .cloned()
                .collect::<Vec<_>>();
            if *performance_workers != 1 {
                let exact_keys = job_costs
                    .iter()
                    .map(|cost| (cost.child_count, cost.child_log_inv_rate, cost.parent_log_inv_rate))
                    .collect::<std::collections::HashSet<_>>();
                for base in consolidated.values().filter(|cost| cost.performance_workers == 1) {
                    let key = (base.child_count, base.child_log_inv_rate, base.parent_log_inv_rate);
                    if exact_keys.contains(&key) {
                        continue;
                    }
                    let mut anchors = [4usize, 16]
                        .into_iter()
                        .filter_map(|arity| {
                            let baseline =
                                consolidated.get(&(arity, base.child_log_inv_rate, base.parent_log_inv_rate, 1))?;
                            let target = consolidated.get(&(
                                arity,
                                base.child_log_inv_rate,
                                base.parent_log_inv_rate,
                                *performance_workers,
                            ))?;
                            Some((
                                arity,
                                target.service_seconds / baseline.service_seconds.max(f64::MIN_POSITIVE),
                                target.peak_rss_bytes as f64 / baseline.peak_rss_bytes.max(1) as f64,
                            ))
                        })
                        .collect::<Vec<_>>();
                    if anchors.is_empty() {
                        continue;
                    }
                    anchors.sort_by_key(|anchor| anchor.0);
                    let interpolate = |field: usize| {
                        if anchors.len() == 1 || base.child_count <= anchors[0].0 {
                            return if field == 1 { anchors[0].1 } else { anchors[0].2 };
                        }
                        let last = anchors[anchors.len() - 1];
                        if base.child_count >= last.0 {
                            return if field == 1 { last.1 } else { last.2 };
                        }
                        let left = anchors[0];
                        let right = anchors[1];
                        let weight = (base.child_count - left.0) as f64 / (right.0 - left.0) as f64;
                        let left_value = if field == 1 { left.1 } else { left.2 };
                        let right_value = if field == 1 { right.1 } else { right.2 };
                        left_value + weight * (right_value - left_value)
                    };
                    let mut modeled = base.clone();
                    modeled.performance_workers = *performance_workers;
                    modeled.service_seconds *= interpolate(1);
                    modeled.peak_rss_bytes = (modeled.peak_rss_bytes as f64 * interpolate(2)).ceil() as u64;
                    modeled.directly_measured = false;
                    job_costs.push(modeled);
                }
            }
            let plan = rec_aggregation::query::plan_tree_with_rate_pairs(
                *inputs_per_root,
                *leaf_log_inv_rate,
                *root_log_inv_rate,
                &loaded.search.arities,
                &loaded.search.nonfinal_rate_pairs,
                &loaded.search.final_rate_pairs,
                &job_costs,
            )
            .expect("schema-2 tree plan resolves");
            println!("{}", serde_json::to_string(&plan).expect("tree plan serializes"));
        }
        Command::RecursionBenchmarkCase {
            query,
            costs,
            arrival_rate,
            inputs_per_root,
            leaf_log_inv_rate,
            root_target,
            root_log_inv_rate,
            leaf_cache_dir,
            fixed_plan,
            run_id,
            root_shard_index,
            root_shard_count,
            barrier_dir,
        } => {
            let loaded = rec_aggregation::BenchmarkQuery::from_path(query).expect("recursion benchmark query is valid");
            if loaded.schema_version == 2 {
                let n = inputs_per_root.expect("schema-2 benchmark cases require --inputs-per-root");
                let root_rate = root_log_inv_rate.unwrap_or(1);
                let assumptions = loaded.assumptions.as_ref().expect("schema-2 assumptions");
                let config = &loaded.workload.adapter_config;
                let seed = config
                    .get("fixture_seed")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(7);
                let count = config
                    .get("fixture_count")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(n as u64) as usize;
                let result = rec_aggregation::privacy_pool::run_query_case(
                    &loaded,
                    &rec_aggregation::privacy_pool::file_blake2s_digest(query).expect("benchmark query is readable"),
                    n,
                    *leaf_log_inv_rate,
                    root_rate,
                    *root_target,
                    loaded
                        .arrivals
                        .period_seconds
                        .expect("schema-2 block bursts require a period"),
                    seed,
                    count,
                    leaf_cache_dir.as_deref(),
                    fixed_plan.as_deref(),
                )
                .expect("privacy-pool query case succeeds");
                println!(
                    "{}",
                    serde_json::json!({"run_id": run_id, "assumptions": assumptions, "result": result})
                );
            } else {
                let rate = arrival_rate.expect("schema-1 benchmark cases require --arrival-rate");
                let costs = costs.as_ref().expect("schema-1 benchmark cases require --costs");
                if inputs_per_root.is_some()
                    || root_log_inv_rate.is_some()
                    || leaf_cache_dir.is_some()
                    || fixed_plan.is_some()
                {
                    panic!("schema-2 benchmark arguments require a schema-2 query");
                }
                rec_aggregation::run_recursion_benchmark_case(
                    query,
                    costs,
                    rate,
                    *leaf_log_inv_rate,
                    *root_target,
                    run_id.clone(),
                    *root_shard_index,
                    *root_shard_count,
                    barrier_dir.as_deref(),
                )
                .expect("recursion benchmark query case succeeds");
            }
        }
        Command::RecursionBenchmarkValidate { .. } => {
            unreachable!("query validation returns before prover initialization")
        }
        Command::Fibonacci { n } => {
            if cli.tracing {
                primitives::init_tracing();
            }
            rec_aggregation::run_fibonacci(*n, cli.log_inv_rate, plan);
        }
    }
    // What the proving arena absorbed, for sizing its slabs and checking that the
    // buffers meant to be arena-backed are.
    if std::env::var_os("ZK_ALLOC_STATS").is_some() {
        eprintln!("{}", zk_alloc::stats());
    }
}
