//! Independent recursive XMSS and Privacy Pool withdrawal aggregation guests,
//! their benchmark harnesses, and the Fibonacci demo.

pub mod aggregation;
pub mod benchmark;
mod capacity;
pub mod fibonacci;
/// The BLAKE2s hash chain, proven end to end. A `src` module rather than its own
/// test binary so it shares the process, and so the ~1.9 s flock circuit build,
/// with the other workloads.
#[cfg(test)]
mod hash_chain;
pub mod privacy_pool;
// This module keeps a mechanically aligned copy of the recursive verifier.
// Some XMSS application helpers remain in that copy so protocol changes can be
// applied and compared against the original implementation.
#[allow(dead_code)]
mod privacy_recursive;
pub mod query;
pub mod query_run;
pub mod signers_cache;
pub mod workload;

pub use aggregation::{AggregateError, AggregateSignature, VerifyError, aggregate};
pub use benchmark::{run_recursion, run_xmss_aggregation};
pub use capacity::run_capacity_case as run_recursion_capacity_case;
pub use fibonacci::run_fibonacci;
pub use privacy_pool::run_capacity_case as run_privacy_pool_capacity_case;
pub use privacy_pool::{
    Hash256, PrivacyError, PrivacyPoolProof, PrivacyPoolWorkloadAdapter, Withdrawal, WithdrawalFixture,
    WithdrawalPublic, WithdrawalWitness,
};
pub use query::{
    ArrivalConfig, ArrivalEvent, BenchmarkAssumptions, BenchmarkQuery, JobCost, ProofSource, RatePair, RootBatch,
    RootLifecycle, RootPolicy, TreeLevelPlan, TreePlan, arrival_events, close_root_batches, plan_tree,
    plan_tree_with_rate_pairs,
};
pub use query_run::run_query_case as run_recursion_benchmark_case;
pub use workload::{ProofMetadata, WorkloadAdapter, WorkloadDescription, XmssLeafSpec, XmssWorkloadAdapter};

/// The pieces every workload's benchmark report ends with.
///
/// Each caller drops its root tracing span before printing: tracing-forest
/// renders its tree only when that span closes, so the complete trace has to be
/// flushed above the report.
mod report {
    use primitives::pretty_f64;

    /// A count as a power of two, or a dash when the opcode never ran.
    pub fn pow(x: usize) -> String {
        if x == 0 {
            "     -".into()
        } else {
            format!("2^{}", pretty_f64((x as f64).log2()))
        }
    }

    /// Peak resident set size, in GiB.
    pub fn peak_gib() -> String {
        pretty_f64(primitives::bench::peak_rss_bytes() as f64 / (1u64 << 30) as f64)
    }

    pub fn print_proof_size<T: serde::Serialize>(proof: &T) {
        let bytes = bincode::serialized_size(proof).expect("proof is serializable");
        println!("  proof size                  : {:.1} KiB", bytes as f64 / 1024.0);
    }
}
