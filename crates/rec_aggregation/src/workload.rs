//! Workload boundary for recursive aggregation benchmarks.
//!
//! Scheduling and hardware analysis operate on this interface. The current
//! implementation is XMSS, while the interface keeps signer-specific data out
//! of the benchmark core.

use serde::{Deserialize, Serialize};
use xmss::{XmssPublicKey, XmssSignature};

use crate::aggregation::{AggregateSignature, MU_MAX, MU_MIN, aggregate_with_stats};
use crate::signers_cache;

/// Common proof information used by scheduling, capacity analysis, and reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofMetadata {
    pub program: String,
    pub fiat_shamir_seed: [[u64; 3]; 2],
    pub log_bytecode: usize,
    pub log_mem: usize,
    pub table_log_rows: Vec<usize>,
    pub stacked_witness_log_size: usize,
    pub log_inv_rate: usize,
    pub full_proof_bytes: usize,
    pub proof_without_public_data_bytes: usize,
    pub public_data_bytes: usize,
    pub public_data_items: usize,
    pub can_be_used_recursively: bool,
}

/// Reader-facing identity and verification boundary for a workload adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadDescription {
    pub adapter: String,
    pub adapter_schema_version: u32,
    pub guest: String,
    pub public_statement: String,
    pub verification_boundary: String,
}

/// Operations the benchmark core needs from an application workload.
pub trait WorkloadAdapter {
    type Proof: Clone;
    type LeafSpec;

    fn adapter_id(&self) -> &'static str;
    fn adapter_schema_version(&self) -> u32;
    fn description(&self) -> WorkloadDescription;
    fn prepare_leaves(&self, specs: &[Self::LeafSpec], log_inv_rate: usize) -> Result<Vec<Self::Proof>, String>;
    fn aggregate(&self, children: &[Self::Proof], log_inv_rate: usize) -> Result<Self::Proof, String>;
    fn verify(&self, proof: &Self::Proof) -> Result<(), String>;
    fn metadata(&self, proof: &Self::Proof) -> Result<ProofMetadata, String>;
    fn serialize(&self, proof: &Self::Proof) -> Vec<u8>;
    fn empty_root(&self, _log_inv_rate: usize) -> Result<Option<Self::Proof>, String> {
        Ok(None)
    }
}

/// One XMSS aggregate used as a leaf proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmssLeafSpec {
    pub signer_start: usize,
    pub signatures: usize,
}

/// Adapter for the recursive XMSS aggregation guest in this checkout.
#[derive(Clone, Copy, Debug, Default)]
pub struct XmssWorkloadAdapter;

impl XmssWorkloadAdapter {
    fn signer_slice(
        spec: &XmssLeafSpec,
        signers: &[(XmssPublicKey, XmssSignature)],
    ) -> Result<Vec<(XmssPublicKey, XmssSignature)>, String> {
        if spec.signatures == 0 {
            return Err("an XMSS leaf needs at least one signature".into());
        }
        let end = spec
            .signer_start
            .checked_add(spec.signatures)
            .ok_or_else(|| "XMSS signer range overflows".to_owned())?;
        signers.get(spec.signer_start..end).map(<[_]>::to_vec).ok_or_else(|| {
            format!(
                "XMSS signer range {}..{end} is outside the prepared pool",
                spec.signer_start
            )
        })
    }
}

impl WorkloadAdapter for XmssWorkloadAdapter {
    type Proof = AggregateSignature;
    type LeafSpec = XmssLeafSpec;

    fn adapter_id(&self) -> &'static str {
        "xmss"
    }

    fn adapter_schema_version(&self) -> u32 {
        1
    }

    fn description(&self) -> WorkloadDescription {
        WorkloadDescription {
            adapter: self.adapter_id().into(),
            adapter_schema_version: self.adapter_schema_version(),
            guest: "crates/rec_aggregation/guests/aggregate.py".into(),
            public_statement: "one XMSS message and epoch plus the sorted signer list covered by the aggregate".into(),
            verification_boundary: "each non-root parent is verified by the recursive parent; each completed root is verified by the native Rust verifier, including deferred claims".into(),
        }
    }

    fn prepare_leaves(&self, specs: &[Self::LeafSpec], log_inv_rate: usize) -> Result<Vec<Self::Proof>, String> {
        if specs.is_empty() {
            return Err("a workload needs at least one leaf proof".into());
        }
        if !(1..=4).contains(&log_inv_rate) {
            return Err(format!(
                "XMSS leaf WHIR inverse-rate logarithm must be in 1..=4, got {log_inv_rate}"
            ));
        }
        let signer_count = specs
            .iter()
            .map(|spec| spec.signer_start.saturating_add(spec.signatures))
            .max()
            .unwrap_or(0);
        let signers = signers_cache::get_signers(signer_count);
        specs
            .iter()
            .map(|spec| {
                let raw = Self::signer_slice(spec, &signers)?;
                aggregate_with_stats(&[], raw, signers_cache::message(), signers_cache::EPOCH, log_inv_rate)
                    .map(|(proof, _)| proof)
                    .map_err(|error| format!("XMSS leaf aggregation failed: {error:?}"))
            })
            .collect()
    }

    fn aggregate(&self, children: &[Self::Proof], log_inv_rate: usize) -> Result<Self::Proof, String> {
        if children.is_empty() {
            return Err("a recursive parent needs at least one child proof".into());
        }
        aggregate_with_stats(
            children,
            Vec::new(),
            signers_cache::message(),
            signers_cache::EPOCH,
            log_inv_rate,
        )
        .map(|(proof, _)| proof)
        .map_err(|error| format!("XMSS recursive aggregation failed: {error:?}"))
    }

    fn verify(&self, proof: &Self::Proof) -> Result<(), String> {
        proof
            .verify_against(&signers_cache::message(), signers_cache::EPOCH)
            .map_err(|error| format!("XMSS aggregate verification failed: {error:?}"))
    }

    fn metadata(&self, proof: &Self::Proof) -> Result<ProofMetadata, String> {
        let shape = proof
            .proof_shape_against(&signers_cache::message(), signers_cache::EPOCH)
            .map_err(|error| format!("read XMSS aggregate proof shape: {error:?}"))?;
        let full_proof_bytes = proof.to_bytes().len();
        let proof_without_public_data_bytes = proof.to_bytes_without_pubkeys().len();
        Ok(ProofMetadata {
            program: "crates/rec_aggregation/guests/aggregate.py".into(),
            fiat_shamir_seed: shape.fs_seed.map(|value| [value.c0, value.c1, value.c2]),
            log_bytecode: shape.log_bytecode,
            log_mem: shape.log_mem,
            table_log_rows: shape.taus.to_vec(),
            stacked_witness_log_size: shape.m,
            log_inv_rate: shape.log_inv_rate,
            full_proof_bytes,
            proof_without_public_data_bytes,
            public_data_bytes: full_proof_bytes.saturating_sub(proof_without_public_data_bytes),
            public_data_items: proof.public_keys.len(),
            can_be_used_recursively: (MU_MIN..=MU_MAX).contains(&shape.m),
        })
    }

    fn serialize(&self, proof: &Self::Proof) -> Vec<u8> {
        proof.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingAdapter;

    impl WorkloadAdapter for CountingAdapter {
        type Proof = usize;
        type LeafSpec = usize;

        fn adapter_id(&self) -> &'static str {
            "counting_test"
        }

        fn adapter_schema_version(&self) -> u32 {
            1
        }

        fn description(&self) -> WorkloadDescription {
            WorkloadDescription {
                adapter: self.adapter_id().into(),
                adapter_schema_version: self.adapter_schema_version(),
                guest: "test".into(),
                public_statement: "positive integer".into(),
                verification_boundary: "test verifier".into(),
            }
        }

        fn prepare_leaves(&self, specs: &[Self::LeafSpec], _log_inv_rate: usize) -> Result<Vec<Self::Proof>, String> {
            Ok(specs.to_vec())
        }

        fn aggregate(&self, children: &[Self::Proof], _log_inv_rate: usize) -> Result<Self::Proof, String> {
            Ok(children.iter().sum())
        }

        fn verify(&self, proof: &Self::Proof) -> Result<(), String> {
            (*proof > 0).then_some(()).ok_or_else(|| "zero proof".into())
        }

        fn metadata(&self, proof: &Self::Proof) -> Result<ProofMetadata, String> {
            Ok(ProofMetadata {
                program: "test".into(),
                fiat_shamir_seed: [[0; 3]; 2],
                log_bytecode: 0,
                log_mem: 0,
                table_log_rows: Vec::new(),
                stacked_witness_log_size: 0,
                log_inv_rate: 1,
                full_proof_bytes: size_of::<usize>(),
                proof_without_public_data_bytes: size_of::<usize>(),
                public_data_bytes: 0,
                public_data_items: *proof,
                can_be_used_recursively: true,
            })
        }

        fn serialize(&self, proof: &Self::Proof) -> Vec<u8> {
            proof.to_le_bytes().to_vec()
        }
    }

    #[test]
    fn metadata_serialization_round_trips() {
        let metadata = ProofMetadata {
            program: "test".into(),
            fiat_shamir_seed: [[0; 3]; 2],
            log_bytecode: 10,
            log_mem: 20,
            table_log_rows: vec![1, 2, 3],
            stacked_witness_log_size: 22,
            log_inv_rate: 2,
            full_proof_bytes: 200,
            proof_without_public_data_bytes: 160,
            public_data_bytes: 40,
            public_data_items: 2,
            can_be_used_recursively: true,
        };
        let encoded = serde_json::to_vec(&metadata).unwrap();
        assert_eq!(serde_json::from_slice::<ProofMetadata>(&encoded).unwrap(), metadata);
    }

    #[test]
    fn workload_contract_is_independent_of_xmss() {
        let adapter = CountingAdapter;
        let leaves = adapter.prepare_leaves(&[2, 3, 5], 1).unwrap();
        let parent = adapter.aggregate(&leaves, 1).unwrap();
        adapter.verify(&parent).unwrap();
        assert_eq!(adapter.metadata(&parent).unwrap().public_data_items, 10);
        assert_eq!(adapter.serialize(&parent), 10usize.to_le_bytes());
    }

    #[test]
    #[ignore = "produces and recursively verifies real XMSS proofs"]
    fn xmss_adapter_produces_and_verifies_recursive_proofs() {
        lean_vm::init_prover_pool();
        let adapter = XmssWorkloadAdapter;
        let leaves = adapter
            .prepare_leaves(
                &[
                    XmssLeafSpec {
                        signer_start: 0,
                        signatures: 1,
                    },
                    XmssLeafSpec {
                        signer_start: 1,
                        signatures: 1,
                    },
                ],
                2,
            )
            .unwrap();
        for leaf in &leaves {
            adapter.verify(leaf).unwrap();
        }
        let parent = adapter.aggregate(&leaves, 2).unwrap();
        adapter.verify(&parent).unwrap();
        assert!(adapter.metadata(&parent).unwrap().can_be_used_recursively);
        let next_leaf = adapter
            .prepare_leaves(
                &[XmssLeafSpec {
                    signer_start: 2,
                    signatures: 1,
                }],
                2,
            )
            .unwrap()
            .pop()
            .unwrap();
        let next_root = adapter.aggregate(&[parent, next_leaf], 2).unwrap();
        adapter.verify(&next_root).unwrap();
        assert_eq!(adapter.metadata(&next_root).unwrap().public_data_items, 3);
    }
}
