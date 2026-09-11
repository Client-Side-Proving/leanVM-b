//! Privacy Pool withdrawal fixtures and recursive proof boundary.
//!
//! A withdrawal leaf binds the public withdrawal amount, context, tree depth,
//! state root, ASP root, existing nullifier hash, and new commitment hash. The
//! private witness carries the old and new raw nullifiers, secret, remaining
//! value, and two depth-32 Merkle paths. The recursive wrapper binds the
//! canonical ordered list of complete public withdrawals in its public input.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use primitives::blake2s;
use primitives::field::F192;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::workload::WorkloadAdapter;

pub const TREE_DEPTH: usize = 32;
pub(crate) const PROOF_SERIALIZATION_VERSION: u32 = 1;
pub const ADAPTER_SCHEMA_VERSION: u32 = 1;
pub const HASH_NAME: &str = "blake2s_256";
pub type Hash256 = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct U128(pub u128);

impl U128 {
    pub fn cells(self) -> [F192; 2] {
        [F192::new(self.0 as u64, (self.0 >> 64) as u64, 0), F192::ZERO]
    }

    pub fn bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    pub fn add_u129(self, other: Self) -> U129 {
        U129 {
            low: self.0.wrapping_add(other.0),
            high: self.0.checked_add(other.0).is_none(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath {
    pub leaf: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub index: u32,
    pub root: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WithdrawalPublic {
    pub withdrawn_value: u128,
    pub state_root: Hash256,
    pub state_tree_depth: u8,
    pub asp_root: Hash256,
    pub asp_tree_depth: u8,
    pub context: Hash256,
    pub new_commitment_hash: Hash256,
    pub existing_nullifier_hash: Hash256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalWitness {
    pub label: Hash256,
    pub existing_value: U129,
    pub remaining_value: u128,
    pub existing_nullifier: Hash256,
    pub existing_secret: Hash256,
    pub new_nullifier: Hash256,
    pub new_secret: Hash256,
    pub state_siblings: Vec<Hash256>,
    pub state_index: u32,
    pub asp_siblings: Vec<Hash256>,
    pub asp_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withdrawal {
    pub label: [u8; 32],
    pub withdrawn: U128,
    pub context: [u8; 32],
    pub state_tree_depth: u32,
    pub state_root: [u8; 32],
    pub asp_tree_depth: u32,
    pub asp_root: [u8; 32],
    pub new_nullifier_hash: [u8; 32],
    pub new_commitment_hash: [u8; 32],
    pub old_nullifier: [u8; 32],
    pub existing_value: U129,
    pub existing_secret: [u8; 32],
    pub new_nullifier: [u8; 32],
    pub new_secret: [u8; 32],
    pub remaining: U128,
    pub state_path: MerklePath,
    pub asp_path: MerklePath,
}

impl Withdrawal {
    pub fn public(&self) -> WithdrawalPublic {
        WithdrawalPublic {
            withdrawn_value: self.withdrawn.0,
            state_root: self.state_root,
            state_tree_depth: self.state_tree_depth as u8,
            asp_root: self.asp_root,
            asp_tree_depth: self.asp_tree_depth as u8,
            context: self.context,
            new_commitment_hash: self.new_commitment_hash,
            existing_nullifier_hash: h1(&self.old_nullifier),
        }
    }

    pub fn witness(&self) -> WithdrawalWitness {
        WithdrawalWitness {
            label: self.label,
            existing_value: self.existing_value,
            remaining_value: self.remaining.0,
            existing_nullifier: self.old_nullifier,
            existing_secret: self.existing_secret,
            new_nullifier: self.new_nullifier,
            new_secret: self.new_secret,
            state_siblings: self.state_path.siblings.clone(),
            state_index: self.state_path.index,
            asp_siblings: self.asp_path.siblings.clone(),
            asp_index: self.asp_path.index,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalFixture {
    pub index: usize,
    pub withdrawal: Withdrawal,
    pub claim_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivacyError {
    InvalidConfig(String),
    InvalidWithdrawal(String),
    InvalidProof(String),
    InvalidList(String),
    Vm(lean_vm::cpu::Error),
}

impl std::fmt::Display for PrivacyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PrivacyError {}

fn tagged(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut input = Vec::with_capacity(label.len() + parts.iter().map(|part| part.len()).sum::<usize>());
    input.extend_from_slice(label);
    for part in parts {
        input.extend_from_slice(part);
    }
    blake2s::hash(&input)
}

pub fn h1(value: &[u8; 32]) -> [u8; 32] {
    blake2s::hash(value)
}

pub fn h2(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(left);
    block[32..].copy_from_slice(right);
    blake2s::hash(&block)
}

pub fn h3(value: &[u8; 32], label: &[u8; 32], precommitment: &[u8; 32]) -> [u8; 32] {
    let mut block = [0u8; 96];
    block[..32].copy_from_slice(value);
    block[32..64].copy_from_slice(label);
    block[64..].copy_from_slice(precommitment);
    blake2s::hash(&block)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct U129 {
    pub low: u128,
    pub high: bool,
}

fn amount32(value: U128) -> [u8; 32] {
    raw32(&value.bytes())
}

fn amount129_32(value: U129) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&value.low.to_le_bytes());
    out[16] = value.high as u8;
    out
}

pub fn u129_bytes(value: U129) -> [u8; 17] {
    let mut out = [0u8; 17];
    out[..16].copy_from_slice(&value.low.to_le_bytes());
    out[16] = value.high as u8;
    out
}

fn path_root(path: &MerklePath) -> Result<[u8; 32], PrivacyError> {
    if path.siblings.len() != TREE_DEPTH {
        return Err(PrivacyError::InvalidWithdrawal(
            "Merkle paths must have depth 32".into(),
        ));
    }
    let mut node = path.leaf;
    for (level, sibling) in path.siblings.iter().enumerate() {
        if *sibling == [0; 32] {
            continue;
        }
        node = if (path.index >> level) & 1 == 0 {
            h2(&node, sibling)
        } else {
            h2(sibling, &node)
        };
    }
    Ok(node)
}

pub fn validate_withdrawal(withdrawal: &Withdrawal) -> Result<(), PrivacyError> {
    if withdrawal.state_tree_depth as usize != TREE_DEPTH {
        return Err(PrivacyError::InvalidWithdrawal("state tree depth must be 32".into()));
    }
    if withdrawal.asp_tree_depth as usize != TREE_DEPTH {
        return Err(PrivacyError::InvalidWithdrawal("ASP tree depth must be 32".into()));
    }
    if withdrawal.old_nullifier == withdrawal.new_nullifier {
        return Err(PrivacyError::InvalidWithdrawal(
            "old and new raw nullifiers must differ".into(),
        ));
    }
    if withdrawal.existing_value != withdrawal.withdrawn.add_u129(withdrawal.remaining) {
        return Err(PrivacyError::InvalidWithdrawal(
            "existing value is not withdrawn plus remaining".into(),
        ));
    }
    let state_leaf = h3(
        &amount129_32(withdrawal.existing_value),
        &withdrawal.label,
        &h2(&withdrawal.old_nullifier, &withdrawal.existing_secret),
    );
    if withdrawal.state_path.leaf != state_leaf || path_root(&withdrawal.state_path)? != withdrawal.state_root {
        return Err(PrivacyError::InvalidWithdrawal(
            "state Merkle path does not reach state_root".into(),
        ));
    }
    let asp_leaf = withdrawal.label;
    if withdrawal.asp_path.leaf != asp_leaf || path_root(&withdrawal.asp_path)? != withdrawal.asp_root {
        return Err(PrivacyError::InvalidWithdrawal(
            "ASP Merkle path does not reach asp_root".into(),
        ));
    }
    if h1(&withdrawal.new_nullifier) != withdrawal.new_nullifier_hash {
        return Err(PrivacyError::InvalidWithdrawal(
            "new nullifier hash is not H1(new nullifier)".into(),
        ));
    }
    if h3(
        &amount32(withdrawal.remaining),
        &withdrawal.label,
        &h2(&withdrawal.new_nullifier, &withdrawal.new_secret),
    ) != withdrawal.new_commitment_hash
    {
        return Err(PrivacyError::InvalidWithdrawal(
            "new commitment hash is not H3(secret)".into(),
        ));
    }
    Ok(())
}

pub fn claim_id(withdrawal: &Withdrawal) -> [u8; 32] {
    withdrawal_claim_id(&withdrawal.public())
}

pub fn withdrawal_claim_id(public: &WithdrawalPublic) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(288);
    let mut tag = [0u8; 32];
    let label = b"leanvm-b/pp-withdrawal-claim/v1";
    assert!(label.len() <= tag.len());
    tag[..label.len()].copy_from_slice(label);
    preimage.extend_from_slice(&tag);
    preimage.extend_from_slice(&amount32(U128(public.withdrawn_value)));
    preimage.extend_from_slice(&public.state_root);
    preimage.extend_from_slice(&raw32(&public.state_tree_depth.to_le_bytes()));
    preimage.extend_from_slice(&public.asp_root);
    preimage.extend_from_slice(&raw32(&public.asp_tree_depth.to_le_bytes()));
    preimage.extend_from_slice(&public.context);
    preimage.extend_from_slice(&public.new_commitment_hash);
    preimage.extend_from_slice(&public.existing_nullifier_hash);
    assert_eq!(preimage.len(), 288);
    blake2s::hash(&preimage)
}

pub fn encode_withdrawal_public(public: &WithdrawalPublic) -> [u8; 256] {
    let mut out = [0u8; 256];
    out[..32].copy_from_slice(&amount32(U128(public.withdrawn_value)));
    out[32..64].copy_from_slice(&public.state_root);
    out[64..96].copy_from_slice(&raw32(&public.state_tree_depth.to_le_bytes()));
    out[96..128].copy_from_slice(&public.asp_root);
    out[128..160].copy_from_slice(&raw32(&public.asp_tree_depth.to_le_bytes()));
    out[160..192].copy_from_slice(&public.context);
    out[192..224].copy_from_slice(&public.new_commitment_hash);
    out[224..].copy_from_slice(&public.existing_nullifier_hash);
    out
}

pub fn decode_withdrawal_public(bytes: &[u8]) -> Result<WithdrawalPublic, PrivacyError> {
    if bytes.len() != 256 {
        return Err(PrivacyError::InvalidList(
            "encoded withdrawal public data must be 256 bytes".into(),
        ));
    }
    if bytes[16..32].iter().any(|byte| *byte != 0)
        || bytes[65..96].iter().any(|byte| *byte != 0)
        || bytes[129..160].iter().any(|byte| *byte != 0)
    {
        return Err(PrivacyError::InvalidList(
            "encoded withdrawal public data is not canonical".into(),
        ));
    }
    Ok(WithdrawalPublic {
        withdrawn_value: u128::from_le_bytes(bytes[..16].try_into().expect("amount width")),
        state_root: bytes[32..64].try_into().expect("state root width"),
        state_tree_depth: bytes[64],
        asp_root: bytes[96..128].try_into().expect("ASP root width"),
        asp_tree_depth: bytes[128],
        context: bytes[160..192].try_into().expect("context width"),
        new_commitment_hash: bytes[192..224].try_into().expect("commitment width"),
        existing_nullifier_hash: bytes[224..256].try_into().expect("nullifier width"),
    })
}

fn raw32(value: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..value.len()].copy_from_slice(value);
    out
}

pub fn list_digest(ids: &[[u8; 32]]) -> Result<[u8; 32], PrivacyError> {
    if ids.is_empty() {
        return Err(PrivacyError::InvalidList("withdrawal list must be nonempty".into()));
    }
    let mut tag = [0u8; 32];
    let label = b"leanvm-b/pp-claim-list/v1";
    tag[..label.len()].copy_from_slice(label);
    let mut count = [0u8; 32];
    count[..8].copy_from_slice(&(ids.len() as u64).to_le_bytes());
    let mut state = h2(&tag, &count);
    for id in ids {
        state = h2(&state, id);
    }
    Ok(state)
}

pub fn withdrawal_list_digest(withdrawals: &[WithdrawalPublic]) -> Result<[u8; 32], PrivacyError> {
    if withdrawals.iter().any(|withdrawal| {
        withdrawal.state_tree_depth as usize != TREE_DEPTH || withdrawal.asp_tree_depth as usize != TREE_DEPTH
    }) {
        return Err(PrivacyError::InvalidList(
            "withdrawal list tree depths must both be 32".into(),
        ));
    }
    if withdrawals.is_empty()
        || !withdrawals
            .windows(2)
            .all(|window| window[0].existing_nullifier_hash < window[1].existing_nullifier_hash)
    {
        return Err(PrivacyError::InvalidList(
            "withdrawals must be nonempty and strictly sorted by existing nullifier hash".into(),
        ));
    }
    let ids = withdrawals.iter().map(withdrawal_claim_id).collect::<Vec<_>>();
    list_digest(&ids)
}

pub type PrivacyPoolProof = crate::privacy_recursive::PrivacyAggregate;

fn leaf_cache_path(
    cache_dir: &Path,
    program_identity: &str,
    fixture_seed: u64,
    fixture_count: usize,
    fixture_index: usize,
    log_inv_rate: usize,
) -> std::path::PathBuf {
    cache_dir.join(format!(
        "privacy-pool-withdrawal-a{}-p{}-g{}-s{}-c{}-i{}-r{}.bin",
        ADAPTER_SCHEMA_VERSION,
        PROOF_SERIALIZATION_VERSION,
        program_identity,
        fixture_seed,
        fixture_count,
        fixture_index,
        log_inv_rate,
    ))
}

pub fn fixture(seed: u64, index: usize) -> WithdrawalFixture {
    let mut rng = StdRng::seed_from_u64(seed ^ index as u64);
    let old_nullifier = blake2s::hash(&rng.random::<[u8; 32]>());
    let new_nullifier = blake2s::hash(&rng.random::<[u8; 32]>());
    let label = rng.random::<[u8; 32]>();
    let existing_secret = rng.random::<[u8; 32]>();
    let new_secret = rng.random::<[u8; 32]>();
    let withdrawn = U128(rng.random());
    let remaining = U128(rng.random());
    let existing_value = U129 {
        low: withdrawn.0.wrapping_add(remaining.0),
        high: withdrawn.0.checked_add(remaining.0).is_none(),
    };
    let existing_commitment = h3(
        &amount129_32(existing_value),
        &label,
        &h2(&old_nullifier, &existing_secret),
    );
    let mut state_path = MerklePath {
        leaf: existing_commitment,
        siblings: Vec::new(),
        index: rng.random(),
        root: [0; 32],
    };
    let mut asp_path = MerklePath {
        leaf: label,
        siblings: Vec::new(),
        index: rng.random(),
        root: [0; 32],
    };
    for level in 0..TREE_DEPTH {
        state_path.siblings.push(tagged(
            b"privacy-pool/state-sibling",
            &[&index.to_le_bytes(), &(level as u64).to_le_bytes()],
        ));
        asp_path.siblings.push(tagged(
            b"privacy-pool/asp-sibling",
            &[&index.to_le_bytes(), &(level as u64).to_le_bytes()],
        ));
    }
    state_path.root = path_root(&state_path).expect("generated state path");
    asp_path.root = path_root(&asp_path).expect("generated ASP path");
    let withdrawal = Withdrawal {
        withdrawn,
        context: rng.random(),
        state_tree_depth: TREE_DEPTH as u32,
        state_root: state_path.root,
        asp_tree_depth: TREE_DEPTH as u32,
        asp_root: asp_path.root,
        new_nullifier_hash: h1(&new_nullifier),
        new_commitment_hash: h3(&amount32(remaining), &label, &h2(&new_nullifier, &new_secret)),
        label,
        old_nullifier,
        existing_value,
        existing_secret,
        new_nullifier,
        new_secret,
        remaining,
        state_path,
        asp_path,
    };
    let claim_id = claim_id(&withdrawal);
    WithdrawalFixture {
        index,
        withdrawal,
        claim_id,
    }
}

pub fn fixtures(seed: u64, count: usize) -> Vec<WithdrawalFixture> {
    (0..count).map(|index| fixture(seed, index)).collect()
}

#[derive(Clone, Debug)]
pub struct PrivacyPoolWorkloadAdapter {
    pub fixture_seed: u64,
    pub fixture_count: usize,
    pub cache_dir: Option<std::path::PathBuf>,
    cache_hits: Arc<AtomicUsize>,
    cache_misses: Arc<AtomicUsize>,
}

impl PrivacyPoolWorkloadAdapter {
    pub fn new(fixture_seed: u64, fixture_count: usize) -> Result<Self, PrivacyError> {
        if fixture_count == 0 {
            return Err(PrivacyError::InvalidConfig("fixture_count must be positive".into()));
        }
        Ok(Self {
            fixture_seed,
            fixture_count,
            cache_dir: None,
            cache_hits: Arc::new(AtomicUsize::new(0)),
            cache_misses: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn with_cache_dir(mut self, cache_dir: impl Into<std::path::PathBuf>) -> Self {
        self.cache_dir = Some(cache_dir.into());
        self
    }

    pub fn fixture(&self, index: usize) -> Result<WithdrawalFixture, PrivacyError> {
        if index >= self.fixture_count {
            return Err(PrivacyError::InvalidConfig(
                "fixture index exceeds fixture_count".into(),
            ));
        }
        Ok(fixture(self.fixture_seed, index))
    }

    pub fn cache_stats(&self) -> (usize, usize) {
        (
            self.cache_hits.load(Ordering::Relaxed),
            self.cache_misses.load(Ordering::Relaxed),
        )
    }
}

impl crate::workload::WorkloadAdapter for PrivacyPoolWorkloadAdapter {
    type Proof = PrivacyPoolProof;
    type LeafSpec = usize;

    fn adapter_id(&self) -> &'static str {
        "privacy_pool_withdrawal"
    }
    fn adapter_schema_version(&self) -> u32 {
        ADAPTER_SCHEMA_VERSION
    }

    fn description(&self) -> crate::workload::WorkloadDescription {
        crate::workload::WorkloadDescription {
            adapter: self.adapter_id().into(),
            adapter_schema_version: self.adapter_schema_version(),
            guest: "crates/rec_aggregation/guests/privacy_pool_withdrawal.py".into(),
            public_statement:
                "complete public withdrawals ordered by existing nullifier hash and bound through claim IDs".into(),
            verification_boundary:
                "the native adapter verifies child proofs and roots against the exact withdrawal list".into(),
        }
    }

    fn prepare_leaves(&self, specs: &[Self::LeafSpec], log_inv_rate: usize) -> Result<Vec<Self::Proof>, String> {
        specs
            .iter()
            .map(|index| {
                let item = self.fixture(*index).map_err(|error| error.to_string())?;
                if let Some(cache_dir) = &self.cache_dir {
                    let program_id = hex_digest(&crate::privacy_recursive::privacy_program_identity());
                    let path = leaf_cache_path(
                        cache_dir,
                        &program_id,
                        self.fixture_seed,
                        self.fixture_count,
                        *index,
                        log_inv_rate,
                    );
                    if let Ok(bytes) = std::fs::read(&path)
                        && let Some(proof) = PrivacyPoolProof::from_bytes(&bytes)
                    {
                        let shape_matches = proof
                            .metadata()
                            .map(|metadata| metadata.log_inv_rate == log_inv_rate)
                            .unwrap_or(false);
                        if shape_matches && proof.verify_against(&[item.withdrawal.public()]).is_ok() {
                            self.cache_hits.fetch_add(1, Ordering::Relaxed);
                            return Ok(proof);
                        }
                    }
                    self.cache_misses.fetch_add(1, Ordering::Relaxed);
                    std::fs::create_dir_all(cache_dir).map_err(|error| error.to_string())?;
                    let proof = PrivacyPoolProof::prove_leaf(&item.withdrawal, log_inv_rate)
                        .map_err(|error| error.to_string())?;
                    let temporary = path.with_extension(format!("tmp-{}-{}", std::process::id(), index));
                    use std::io::Write;
                    let mut file = std::fs::File::create(&temporary).map_err(|error| error.to_string())?;
                    file.write_all(&proof.to_bytes()).map_err(|error| error.to_string())?;
                    file.sync_all().map_err(|error| error.to_string())?;
                    std::fs::rename(&temporary, &path).map_err(|error| error.to_string())?;
                    return Ok(proof);
                }
                PrivacyPoolProof::prove_leaf(&item.withdrawal, log_inv_rate).map_err(|error| error.to_string())
            })
            .collect()
    }

    fn aggregate(&self, children: &[Self::Proof], log_inv_rate: usize) -> Result<Self::Proof, String> {
        PrivacyPoolProof::aggregate(children, log_inv_rate).map_err(|error| error.to_string())
    }

    fn verify(&self, proof: &Self::Proof) -> Result<(), String> {
        proof.verify().map_err(|error| error.to_string())
    }

    fn metadata(&self, proof: &Self::Proof) -> Result<crate::workload::ProofMetadata, String> {
        proof.metadata().map_err(|error| error.to_string())
    }

    fn serialize(&self, proof: &Self::Proof) -> Vec<u8> {
        proof.to_bytes()
    }

    fn statement_items(&self, proof: &Self::Proof) -> Result<Vec<Vec<u8>>, String> {
        Ok(proof
            .withdrawals
            .iter()
            .map(|public| encode_withdrawal_public(public).to_vec())
            .collect())
    }

    fn verify_against_items(&self, proof: &Self::Proof, expected: &[Vec<u8>]) -> Result<(), String> {
        let expected = expected
            .iter()
            .map(|item| decode_withdrawal_public(item).map_err(|error| error.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        proof.verify_against(&expected).map_err(|error| error.to_string())
    }

    fn deserialize(&self, bytes: &[u8]) -> Result<Self::Proof, String> {
        PrivacyPoolProof::from_bytes(bytes).ok_or_else(|| "invalid privacy-pool proof bytes".into())
    }
}

pub fn write_fixture(path: &Path, value: &WithdrawalFixture) -> Result<(), PrivacyError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| PrivacyError::InvalidConfig(error.to_string()))?;
    std::fs::write(path, bytes).map_err(|error| PrivacyError::InvalidConfig(error.to_string()))
}

pub fn file_blake2s_digest(path: &Path) -> Result<String, PrivacyError> {
    let bytes = std::fs::read(path).map_err(|error| PrivacyError::InvalidConfig(error.to_string()))?;
    Ok(hex_digest(&blake2s::hash(&bytes)))
}

pub fn run_capacity_case(
    query: &crate::query::BenchmarkQuery,
    query_blake2s: &str,
    arity: usize,
    child_log_inv_rate: usize,
    parent_log_inv_rate: usize,
    role: &str,
    repeat: usize,
    performance_workers: usize,
    leaf_cache_dir: Option<&Path>,
    workload_case: Option<&Path>,
) -> Result<serde_json::Value, PrivacyError> {
    if !matches!(role, "nonfinal" | "final" | "diagnostic") {
        return Err(PrivacyError::InvalidConfig(
            "capacity role must be nonfinal, final, or diagnostic".into(),
        ));
    }
    let adapter_config = query
        .workload
        .adapter_config
        .as_object()
        .ok_or_else(|| PrivacyError::InvalidConfig("privacy-pool adapter config must be an object".into()))?;
    let fixture_seed = adapter_config
        .get("fixture_seed")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| PrivacyError::InvalidConfig("privacy-pool adapter config needs fixture_seed".into()))?;
    let fixture_count = adapter_config
        .get("fixture_count")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| PrivacyError::InvalidConfig("privacy-pool adapter config needs fixture_count".into()))?
        as usize;
    if !(2..=16).contains(&arity) || fixture_count < arity || repeat == 0 {
        return Err(PrivacyError::InvalidConfig("invalid privacy-pool capacity case".into()));
    }
    let workload_case_value = if let Some(case_path) = workload_case {
        let case_text = std::fs::read_to_string(case_path)
            .map_err(|error| PrivacyError::InvalidConfig(format!("cannot read workload case: {error}")))?;
        let case: serde_json::Value = serde_json::from_str(&case_text)
            .map_err(|error| PrivacyError::InvalidConfig(format!("invalid workload case: {error}")))?;
        validate_capacity_manifest(&case, arity, child_log_inv_rate, parent_log_inv_rate, fixture_seed)?;
        Some(case)
    } else {
        None
    };
    if performance_workers == 0 {
        return Err(PrivacyError::InvalidConfig(
            "performance_workers must be positive".into(),
        ));
    }
    lean_vm::init_prover_pool();
    let mut adapter = PrivacyPoolWorkloadAdapter::new(fixture_seed, fixture_count)?;
    if let Some(cache_dir) = leaf_cache_dir {
        adapter = adapter.with_cache_dir(cache_dir);
    }
    let children = if let Some(specs) = workload_case_value
        .as_ref()
        .and_then(|case| case.get("children"))
        .and_then(serde_json::Value::as_array)
    {
        specs
            .iter()
            .map(|spec| build_capacity_child(&adapter, spec))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        adapter
            .prepare_leaves(&(0..arity).collect::<Vec<_>>(), child_log_inv_rate)
            .map_err(PrivacyError::InvalidConfig)?
    };
    if children.len() != arity {
        return Err(PrivacyError::InvalidConfig(
            "workload case child count does not match arity".into(),
        ));
    }
    let child_shapes = children
        .iter()
        .map(|child| adapter.metadata(child).map_err(PrivacyError::InvalidConfig))
        .collect::<Result<Vec<_>, _>>()?;
    if child_shapes
        .iter()
        .any(|shape| shape.log_inv_rate != child_log_inv_rate)
    {
        return Err(PrivacyError::InvalidConfig(
            "workload case child rate does not match capacity arguments".into(),
        ));
    }
    let mut samples = Vec::with_capacity(repeat);
    let mut parent = None;
    for _ in 0..repeat {
        let started = std::time::Instant::now();
        let proof = adapter
            .aggregate(&children, parent_log_inv_rate)
            .map_err(PrivacyError::InvalidConfig)?;
        samples.push(started.elapsed().as_secs_f64());
        parent = Some(proof);
    }
    let parent = parent.expect("capacity repeat is positive");
    let mut expected = children
        .iter()
        .flat_map(|child| child.withdrawals.iter().copied())
        .collect::<Vec<_>>();
    expected.sort_by_key(|public| public.existing_nullifier_hash);
    parent.verify_against(&expected)?;
    let parent_shape = adapter.metadata(&parent).map_err(PrivacyError::InvalidConfig)?;
    let program_identity = hex_digest(&crate::privacy_recursive::privacy_program_identity());
    let adapter_config_digest = hex_digest(&blake2s::hash(
        &serde_json::to_vec(&query.workload.adapter_config)
            .map_err(|error| PrivacyError::InvalidConfig(error.to_string()))?,
    ));
    let workload_case_id = workload_case.and_then(|path| {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|case| {
                case.get("case_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
    });
    let workload_case_blake2s = workload_case.map(file_blake2s_digest).transpose()?;
    let ordered_child_claim_counts = children.iter().map(|child| child.withdrawals.len()).collect::<Vec<_>>();
    let shape_material = serde_json::json!({
        "program_identity": program_identity,
        "ordered_child_claim_counts": ordered_child_claim_counts,
        "child_shapes": child_shapes,
        "total_parent_claim_count": ordered_child_claim_counts.iter().sum::<usize>(),
        "child_log_inv_rate": child_log_inv_rate,
        "parent_log_inv_rate": parent_log_inv_rate,
        "arity": arity,
        "performance_workers": performance_workers,
    });
    let workload_shape_fingerprint = hex_digest(&blake2s::hash(
        &serde_json::to_vec(&shape_material).map_err(|error| PrivacyError::InvalidConfig(error.to_string()))?,
    ));
    Ok(serde_json::json!({
        "record_type": "parent_job",
        "schema_version": 2,
        "workload_adapter": "privacy_pool_withdrawal",
        "workload_adapter_schema_version": ADAPTER_SCHEMA_VERSION,
        "adapter_config_digest": adapter_config_digest,
        "query_blake2s": query_blake2s,
        "program_identity": program_identity,
        "role": role,
        "workload_case_id": workload_case_id,
        "workload_case_blake2s": workload_case_blake2s,
        "ordered_child_claim_counts": ordered_child_claim_counts,
        "workload_shape_fingerprint": workload_shape_fingerprint,
        "configuration": {
            "arity": arity,
            "child_log_inv_rate": child_log_inv_rate,
            "parent_log_inv_rate": parent_log_inv_rate,
            "fixture_seed": fixture_seed,
            "performance_workers": performance_workers,
        },
        "child_shape": child_shapes[0],
        "child_shapes": child_shapes,
        "parent_shape": parent_shape,
        "aggregation_seconds": samples,
        "mean_service_seconds": samples.iter().sum::<f64>() / samples.len() as f64,
        "proof_bytes": adapter.serialize(&parent).len(),
        "verified": true,
        "performance_workers": performance_workers,
    }))
}

fn build_capacity_child(
    adapter: &PrivacyPoolWorkloadAdapter,
    spec: &serde_json::Value,
) -> Result<PrivacyPoolProof, PrivacyError> {
    let kind = spec
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PrivacyError::InvalidConfig("capacity child needs kind".into()))?;
    let output_rate = spec
        .get("output_log_inv_rate")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| PrivacyError::InvalidConfig("capacity child needs output_log_inv_rate".into()))?
        as usize;
    if !(1..=4).contains(&output_rate) {
        return Err(PrivacyError::InvalidConfig(
            "capacity child output rate must be in 1..=4".into(),
        ));
    }
    match kind {
        "leaf" => {
            let index = spec
                .get("fixture_index")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| PrivacyError::InvalidConfig("leaf child needs fixture_index".into()))?
                as usize;
            let mut proofs = adapter
                .prepare_leaves(&[index], output_rate)
                .map_err(PrivacyError::InvalidConfig)?;
            Ok(proofs.pop().expect("one requested leaf"))
        }
        "parent" => {
            let children = spec
                .get("children")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| PrivacyError::InvalidConfig("parent child needs children".into()))?;
            if !(2..=16).contains(&children.len()) {
                return Err(PrivacyError::InvalidConfig(
                    "capacity parent child arity must be in 2..=16".into(),
                ));
            }
            let proofs = children
                .iter()
                .map(|child| build_capacity_child(adapter, child))
                .collect::<Result<Vec<_>, _>>()?;
            PrivacyPoolProof::aggregate(&proofs, output_rate)
        }
        _ => Err(PrivacyError::InvalidConfig(
            "capacity child kind must be leaf or parent".into(),
        )),
    }
}

fn validate_capacity_manifest(
    case: &serde_json::Value,
    arity: usize,
    child_log_inv_rate: usize,
    parent_log_inv_rate: usize,
    fixture_seed: u64,
) -> Result<(), PrivacyError> {
    let config = case
        .get("configuration")
        .ok_or_else(|| PrivacyError::InvalidConfig("workload case has no configuration".into()))?;
    let has_exact_children = case
        .get("children")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|children| children.len() == arity);
    if let Some(expected_program) = case.get("program_identity").and_then(serde_json::Value::as_str)
        && expected_program != hex_digest(&crate::privacy_recursive::privacy_program_identity())
    {
        return Err(PrivacyError::InvalidConfig(
            "workload case program identity does not match this binary".into(),
        ));
    }
    if has_exact_children {
        let mut actual_indices = Vec::new();
        collect_capacity_fixture_indices(case.get("children").expect("exact children exist"), &mut actual_indices)?;
        let mut canonical_indices = actual_indices.clone();
        canonical_indices.sort_unstable();
        canonical_indices.dedup();
        if canonical_indices != actual_indices
            || case
                .get("expected_fixture_indices")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|values| {
                    values.iter().map(serde_json::Value::as_u64).collect::<Option<Vec<_>>>()
                        != Some(actual_indices.iter().map(|index| *index as u64).collect())
                })
        {
            return Err(PrivacyError::InvalidConfig(
                "exact workload case fixture indices must be sorted, unique, and explicit".into(),
            ));
        }
    }
    let indices_match = case
        .get("fixture_indices")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|indices| {
            indices.len() == arity
                && indices
                    .iter()
                    .enumerate()
                    .all(|(index, value)| value.as_u64() == Some(index as u64))
        });
    let matches = case.get("schema_version").and_then(serde_json::Value::as_u64) == Some(1)
        && case.get("workload_adapter").and_then(serde_json::Value::as_str) == Some("privacy_pool_withdrawal")
        && case.get("fixture_seed").and_then(serde_json::Value::as_u64) == Some(fixture_seed)
        && config.get("arity").and_then(serde_json::Value::as_u64) == Some(arity as u64)
        && config.get("child_log_inv_rate").and_then(serde_json::Value::as_u64) == Some(child_log_inv_rate as u64)
        && config.get("parent_log_inv_rate").and_then(serde_json::Value::as_u64) == Some(parent_log_inv_rate as u64)
        && (indices_match || has_exact_children);
    if matches {
        Ok(())
    } else {
        Err(PrivacyError::InvalidConfig(
            "workload case does not match capacity arguments".into(),
        ))
    }
}

fn collect_capacity_fixture_indices(value: &serde_json::Value, output: &mut Vec<usize>) -> Result<(), PrivacyError> {
    if let Some(values) = value.as_array() {
        for value in values {
            collect_capacity_fixture_indices(value, output)?;
        }
        return Ok(());
    }
    match value.get("kind").and_then(serde_json::Value::as_str) {
        Some("leaf") => output.push(
            value
                .get("fixture_index")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| PrivacyError::InvalidConfig("leaf child needs fixture_index".into()))?
                as usize,
        ),
        Some("parent") => collect_capacity_fixture_indices(
            value
                .get("children")
                .ok_or_else(|| PrivacyError::InvalidConfig("parent child needs children".into()))?,
            output,
        )?,
        _ => {
            return Err(PrivacyError::InvalidConfig(
                "capacity child kind must be leaf or parent".into(),
            ));
        }
    }
    Ok(())
}

fn execute_tree_plan(
    leaves: &[PrivacyPoolProof],
    plan: Option<&crate::query::TreePlan>,
) -> Result<PrivacyPoolProof, PrivacyError> {
    if leaves.len() == 1 {
        return Ok(leaves[0].clone());
    }
    let plan = plan.ok_or_else(|| PrivacyError::InvalidConfig("missing resolved tree plan".into()))?;
    let mut level = leaves.to_vec();
    for level_plan in &plan.levels {
        let mut next = Vec::with_capacity(level_plan.child_counts.len());
        let mut offset = 0;
        for &child_count in &level_plan.child_counts {
            let end = offset + child_count;
            if child_count == 0 || child_count > 16 || end > level.len() {
                return Err(PrivacyError::InvalidConfig(
                    "resolved tree plan has invalid grouping".into(),
                ));
            }
            if child_count == 1 {
                if level_plan.child_log_inv_rate != level_plan.parent_log_inv_rate {
                    return Err(PrivacyError::InvalidConfig("unary tree carry changed rate".into()));
                }
                next.push(level[offset].clone());
            } else {
                next.push(PrivacyPoolProof::aggregate(
                    &level[offset..end],
                    level_plan.parent_log_inv_rate,
                )?);
            }
            offset = end;
        }
        if offset != level.len() || next.len() != level_plan.output_count {
            return Err(PrivacyError::InvalidConfig(
                "resolved tree plan does not cover the level".into(),
            ));
        }
        level = next;
    }
    if level.len() != 1 {
        return Err(PrivacyError::InvalidConfig(
            "resolved tree plan did not produce one root".into(),
        ));
    }
    Ok(level.pop().expect("one root"))
}

/// Execute one resolved schema-2 candidate. Fixture generation and leaf proof
/// construction happen before the first block burst. Each later burst arrives
/// one block period after the previous burst. Root verification is deferred
/// until every root has crossed the serialization boundary.
pub fn run_query_case(
    query: &crate::query::BenchmarkQuery,
    query_blake2s: &str,
    inputs_per_root: usize,
    leaf_log_inv_rate: usize,
    root_log_inv_rate: usize,
    root_target: usize,
    block_period_seconds: f64,
    fixture_seed: u64,
    fixture_count: usize,
    leaf_cache_dir: Option<&Path>,
    fixed_plan: Option<&Path>,
) -> Result<serde_json::Value, PrivacyError> {
    if inputs_per_root == 0 || inputs_per_root > fixture_count || root_target == 0 {
        return Err(PrivacyError::InvalidConfig(
            "inputs_per_root must be within fixture_count and root_target must be positive".into(),
        ));
    }
    if !block_period_seconds.is_finite() || block_period_seconds <= 0.0 {
        return Err(PrivacyError::InvalidConfig(
            "block period must be finite and positive".into(),
        ));
    }
    let resolved_plan = if let Some(plan_path) = fixed_plan {
        let plan_text = std::fs::read_to_string(plan_path)
            .map_err(|error| PrivacyError::InvalidConfig(format!("cannot read fixed plan: {error}")))?;
        let plan: serde_json::Value = serde_json::from_str(&plan_text)
            .map_err(|error| PrivacyError::InvalidConfig(format!("invalid fixed plan: {error}")))?;
        if plan.get("query_blake2s").and_then(serde_json::Value::as_str) != Some(query_blake2s) {
            return Err(PrivacyError::InvalidConfig(
                "fixed plan query digest does not match the supplied query".into(),
            ));
        }
        let plan: crate::query::TreePlan = serde_json::from_value(plan)
            .map_err(|error| PrivacyError::InvalidConfig(format!("invalid resolved tree plan: {error}")))?;
        if plan.leaf_count != inputs_per_root
            || plan.leaf_log_inv_rate != leaf_log_inv_rate
            || plan.root_log_inv_rate != root_log_inv_rate
        {
            return Err(PrivacyError::InvalidConfig(
                "fixed plan does not match the resolved case".into(),
            ));
        }
        let mut level_input_count = inputs_per_root;
        let mut level_input_rate = leaf_log_inv_rate;
        for (index, level) in plan.levels.iter().enumerate() {
            let allowed_pairs = if level.output_count == 1 {
                &query.search.final_rate_pairs
            } else {
                &query.search.nonfinal_rate_pairs
            };
            if level.input_count != level_input_count
                || level.child_log_inv_rate != level_input_rate
                || level.output_count != level.child_counts.len()
                || level.child_counts.contains(&0)
                || level.child_counts.iter().any(|count| *count > 16)
                || level.child_counts.iter().sum::<usize>() != level.input_count
                || level
                    .child_counts
                    .iter()
                    .any(|count| *count == 1 && level.child_log_inv_rate != level.parent_log_inv_rate)
                || level
                    .child_counts
                    .iter()
                    .any(|count| *count > 1 && !query.search.arities.contains(count))
                || !allowed_pairs.iter().any(|pair| {
                    pair.child_log_inv_rate == level.child_log_inv_rate
                        && pair.parent_log_inv_rate == level.parent_log_inv_rate
                })
            {
                return Err(PrivacyError::InvalidConfig(format!(
                    "fixed plan level {index} does not cover its declared input"
                )));
            }
            level_input_count = level.output_count;
            level_input_rate = level.parent_log_inv_rate;
        }
        if level_input_count != 1
            || plan.levels.last().map(|level| level.parent_log_inv_rate) != Some(root_log_inv_rate)
        {
            return Err(PrivacyError::InvalidConfig(
                "fixed plan does not produce the requested root".into(),
            ));
        }
        Some(plan)
    } else if inputs_per_root > 1 {
        return Err(PrivacyError::InvalidConfig(
            "schema-2 cases require a resolved tree plan".into(),
        ));
    } else {
        None
    };
    lean_vm::init_prover_pool();
    let fixtures = fixtures(fixture_seed, inputs_per_root);
    let mut adapter = PrivacyPoolWorkloadAdapter::new(fixture_seed, fixture_count)?;
    if let Some(cache_dir) = leaf_cache_dir {
        adapter = adapter.with_cache_dir(cache_dir);
    }
    let preparation_started = std::time::Instant::now();
    let leaves = adapter
        .prepare_leaves(&(0..inputs_per_root).collect::<Vec<_>>(), leaf_log_inv_rate)
        .map_err(PrivacyError::InvalidConfig)?;
    let leaf_preparation_seconds = preparation_started.elapsed().as_secs_f64();
    let (leaf_cache_hits, leaf_cache_misses) = adapter.cache_stats();
    let mut expected = fixtures.iter().map(|item| item.withdrawal.public()).collect::<Vec<_>>();
    expected.sort_by_key(|public| public.existing_nullifier_hash);
    let expected_withdrawal_list_digest = hex_digest(&withdrawal_list_digest(&expected)?);
    eprintln!("LEANVM_BENCHMARK_PHASE=timed_proving");
    let campaign_started = std::time::Instant::now();
    let campaign_started_unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| PrivacyError::InvalidConfig(error.to_string()))?
        .as_secs_f64();
    let mut fixture_index_bytes = Vec::with_capacity(inputs_per_root * 8);
    for index in 0..inputs_per_root {
        fixture_index_bytes.extend_from_slice(&(index as u64).to_le_bytes());
    }
    let fixture_indices_digest = hex_digest(&blake2s::hash(&fixture_index_bytes));
    let mut pending_verification = Vec::with_capacity(root_target);
    let mut root_records = Vec::with_capacity(root_target);
    let mut previous_serialized_seconds = None;
    for root_index in 0..root_target {
        let burst_arrival_seconds = root_index as f64 * block_period_seconds;
        let scheduled = std::time::Duration::from_secs_f64(burst_arrival_seconds);
        if campaign_started.elapsed() < scheduled {
            std::thread::sleep(scheduled - campaign_started.elapsed());
        }
        let proving_started = std::time::Instant::now();
        let queue_delay_seconds = (campaign_started.elapsed().as_secs_f64() - burst_arrival_seconds).max(0.0);
        let root = execute_tree_plan(&leaves, resolved_plan.as_ref())?;
        let proving_seconds = proving_started.elapsed().as_secs_f64();
        let root_proof_ready_elapsed_seconds = campaign_started.elapsed().as_secs_f64();
        let serialization_started = std::time::Instant::now();
        let serialized = root.to_bytes();
        let serialization_seconds = serialization_started.elapsed().as_secs_f64();
        let campaign_elapsed_at_serialization_seconds = campaign_started.elapsed().as_secs_f64();
        let serialized_input_to_root_seconds =
            (campaign_elapsed_at_serialization_seconds - burst_arrival_seconds).max(0.0);
        let metadata = root.metadata()?;
        let root_interval_seconds =
            previous_serialized_seconds.map(|previous| campaign_elapsed_at_serialization_seconds - previous);
        previous_serialized_seconds = Some(campaign_elapsed_at_serialization_seconds);
        let record = serde_json::json!({
            "status": "pending_verification",
            "root_index": root_index,
            "inputs_per_root": inputs_per_root,
            "leaf_log_inv_rate": leaf_log_inv_rate,
            "requested_root_log_inv_rate": root_log_inv_rate,
            "actual_root_log_inv_rate": metadata.log_inv_rate,
            "completed_roots": 1,
            "completed_inputs": inputs_per_root,
            "burst_arrival_seconds": burst_arrival_seconds,
            "scheduled_burst_unix_seconds": campaign_started_unix_seconds + burst_arrival_seconds,
            "fixture_start_index": 0,
            "fixture_count": inputs_per_root,
            "fixture_indices_digest": fixture_indices_digest,
            "expected_withdrawal_count": expected.len(),
            "expected_withdrawal_list_digest": expected_withdrawal_list_digest.clone(),
            "queue_delay_seconds": queue_delay_seconds,
            "campaign_elapsed_at_serialization_seconds": campaign_elapsed_at_serialization_seconds,
            "root_proof_ready_unix_seconds": campaign_started_unix_seconds + root_proof_ready_elapsed_seconds,
            "root_serialized_unix_seconds": campaign_started_unix_seconds + campaign_elapsed_at_serialization_seconds,
            "root_interval_seconds": root_interval_seconds,
            "proving_and_verification_seconds": proving_seconds,
            "serialization_seconds": serialization_seconds,
            "serialized_input_to_root_seconds": serialized_input_to_root_seconds,
            "proof_bytes": serialized.len(),
            "serialized_root_proof_bytes": serialized.len(),
            "withdrawal_list_digest": hex_digest(&root.list_digest),
            "parse_ok": false,
            "in_memory_verify_ok": false,
            "roundtrip_verify_ok": false,
            "error": serde_json::Value::Null,
        });
        root_records.push(record);
        pending_verification.push((root, serialized));
    }
    eprintln!("LEANVM_BENCHMARK_PHASE=post_verification");
    for (record, (root, serialized)) in root_records.iter_mut().zip(&pending_verification) {
        let verification_started = std::time::Instant::now();
        let in_memory_result = root.verify_against(&expected);
        record["in_memory_verify_ok"] = serde_json::json!(in_memory_result.is_ok());
        let parsed = PrivacyPoolProof::from_bytes(serialized);
        record["parse_ok"] = serde_json::json!(parsed.is_some());
        let roundtrip_result = parsed
            .as_ref()
            .ok_or_else(|| PrivacyError::InvalidProof("serialized root proof did not parse".into()))
            .and_then(|parsed| parsed.verify_against(&expected));
        record["roundtrip_verify_ok"] = serde_json::json!(roundtrip_result.is_ok());
        record["native_verification_seconds"] = serde_json::json!(verification_started.elapsed().as_secs_f64());
        if let Err(error) = in_memory_result.and(roundtrip_result) {
            record["status"] = serde_json::json!("failed");
            record["error"] = serde_json::json!(error.to_string());
        } else {
            record["status"] = serde_json::json!("success");
        }
    }
    let completed_roots = root_records
        .iter()
        .filter(|record| record.get("status").and_then(serde_json::Value::as_str) == Some("success"))
        .count();
    let executed_plan = resolved_plan
        .as_ref()
        .map(|plan| serde_json::to_value(plan).expect("tree plan serializes"));
    Ok(serde_json::json!({
        "status": if completed_roots == root_target { "success" } else { "failed" },
        "inputs_per_root": inputs_per_root,
        "leaf_log_inv_rate": leaf_log_inv_rate,
        "requested_root_log_inv_rate": root_log_inv_rate,
        "root_target": root_target,
        "block_period_seconds": block_period_seconds,
        "program_identity": hex_digest(&crate::privacy_recursive::privacy_program_identity()),
        "leaf_preparation_seconds": leaf_preparation_seconds,
        "leaf_cache_hits": leaf_cache_hits,
        "leaf_cache_misses": leaf_cache_misses,
        "completed_roots": completed_roots,
        "completed_inputs": completed_roots * inputs_per_root,
        "roots": root_records,
        "executed_plan": executed_plan,
    }))
}

fn hex_digest(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_fixture_is_valid() {
        let value = fixture(7, 0);
        validate_withdrawal(&value.withdrawal).unwrap();
        assert_eq!(claim_id(&value.withdrawal), value.claim_id);
    }

    #[test]
    fn list_digest_binds_order_and_count() {
        let a = fixture(7, 0).claim_id;
        let b = fixture(7, 1).claim_id;
        let ordered = if a < b { vec![a, b] } else { vec![b, a] };
        assert_ne!(list_digest(&ordered).unwrap(), list_digest(&ordered[..1]).unwrap());
        assert_ne!(
            list_digest(&ordered).unwrap(),
            list_digest(&[ordered[1], ordered[0]]).unwrap()
        );
    }

    #[test]
    fn withdrawal_list_digest_requires_nullifier_order_without_duplicates() {
        let mut publics = [fixture(7, 0).withdrawal.public(), fixture(7, 1).withdrawal.public()];
        publics.sort_by_key(|public| public.existing_nullifier_hash);
        assert!(withdrawal_list_digest(&publics).is_ok());
        assert!(withdrawal_list_digest(&[publics[1], publics[0]]).is_err());
        assert!(withdrawal_list_digest(&[publics[0], publics[0]]).is_err());
    }

    #[test]
    fn u129_encoding_preserves_the_high_bit() {
        assert_eq!(u129_bytes(U129 { low: 0, high: false }), [0; 17]);
        let max = u129_bytes(U129 {
            low: u128::MAX,
            high: true,
        });
        assert_eq!(&max[..16], &[0xff; 16]);
        assert_eq!(max[16], 1);
    }

    #[test]
    fn u128_addition_retains_carry() {
        assert_eq!(
            U128(u128::MAX).add_u129(U128(0)),
            U129 {
                low: u128::MAX,
                high: false
            }
        );
        assert_eq!(U128(u128::MAX).add_u129(U128(1)), U129 { low: 0, high: true });
        assert_eq!(
            U128(u128::MAX).add_u129(U128(u128::MAX)),
            U129 {
                low: u128::MAX - 1,
                high: true
            }
        );
    }

    #[test]
    fn standard_blake2s_vectors_cover_short_and_multiblock_inputs() {
        let x = core::array::from_fn(|i| i as u8);
        let y = core::array::from_fn(|i| 0x20u8 + i as u8);
        let z = core::array::from_fn(|i| 0x40u8 + i as u8);
        assert_eq!(
            h1(&x),
            bytes("05825607d7fdf2d82ef4c3c8c2aea961ad98d60edff7d018983e21204c0d93d1")
        );
        assert_eq!(
            h2(&x, &y),
            bytes("56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e")
        );
        assert_eq!(
            h3(&x, &y, &z),
            bytes("8479731aeda57bd37eadb51a507e307f3bd95e69dbca94f3bc21726066ad6dfd")
        );
        let x = bytes("ea72cae1ee5d4f1ed66ae54073c2f0139d9be829f8baece0712e8cad00f1a75d");
        let y = bytes("43456cb7d0493d58365b2591456d1041c7fa88d31763d303930e7f17533fb22c");
        let z = bytes("ceaaf32f1db5a4b79c0616213093e5650781adb17afacfa0559fc4ca33bfee89");
        assert_eq!(
            h1(&x),
            bytes("31cc8cf7d3e43682e0ccd930420598c2394d9d89fe0ce8587b0a453654180717")
        );
        assert_eq!(
            h2(&x, &y),
            bytes("88af536f71a5fd7bebd79d16f937355a45a6f622654e4fe8065d343c68f547a1")
        );
        assert_eq!(
            h3(&x, &y, &z),
            bytes("ceba473ffb11e8a5f0a0f9259361acc49f9291a4c439c916b19e324af2a7e8ca")
        );
    }

    #[test]
    fn canonical_claim_and_list_vectors_match_the_plan() {
        let public = WithdrawalPublic {
            withdrawn_value: 7,
            state_root: core::array::from_fn(|index| index as u8),
            state_tree_depth: 32,
            asp_root: core::array::from_fn(|index| 0x20u8 + index as u8),
            asp_tree_depth: 32,
            context: core::array::from_fn(|index| 0x40u8 + index as u8),
            new_commitment_hash: core::array::from_fn(|index| 0x60u8 + index as u8),
            existing_nullifier_hash: core::array::from_fn(|index| 0x80u8 + index as u8),
        };
        let id = withdrawal_claim_id(&public);
        assert_eq!(
            id,
            bytes("4abcbebf932f028682a43981d2332321b8a4f83af7f5cd2ee4a2d4c0683bff38")
        );
        assert_eq!(
            list_digest(&[id]).unwrap(),
            bytes("817ad1e37fc33daf97f1098f0daa700973ba1d9757ce6c9fde964ef7968d8b88")
        );
        let mut padded_claim = Vec::from(label_tag_bytes(b"leanvm-b/pp-withdrawal-claim/v1"));
        padded_claim.extend_from_slice(&encode_withdrawal_public(&public));
        padded_claim.resize(320, 0);
        assert_eq!(
            blake2s::hash(&padded_claim),
            bytes("87b681581c0e17d41ab92a91b52a527130be4d1882dcc8c283a776a0159b388a")
        );
        assert_ne!(blake2s::hash(&padded_claim), id);
    }

    #[test]
    fn public_withdrawal_encoding_is_fixed_width_and_canonical() {
        let public = fixture(7, 0).withdrawal.public();
        let encoded = encode_withdrawal_public(&public);
        assert_eq!(encoded.len(), 256);
        assert_eq!(decode_withdrawal_public(&encoded).unwrap(), public);
        let mut noncanonical_amount = encoded;
        noncanonical_amount[16] = 1;
        assert!(decode_withdrawal_public(&noncanonical_amount).is_err());
        let mut noncanonical_depth = encoded;
        noncanonical_depth[65] = 1;
        assert!(decode_withdrawal_public(&noncanonical_depth).is_err());
    }

    #[test]
    fn every_public_field_changes_the_claim_id() {
        let public = fixture(7, 0).withdrawal.public();
        let original = withdrawal_claim_id(&public);
        let mut variants = Vec::new();
        let mut changed = public;
        changed.withdrawn_value ^= 1;
        variants.push(changed);
        let mut changed = public;
        changed.state_root[0] ^= 1;
        variants.push(changed);
        let mut changed = public;
        changed.state_tree_depth ^= 1;
        variants.push(changed);
        let mut changed = public;
        changed.asp_root[0] ^= 1;
        variants.push(changed);
        let mut changed = public;
        changed.asp_tree_depth ^= 1;
        variants.push(changed);
        let mut changed = public;
        changed.context[0] ^= 1;
        variants.push(changed);
        let mut changed = public;
        changed.new_commitment_hash[0] ^= 1;
        variants.push(changed);
        let mut changed = public;
        changed.existing_nullifier_hash[0] ^= 1;
        variants.push(changed);
        assert!(variants.iter().all(|variant| withdrawal_claim_id(variant) != original));
    }

    fn bytes(value: &str) -> [u8; 32] {
        core::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
    }

    fn label_tag_bytes(label: &[u8]) -> [u8; 32] {
        let mut tag = [0; 32];
        tag[..label.len()].copy_from_slice(label);
        tag
    }

    fn with_amounts(mut withdrawal: Withdrawal, withdrawn: u128, remaining: u128) -> Withdrawal {
        withdrawal.withdrawn = U128(withdrawn);
        withdrawal.remaining = U128(remaining);
        withdrawal.existing_value = U128(withdrawn).add_u129(U128(remaining));
        withdrawal.state_path.leaf = h3(
            &amount129_32(withdrawal.existing_value),
            &withdrawal.label,
            &h2(&withdrawal.old_nullifier, &withdrawal.existing_secret),
        );
        withdrawal.state_path.root = path_root(&withdrawal.state_path).unwrap();
        withdrawal.state_root = withdrawal.state_path.root;
        withdrawal.new_commitment_hash = h3(
            &amount32(withdrawal.remaining),
            &withdrawal.label,
            &h2(&withdrawal.new_nullifier, &withdrawal.new_secret),
        );
        withdrawal
    }

    #[test]
    fn balance_boundaries_and_underflow_encoding_are_checked() {
        let original = fixture(7, 0).withdrawal;
        for (withdrawn, remaining, high) in [
            (0, 9, false),
            (9, 0, false),
            (u128::MAX, 0, false),
            (u128::MAX, u128::MAX, true),
        ] {
            let value = with_amounts(original.clone(), withdrawn, remaining);
            assert_eq!(value.existing_value.high, high);
            validate_withdrawal(&value).unwrap();
        }
        let mut underflow = with_amounts(original, 9, 3);
        underflow.existing_value = U129 { low: 6, high: false };
        assert!(validate_withdrawal(&underflow).is_err());
    }

    #[test]
    fn invalid_existing_value_is_rejected() {
        let mut value = fixture(7, 0).withdrawal;
        value.existing_value.high = !value.existing_value.high;
        assert!(validate_withdrawal(&value).is_err());
    }

    #[test]
    fn generated_fixture_uses_two_nonzero_depth_32_paths() {
        let value = fixture(7, 0).withdrawal;
        assert_eq!(fixture(7, 0), fixture(7, 0));
        assert_ne!(fixture(7, 0), fixture(7, 1));
        assert_eq!(value.state_path.siblings.len(), TREE_DEPTH);
        assert_eq!(value.asp_path.siblings.len(), TREE_DEPTH);
        assert!(
            value
                .state_path
                .siblings
                .iter()
                .chain(&value.asp_path.siblings)
                .all(|sibling| *sibling != [0; 32])
        );
    }

    #[test]
    fn leaf_cache_key_binds_program_fixture_and_rate() {
        let root = Path::new("cache");
        let base = leaf_cache_path(root, "program-a", 7, 102, 3, 1);
        assert_ne!(base, leaf_cache_path(root, "program-b", 7, 102, 3, 1));
        assert_ne!(base, leaf_cache_path(root, "program-a", 8, 102, 3, 1));
        assert_ne!(base, leaf_cache_path(root, "program-a", 7, 103, 3, 1));
        assert_ne!(base, leaf_cache_path(root, "program-a", 7, 102, 4, 1));
        assert_ne!(base, leaf_cache_path(root, "program-a", 7, 102, 3, 2));
    }

    #[test]
    fn merkle_membership_binds_leaf_sibling_index_root_and_depth() {
        let original = fixture(7, 0).withdrawal;
        let mut changed = original.clone();
        changed.state_path.leaf[0] ^= 1;
        assert!(validate_withdrawal(&changed).is_err());
        let mut changed = original.clone();
        changed.state_path.siblings[0][0] ^= 1;
        assert!(validate_withdrawal(&changed).is_err());
        let mut changed = original.clone();
        changed.state_path.index ^= 1;
        assert!(validate_withdrawal(&changed).is_err());
        let mut changed = original.clone();
        changed.state_root[0] ^= 1;
        assert!(validate_withdrawal(&changed).is_err());
        let mut changed = original.clone();
        changed.state_tree_depth = 31;
        assert!(validate_withdrawal(&changed).is_err());
        let mut changed = original;
        changed.asp_tree_depth = 33;
        assert!(validate_withdrawal(&changed).is_err());
    }

    #[test]
    fn merkle_direction_is_little_endian_at_every_level() {
        let leaf = [3; 32];
        for level in 0..TREE_DEPTH {
            let sibling = tagged(b"direction-test", &[&(level as u64).to_le_bytes()]);
            let mut siblings = vec![[0; 32]; TREE_DEPTH];
            siblings[level] = sibling;
            for bit in [0, 1] {
                let expected = if bit == 0 {
                    h2(&leaf, &sibling)
                } else {
                    h2(&sibling, &leaf)
                };
                let path = MerklePath {
                    leaf,
                    siblings: siblings.clone(),
                    index: bit << level,
                    root: expected,
                };
                assert_eq!(path_root(&path).unwrap(), expected);
            }
        }
    }

    #[test]
    fn private_withdrawal_inputs_and_new_nullifier_work_are_checked() {
        let original = fixture(7, 0).withdrawal;
        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.label[0] ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.existing_secret[0] ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.new_secret[0] ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.new_nullifier[0] ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.remaining.0 ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.asp_path.siblings[0][0] ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.asp_path.index ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.asp_root[0] ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.new_nullifier_hash[0] ^= 1;
        variants.push(changed);
        assert!(variants.iter().all(|value| validate_withdrawal(value).is_err()));

        let mut equal = original;
        equal.new_nullifier = equal.old_nullifier;
        assert!(validate_withdrawal(&equal).is_err());
    }

    #[test]
    fn zero_siblings_propagate_the_running_merkle_node() {
        let leaf = [9u8; 32];
        let path = MerklePath {
            leaf,
            siblings: vec![[0; 32]; TREE_DEPTH],
            index: u32::MAX,
            root: leaf,
        };
        assert_eq!(path_root(&path).unwrap(), leaf);
    }

    #[test]
    #[ignore = "builds a zero-sibling guest proof"]
    fn zero_sibling_guest_leaf_proves_and_verifies() {
        let mut value = fixture(7, 0).withdrawal;
        value.state_path.siblings = vec![[0; 32]; TREE_DEPTH];
        value.state_path.root = value.state_path.leaf;
        value.state_root = value.state_path.root;
        value.asp_path.siblings = vec![[0; 32]; TREE_DEPTH];
        value.asp_path.root = value.asp_path.leaf;
        value.asp_root = value.asp_path.root;
        assert_eq!(
            value.state_path.leaf,
            h3(
                &amount129_32(value.existing_value),
                &value.label,
                &h2(&value.old_nullifier, &value.existing_secret)
            )
        );
        assert_eq!(path_root(&value.state_path).unwrap(), value.state_path.root);
        assert_eq!(path_root(&value.asp_path).unwrap(), value.asp_path.root);
        PrivacyPoolProof::prove_leaf(&value, 1).unwrap().verify().unwrap();
    }

    #[test]
    fn public_claim_fields_change_the_claim_id() {
        let mut value = fixture(7, 0).withdrawal;
        let original = claim_id(&value);
        value.context[0] ^= 1;
        assert_ne!(claim_id(&value), original);
    }

    #[test]
    fn parent_requires_at_least_two_children() {
        let error = PrivacyPoolProof::aggregate(&[], 1).unwrap_err();
        assert!(matches!(error, PrivacyError::InvalidList(message) if message.contains("2..=16")));
    }

    #[test]
    fn capacity_manifest_rejects_changed_fixture_order() {
        let manifest = serde_json::json!({
            "schema_version": 1,
            "workload_adapter": "privacy_pool_withdrawal",
            "fixture_seed": 7,
            "fixture_indices": [1, 0],
            "configuration": {
                "arity": 2,
                "child_log_inv_rate": 1,
                "parent_log_inv_rate": 1
            }
        });
        assert!(validate_capacity_manifest(&manifest, 2, 1, 1, 7).is_err());
    }

    #[test]
    #[ignore = "builds and verifies a real privacy-pool VM proof"]
    fn recursive_proof_round_trip() {
        lean_vm::init_prover_pool();
        let a = fixture(7, 0).withdrawal;
        let b = fixture(7, 1).withdrawal;
        let leaves = [
            PrivacyPoolProof::prove_leaf(&a, 4).unwrap(),
            PrivacyPoolProof::prove_leaf(&b, 4).unwrap(),
        ];
        let parent = PrivacyPoolProof::aggregate(&leaves, 4).unwrap();
        parent.verify().unwrap();
    }
}
