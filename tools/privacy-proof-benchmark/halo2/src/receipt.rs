use serde::Serialize;

#[derive(Clone, Debug)]
pub struct BenchmarkConfig {
    pub commit: String,
    pub tree: String,
    pub circuit_digest: String,
    pub iterations: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Receipt {
    pub format: u64,
    pub status: &'static str,
    pub actual_backend_run: bool,
    pub backend: BackendReceipt,
    pub circuit: CircuitReceipt,
    pub source: SourceReceipt,
    pub parameters: ParameterReceipt,
    pub artifacts: ArtifactReceipt,
    pub metrics: MetricReceipt,
    pub cases: Vec<CaseReceipt>,
    pub claims: ClaimReceipt,
    pub unassessed: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BackendReceipt {
    pub id: &'static str,
    pub halo2_proofs: &'static str,
    pub halo2_gadgets: &'static str,
    pub halo2_poseidon: &'static str,
    pub pasta_curves: &'static str,
    pub field: &'static str,
    pub commitment_curve: &'static str,
    pub proof_system: &'static str,
    pub hash: &'static str,
    pub transcript: &'static str,
    pub license: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct CircuitReceipt {
    pub id: &'static str,
    pub source_digest: String,
    pub k: u32,
    pub domain_rows: u64,
    pub estimated_proof_bytes: usize,
    pub depth: usize,
    pub inputs: usize,
    pub outputs: usize,
    pub value_bits: usize,
    pub public_inputs: Vec<&'static str>,
    pub private_inputs_retained: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceReceipt {
    pub commit: String,
    pub tree: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ParameterReceipt {
    pub kind: &'static str,
    pub ceremony: bool,
    pub reusable: bool,
    pub production: bool,
    pub parameters_sha256: String,
    pub parameters_bytes: usize,
    pub verifying_key_binding: &'static str,
    pub verifying_key_sha256: String,
    pub verifying_key_bytes: usize,
    pub proving_key_serialization_assessed: bool,
    pub proving_key_serialization_reason: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactReceipt {
    pub proof_sha256: String,
    pub proof_bytes: usize,
    pub public_instances_sha256: String,
    pub public_instances_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct MetricReceipt {
    pub parameters_ns: u64,
    pub keygen_vk_ns: u64,
    pub keygen_pk_ns: u64,
    pub iterations: usize,
    pub prove_ns: Vec<u64>,
    pub verify_ns: Vec<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CaseReceipt {
    pub id: &'static str,
    pub expected: &'static str,
    pub observed: &'static str,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ClaimReceipt {
    pub production_privacy: bool,
    pub consensus_integrated: bool,
    pub network_anonymity: bool,
    pub production_custody: bool,
    pub real_funds: bool,
    pub independent_review: bool,
}
