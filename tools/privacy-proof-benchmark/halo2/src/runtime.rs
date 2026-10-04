use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::{CircuitCost, MockProver},
    pasta::{Eq, EqAffine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Instance, ProvingKey, Selector, SingleVerifier, VerifyingKey,
    },
    poly::{commitment::Params, Rotation},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::rng;
use sha2::{Digest, Sha256};

use crate::{
    circuit::{NoteCircuit, CIRCUIT_ID, DEPTH, K, PUBLIC_INPUTS},
    fixture::{Assignment, F},
    receipt::{
        ArtifactReceipt, BackendReceipt, BenchmarkConfig, CaseReceipt, CircuitReceipt,
        ClaimReceipt, MetricReceipt, ParameterReceipt, Receipt, SourceReceipt,
    },
};

const UNASSESSED: [&str; 7] = [
    "global nullifier uniqueness and consensus ordering",
    "production parameter and verifying-key governance",
    "independent cryptographic review",
    "wallet scanning and recovery",
    "network anonymity and metadata resistance",
    "production custody and side-channel resistance",
    "public-network and real-funds safety",
];

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn elapsed_ns(started: Instant) -> Result<u64> {
    let value = u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| anyhow!("measured duration overflow"))?;
    if value == 0 {
        bail!("nonpositive measured duration");
    }
    Ok(value)
}

fn exact_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl BenchmarkConfig {
    pub fn validate(&self) -> Result<()> {
        if !exact_hex(&self.commit, 40)
            || !exact_hex(&self.tree, 40)
            || !exact_hex(&self.circuit_digest, 64)
        {
            bail!("source identities must be exact lowercase hexadecimal IDs");
        }
        if !(1..=10).contains(&self.iterations) {
            bail!("iterations must be between 1 and 10");
        }
        Ok(())
    }
}

fn create_proof_bytes(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    circuit: NoteCircuit,
    instances: &[F],
) -> Result<Vec<u8>> {
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(
        params,
        pk,
        &[circuit],
        &[&[instances]],
        rng(),
        &mut transcript,
    )
    .map_err(|_| anyhow!("Halo2 proof generation failed"))?;
    Ok(transcript.finalize())
}

fn verify_proof_bytes(
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    proof: &[u8],
    instances: &[F],
) -> Result<()> {
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
    verify_proof(params, vk, strategy, &[&[instances]], &mut transcript)
        .map_err(|_| anyhow!("Halo2 proof verification failed"))
}

#[derive(Clone, Debug, Default)]
struct WrongKeyCircuit;

#[derive(Clone, Debug)]
struct WrongKeyConfig {
    value: Column<Advice>,
    instance: Column<Instance>,
    q_boolean: Selector,
}

impl Circuit<F> for WrongKeyCircuit {
    type Config = WrongKeyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let value = meta.advice_column();
        let instance = meta.instance_column();
        meta.enable_equality(value);
        meta.enable_equality(instance);
        let q_boolean = meta.selector();
        meta.create_gate("wrong-key boolean circuit", |meta| {
            let q = meta.query_selector(q_boolean);
            let value = meta.query_advice(value, Rotation::cur());
            vec![q * value.clone() * (halo2_proofs::plonk::Expression::Constant(F::ONE) - value)]
        });
        WrongKeyConfig {
            value,
            instance,
            q_boolean,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> std::result::Result<(), Error> {
        let cell = layouter.assign_region(
            || "wrong-key circuit",
            |mut region| {
                config.q_boolean.enable(&mut region, 0)?;
                region.assign_advice(
                    || "zero",
                    config.value,
                    0,
                    || Value::known(F::ZERO),
                )
            },
        )?;
        layouter.constrain_instance(cell.cell(), config.instance, 0)
    }
}

fn require_rejection(id: &'static str, rejected: bool, cases: &mut Vec<CaseReceipt>) -> Result<()> {
    if !rejected {
        bail!("adversarial case accepted: {id}");
    }
    cases.push(CaseReceipt {
        id,
        expected: "reject",
        observed: "reject",
    });
    Ok(())
}

fn invalid_witness_rejected(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    assignment: Assignment,
) -> Result<bool> {
    let instances = assignment.public_inputs();
    let circuit = NoteCircuit::new(assignment);
    let mock = MockProver::run(K, &circuit, vec![instances.clone()])
        .map_err(|_| anyhow!("invalid witness synthesis failed"))?;
    if mock.verify().is_ok() {
        return Ok(false);
    }
    match create_proof_bytes(params, pk, circuit, &instances) {
        Err(_) => Ok(true),
        Ok(proof) => Ok(verify_proof_bytes(params, vk, &proof, &instances).is_err()),
    }
}

pub fn run_benchmark(config: BenchmarkConfig) -> Result<Receipt> {
    config.validate()?;
    let fixture = Assignment::synthetic();
    let public_instances = fixture.public_inputs();
    let public_bytes = fixture.canonical_public_bytes();
    let circuit = NoteCircuit::new(fixture.clone());

    let mock = MockProver::run(K, &circuit, vec![public_instances.clone()])
        .context("valid Halo2 circuit synthesis failed")?;
    if mock.verify().is_err() {
        bail!("valid synthetic witness did not satisfy the Halo2 circuit");
    }

    let parameters_started = Instant::now();
    let params: Params<EqAffine> = Params::new(K);
    let parameters_ns = elapsed_ns(parameters_started)?;
    let mut parameter_bytes = Vec::new();
    params
        .write(&mut parameter_bytes)
        .context("Halo2 parameter serialization failed")?;
    if parameter_bytes.is_empty() {
        bail!("empty Halo2 parameter serialization");
    }

    let vk_started = Instant::now();
    let vk = keygen_vk(&params, &circuit).context("Halo2 verifying-key generation failed")?;
    let keygen_vk_ns = elapsed_ns(vk_started)?;
    let pk_started = Instant::now();
    let pk = keygen_pk(&params, vk.clone(), &circuit)
        .context("Halo2 proving-key generation failed")?;
    let keygen_pk_ns = elapsed_ns(pk_started)?;

    let vk_bytes = format!("{:?}", vk.pinned()).into_bytes();
    if vk_bytes.is_empty() {
        bail!("empty pinned verifying-key representation");
    }

    let mut prove_ns = Vec::with_capacity(config.iterations);
    let mut verify_ns = Vec::with_capacity(config.iterations);
    let mut proof = Vec::new();
    for _ in 0..config.iterations {
        let prove_started = Instant::now();
        proof = create_proof_bytes(&params, &pk, circuit.clone(), &public_instances)?;
        prove_ns.push(elapsed_ns(prove_started)?);
        let verify_started = Instant::now();
        verify_proof_bytes(&params, &vk, &proof, &public_instances)?;
        verify_ns.push(elapsed_ns(verify_started)?);
    }
    if proof.is_empty() {
        bail!("empty Halo2 proof");
    }

    let estimated_proof_bytes: usize =
        CircuitCost::<Eq, NoteCircuit>::measure(K, &circuit)
            .proof_size(1)
            .into();
    if estimated_proof_bytes == 0 {
        bail!("Halo2 proof-size model returned zero");
    }

    let mut cases = vec![CaseReceipt {
        id: "valid-proof",
        expected: "accept",
        observed: "accept",
    }];

    let mut mutated = proof.clone();
    let mutation_index = mutated.len() / 2;
    mutated[mutation_index] ^= 1;
    require_rejection(
        "mutated-proof",
        verify_proof_bytes(&params, &vk, &mutated, &public_instances).is_err(),
        &mut cases,
    )?;

    let mut changed_public = public_instances.clone();
    changed_public[3] += F::ONE;
    require_rejection(
        "changed-public-input",
        verify_proof_bytes(&params, &vk, &proof, &changed_public).is_err(),
        &mut cases,
    )?;

    let wrong_vk =
        keygen_vk(&params, &WrongKeyCircuit).context("wrong-key fixture generation failed")?;
    require_rejection(
        "wrong-verifying-key",
        verify_proof_bytes(&params, &wrong_vk, &proof, &public_instances).is_err(),
        &mut cases,
    )?;

    for (id, assignment) in [
        ("invalid-membership", fixture.invalid_membership()),
        ("invalid-nullifier", fixture.invalid_nullifier()),
        (
            "invalid-output-commitment",
            fixture.invalid_output_commitment(),
        ),
        (
            "invalid-fee-conservation",
            fixture.invalid_fee_conservation(),
        ),
        ("out-of-range-value", fixture.out_of_range_value()),
        (
            "changed-authorization-digest",
            fixture.changed_authorization(),
        ),
    ] {
        require_rejection(
            id,
            invalid_witness_rejected(&params, &pk, &vk, assignment)?,
            &mut cases,
        )?;
    }

    if cases.len() != 10 {
        bail!("incomplete Halo2 adversarial case inventory");
    }

    Ok(Receipt {
        format: 1,
        status: "passed",
        actual_backend_run: true,
        backend: BackendReceipt {
            id: "zcash-halo2-pasta-ipa",
            halo2_proofs: "0.4.0",
            halo2_gadgets: "0.6.0",
            halo2_poseidon: "0.2.0",
            pasta_curves: "0.6.0",
            field: "Pallas base field",
            commitment_curve: "Vesta",
            proof_system: "Halo2 PLONKish IPA",
            hash: "Poseidon P128Pow5T3",
            transcript: "Blake2b",
            license: "MIT OR Apache-2.0",
        },
        circuit: CircuitReceipt {
            id: CIRCUIT_ID,
            source_digest: config.circuit_digest,
            k: K,
            domain_rows: 1u64 << K,
            estimated_proof_bytes,
            depth: DEPTH,
            inputs: 1,
            outputs: 2,
            value_bits: 64,
            public_inputs: PUBLIC_INPUTS.to_vec(),
            private_inputs_retained: false,
        },
        source: SourceReceipt {
            commit: config.commit,
            tree: config.tree,
        },
        parameters: ParameterReceipt {
            kind: "deterministic-public-halo2-ipa-parameters",
            ceremony: false,
            reusable: true,
            production: false,
            parameters_sha256: sha256(&parameter_bytes),
            parameters_bytes: parameter_bytes.len(),
            verifying_key_binding: "halo2-proofs-0.4.0-pinned-debug-nonportable",
            verifying_key_sha256: sha256(&vk_bytes),
            verifying_key_bytes: vk_bytes.len(),
            proving_key_serialization_assessed: false,
            proving_key_serialization_reason:
                "halo2_proofs 0.4.0 public API exposes no proving-key serialization",
        },
        artifacts: ArtifactReceipt {
            proof_sha256: sha256(&proof),
            proof_bytes: proof.len(),
            public_instances_sha256: sha256(&public_bytes),
            public_instances_bytes: public_bytes.len(),
        },
        metrics: MetricReceipt {
            parameters_ns,
            keygen_vk_ns,
            keygen_pk_ns,
            iterations: config.iterations,
            prove_ns,
            verify_ns,
        },
        cases,
        claims: ClaimReceipt::default(),
        unassessed: UNASSESSED.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_identity_validation_is_closed() {
        let base = BenchmarkConfig {
            commit: "a".repeat(40),
            tree: "b".repeat(40),
            circuit_digest: "c".repeat(64),
            iterations: 1,
        };
        assert!(base.validate().is_ok());
        for value in [
            BenchmarkConfig {
                commit: "A".repeat(40),
                ..base.clone()
            },
            BenchmarkConfig {
                tree: "b".repeat(39),
                ..base.clone()
            },
            BenchmarkConfig {
                circuit_digest: "z".repeat(64),
                ..base.clone()
            },
            BenchmarkConfig {
                iterations: 0,
                ..base.clone()
            },
        ] {
            assert!(value.validate().is_err());
        }
    }
}
