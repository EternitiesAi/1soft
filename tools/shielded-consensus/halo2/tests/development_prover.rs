#![cfg(feature = "dev-prover")]

use std::{
    io::Write,
    process::{Command, Stdio},
};

use shielded_consensus_halo2::{
    encoding::{ProverRequestV1, TransactionV1},
    fixture::SyntheticFixture,
    profile::load_artifacts,
    verifier::PinnedVerifier,
};

#[test]
fn prover_request_is_exact_and_development_binary_emits_only_transaction() {
    let fixture = SyntheticFixture::one_note();
    let request = ProverRequestV1 {
        genesis_sha256: [0x31; 32],
        deployment_id: [0x42; 32],
        public_inputs: fixture.assignment.public.to_field_bytes(),
        witness: fixture.witness_wire(),
    };
    let encoded = request.encode().expect("encode prover request");
    assert_eq!(ProverRequestV1::decode(&encoded).unwrap(), request);
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(ProverRequestV1::decode(&trailing).is_err());

    let mut child = Command::new(env!("CARGO_BIN_EXE_shielded-development-prover"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn development prover");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&encoded)
        .expect("write request");
    let output = child.wait_with_output().expect("wait for prover");
    assert!(
        output.status.success(),
        "prover failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "successful prover must be quiet");

    let profile_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../profile");
    let (descriptor, _) = load_artifacts(&profile_dir).expect("load tracked profile");
    let transaction = TransactionV1::decode(
        &output.stdout,
        descriptor.exact_proof_length as usize,
        shielded_consensus_halo2::constants::MAX_TRANSACTION_BYTES,
    )
    .expect("decode prover transaction");
    assert_eq!(transaction.genesis_sha256, request.genesis_sha256);
    assert_eq!(transaction.deployment_id, request.deployment_id);
    assert_eq!(transaction.public_inputs, request.public_inputs);
    PinnedVerifier::new()
        .expect("construct verifier")
        .verify_public_bytes(&transaction.public_inputs, &transaction.proof)
        .expect("verify prover output");
}
