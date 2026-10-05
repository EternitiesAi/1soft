#![cfg(feature = "prover")]
#[allow(dead_code)]
#[path = "../examples/payment-request-fixture.rs"]
mod synthetic;
use ff::PrimeField;
use owner_treasury_lab::{prover_request as request, wire, F};
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn canonical_request_refuses_altered_public_witness_identity_and_lengths() {
    let bootstrap = [19; 32];
    let a = synthetic::assignment(bootstrap);
    let raw = request::encode(&a, bootstrap).unwrap();
    assert_eq!(raw.len(), request::BYTES);
    let decoded = request::decode(&raw).unwrap();
    assert_eq!(decoded.public, a.public);
    assert_eq!(
        request::witness_fields(&decoded.witness),
        request::witness_fields(&a.witness)
    );
    for i in 0..(30 + request::WITNESS_COUNT) {
        let mut changed = raw.clone();
        changed[136 + i * 32] ^= 1;
        assert!(request::decode(&changed).is_err(), "slot {i}");
    }
    for i in [0, 8, 40, 72, 104] {
        let mut changed = raw.clone();
        changed[i] ^= 1;
        assert!(request::decode(&changed).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(request::decode(&trailing).is_err());
    assert!(request::decode(&raw[..raw.len() - 1]).is_err());
    let mut noncanonical = raw.clone();
    noncanonical[136..168].fill(255);
    assert!(request::decode(&noncanonical).is_err());
    let mut integer = raw.clone();
    integer[136 + 30 * 32..136 + 31 * 32]
        .copy_from_slice(F::from_u128(1u128 << 64).to_repr().as_ref());
    assert!(request::decode(&integer).is_err());
}
fn run(raw: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_owner-payment-prover"))
        .env_clear()
        .env("RAYON_NUM_THREADS", "2")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(raw).unwrap();
    child.wait_with_output().unwrap()
}
#[test]
fn actual_binary_verifies_exact_statement_randomizes_and_refuses_without_echo() {
    let bootstrap = [19; 32];
    let a = synthetic::assignment(bootstrap);
    let raw = request::encode(&a, bootstrap).unwrap();
    let first = run(&raw);
    let second = run(&raw);
    assert!(first.status.success() && second.status.success());
    assert!(first.stderr.is_empty() && second.stderr.is_empty());
    assert_ne!(first.stdout, second.stdout);
    let profile = owner_treasury_lab::proof::Profile::new().unwrap();
    for output in [&first, &second] {
        assert_eq!(output.stdout.len(), wire::BYTES);
        let (public, proof) = wire::decode(&output.stdout).unwrap();
        assert_eq!(public, a.public);
        profile.verify(&public, proof).unwrap();
    }
    let mut bad = raw.clone();
    bad[136 + 30 * 32] ^= 1;
    let failure = run(&bad);
    assert!(!failure.status.success());
    assert!(failure.stdout.is_empty());
    assert_eq!(failure.stderr, b"P7 development prover refused\n");
}
