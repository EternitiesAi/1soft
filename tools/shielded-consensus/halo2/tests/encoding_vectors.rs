use std::fs;
use std::path::PathBuf;

use ff::PrimeField;
use serde_json::Value;
use shielded_consensus_halo2::{
    constants::{PUBLIC_INPUT_COUNT, TRANSACTION_PREFIX_BYTES, WITNESS_BYTES},
    encoding::{
        DeploymentBindingV1, KatV1, ProfileDescriptorV1, TransactionV1, WitnessV1,
        WorkerRequestV1, WorkerResponseV1,
    },
    field::{decode_field, encode_field, h2f, F},
};

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-vectors/crypto-v1.json");
    serde_json::from_slice(&fs::read(path).expect("read vectors")).expect("parse vectors")
}

#[test]
fn field_codec_and_h2f_match_frozen_vectors() {
    let vectors = vectors();
    let zero = F::from(0);
    let one = F::from(1);
    assert_eq!(decode_field(encode_field(zero)).unwrap(), zero);
    assert_eq!(decode_field(encode_field(one)).unwrap(), one);

    let modulus_le =
        hex::decode(vectors["field"]["modulus_le"].as_str().unwrap()).expect("modulus hex");
    let mut modulus = [0u8; 32];
    modulus.copy_from_slice(&modulus_le);
    assert!(decode_field(modulus).is_err());

    let mut modulus_minus_one = modulus;
    modulus_minus_one[0] -= 1;
    let decoded = decode_field(modulus_minus_one).expect("modulus minus one");
    assert_eq!(decoded.to_repr().as_ref(), modulus_minus_one);

    assert_eq!(
        hex::encode(encode_field(h2f(b"asset", b"1soft").unwrap())),
        "4b07fced1905ae36bdde8ef3e2a8ffc948e2d28739df96b5c260415ef894f435"
    );
    assert_eq!(
        hex::encode(encode_field(h2f(b"multi-byte", b"\x00\xffpayload").unwrap())),
        vectors["field"]["h2f_multi_byte"].as_str().unwrap()
    );
}

#[test]
fn binary_documents_are_exact_and_reject_trailing_bytes() {
    assert_eq!(PUBLIC_INPUT_COUNT, 14);
    assert_eq!(TRANSACTION_PREFIX_BYTES, 534);
    assert_eq!(WITNESS_BYTES, 480);

    let profile = ProfileDescriptorV1::test_fixture();
    let deployment = DeploymentBindingV1::test_fixture(profile.identity());
    let kat = KatV1::test_fixture();
    let transaction = TransactionV1::test_fixture(32);
    let witness = WitnessV1::test_fixture();
    let request = WorkerRequestV1::test_fixture(profile.identity());
    let response = WorkerResponseV1::test_fixture(profile.identity());

    for (name, encoded, decode) in [
        (
            "profile",
            profile.encode().unwrap(),
            ProfileDescriptorV1::decode_test as fn(&[u8]) -> bool,
        ),
        (
            "deployment",
            deployment.encode().unwrap(),
            DeploymentBindingV1::decode_test,
        ),
        ("kat", kat.encode().unwrap(), KatV1::decode_test),
        (
            "transaction",
            transaction.encode().unwrap(),
            TransactionV1::decode_test,
        ),
        ("witness", witness.encode().unwrap(), WitnessV1::decode_test),
        (
            "worker request",
            request.encode_frame().unwrap(),
            WorkerRequestV1::decode_test,
        ),
        (
            "worker response",
            response.encode_frame().unwrap(),
            WorkerResponseV1::decode_test,
        ),
    ] {
        assert!(decode(&encoded), "{name} canonical decode");
        let mut trailing = encoded;
        trailing.push(0);
        assert!(!decode(&trailing), "{name} trailing byte accepted");
    }

    assert_eq!(witness.encode().unwrap().len(), WITNESS_BYTES);
    assert_eq!(
        transaction.encode().unwrap().len(),
        TRANSACTION_PREFIX_BYTES + 32
    );
}