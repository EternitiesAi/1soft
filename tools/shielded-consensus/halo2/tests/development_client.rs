#![cfg(feature = "dev-prover")]

use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

use serde_json::Value;
use sha2::{Digest, Sha256};
use shielded_consensus_halo2::{
    development_client::{
        DevelopmentClientRequestV1, GenesisCommitmentsV1, NoteDefinitionV1, NoteDomainV1,
        OwnerKeyV1, RecipientNoteDefinitionV1, SpendHeaderV1, MAX_CLIENT_REQUEST_BYTES,
    },
    encoding::{EncodingError, ProverRequestV1, TransactionV1},
    field::{encode_field, F},
    fixture::SyntheticFixture,
    verifier::PinnedVerifier,
};

fn field(value: u64) -> [u8; 32] {
    encode_field(F::from(value))
}

fn invoke(program: &str, input: &[u8]) -> std::process::Output {
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child");
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().expect("wait for child")
}

fn wallet_vectors() -> Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/wallet-client-v1.json");
    serde_json::from_slice(&fs::read(path).expect("read wallet vectors"))
        .expect("parse wallet vectors")
}

fn vector_hex(vectors: &Value, pointer: &str) -> Vec<u8> {
    hex::decode(
        vectors
            .pointer(pointer)
            .and_then(Value::as_str)
            .expect("string vector"),
    )
    .expect("hex vector")
}

fn vector_usize(vectors: &Value, pointer: &str) -> usize {
    vectors
        .pointer(pointer)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .expect("usize vector")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sample_domain() -> NoteDomainV1 {
    NoteDomainV1 {
        genesis_field: field(11),
        asset_field: field(12),
        context_field: field(13),
        authority_epoch: field(2),
        policy_field: field(14),
    }
}

fn sample_input_note() -> NoteDefinitionV1 {
    NoteDefinitionV1 {
        expiry: 300,
        value: 100,
        owner_spend_secret: field(22),
        note_secret: field(23),
        blinding: field(21),
    }
}

fn sample_genesis(client: &str) -> GenesisCommitmentsV1 {
    let request = DevelopmentClientRequestV1::GenesisCommitments {
        domain: sample_domain(),
        notes: vec![sample_input_note()],
    };
    let output = invoke(client, &request.encode().expect("encode genesis request"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    GenesisCommitmentsV1::decode(&output.stdout).expect("decode genesis output")
}

fn sample_header() -> SpendHeaderV1 {
    SpendHeaderV1 {
        domain: sample_domain(),
        valid_from: field(100),
        valid_until: field(200),
        fee: field(1),
    }
}

fn legacy_spend(commitments: Vec<[u8; 32]>) -> DevelopmentClientRequestV1 {
    DevelopmentClientRequestV1::Spend {
        genesis_sha256: [0x31; 32],
        deployment_id: [0x42; 32],
        header: sample_header(),
        commitments,
        input_position: 0,
        input_note: sample_input_note(),
        outputs: [
            NoteDefinitionV1 {
                expiry: 400,
                value: 40,
                owner_spend_secret: field(33),
                note_secret: field(34),
                blinding: field(32),
            },
            NoteDefinitionV1 {
                expiry: 500,
                value: 59,
                owner_spend_secret: field(43),
                note_secret: field(44),
                blinding: field(42),
            },
        ],
    }
}

#[test]
fn client_derives_genesis_and_spend_then_prover_and_verifier_round_trip() {
    let client = env!("CARGO_BIN_EXE_shielded-development-client");
    let prover = env!("CARGO_BIN_EXE_shielded-development-prover");
    let domain = NoteDomainV1 {
        genesis_field: field(11),
        asset_field: field(12),
        context_field: field(13),
        authority_epoch: field(2),
        policy_field: field(14),
    };
    let input_note = NoteDefinitionV1 {
        expiry: 300,
        value: 100,
        owner_spend_secret: field(22),
        note_secret: field(23),
        blinding: field(21),
    };
    let genesis_request = DevelopmentClientRequestV1::GenesisCommitments {
        domain: domain.clone(),
        notes: vec![input_note.clone()],
    };
    let encoded_genesis = genesis_request.encode().expect("encode genesis request");
    assert_eq!(
        DevelopmentClientRequestV1::decode(&encoded_genesis).unwrap(),
        genesis_request
    );
    let full_genesis = DevelopmentClientRequestV1::GenesisCommitments {
        domain: match &genesis_request {
            DevelopmentClientRequestV1::GenesisCommitments { domain, .. } => domain.clone(),
            _ => unreachable!(),
        },
        notes: (0..16)
            .map(|index| NoteDefinitionV1 {
                expiry: 300 + index,
                value: 1 + index,
                owner_spend_secret: field(100 + index),
                note_secret: field(200 + index),
                blinding: field(300 + index),
            })
            .collect(),
    };
    let full_encoded = full_genesis.encode().expect("encode 16-note genesis");
    assert_eq!(full_encoded.len(), 1966);
    assert_eq!(
        DevelopmentClientRequestV1::decode(&full_encoded).unwrap(),
        full_genesis
    );
    let too_many = DevelopmentClientRequestV1::GenesisCommitments {
        domain: match &genesis_request {
            DevelopmentClientRequestV1::GenesisCommitments { domain, .. } => domain.clone(),
            _ => unreachable!(),
        },
        notes: vec![
            NoteDefinitionV1 {
                expiry: 300,
                value: 1,
                owner_spend_secret: field(100),
                note_secret: field(200),
                blinding: field(300),
            };
            17
        ],
    };
    assert!(too_many.encode().is_err());
    let mut full_trailing = full_encoded;
    full_trailing.push(0);
    assert!(DevelopmentClientRequestV1::decode(&full_trailing).is_err());
    let genesis_output = invoke(client, &encoded_genesis);
    assert!(
        genesis_output.status.success(),
        "{}",
        String::from_utf8_lossy(&genesis_output.stderr)
    );
    assert!(genesis_output.stderr.is_empty());
    let genesis =
        GenesisCommitmentsV1::decode(&genesis_output.stdout).expect("decode genesis output");
    assert_eq!(genesis.commitments.len(), 1);

    let spend_request = DevelopmentClientRequestV1::Spend {
        genesis_sha256: [0x31; 32],
        deployment_id: [0x42; 32],
        header: SpendHeaderV1 {
            domain,
            valid_from: field(100),
            valid_until: field(200),
            fee: field(1),
        },
        commitments: genesis.commitments.clone(),
        input_position: 0,
        input_note,
        outputs: [
            NoteDefinitionV1 {
                expiry: 400,
                value: 40,
                owner_spend_secret: field(33),
                note_secret: field(34),
                blinding: field(32),
            },
            NoteDefinitionV1 {
                expiry: 500,
                value: 59,
                owner_spend_secret: field(43),
                note_secret: field(44),
                blinding: field(42),
            },
        ],
    };
    let encoded_spend = spend_request.encode().expect("encode spend request");
    assert_eq!(
        DevelopmentClientRequestV1::decode(&encoded_spend).unwrap(),
        spend_request
    );
    let client_output = invoke(client, &encoded_spend);
    assert!(
        client_output.status.success(),
        "{}",
        String::from_utf8_lossy(&client_output.stderr)
    );
    assert!(client_output.stderr.is_empty());
    let prover_request =
        ProverRequestV1::decode(&client_output.stdout).expect("decode prover request");
    assert_eq!(
        prover_request.public_inputs,
        SyntheticFixture::one_note()
            .assignment
            .public
            .to_field_bytes()
    );

    let prover_output = invoke(prover, &client_output.stdout);
    assert!(
        prover_output.status.success(),
        "{}",
        String::from_utf8_lossy(&prover_output.stderr)
    );
    assert!(prover_output.stderr.is_empty());
    let proof_length =
        prover_output.stdout.len() - shielded_consensus_halo2::constants::TRANSACTION_PREFIX_BYTES;
    let transaction = TransactionV1::decode(
        &prover_output.stdout,
        proof_length,
        shielded_consensus_halo2::constants::MAX_TRANSACTION_BYTES,
    )
    .expect("decode transaction");
    for secret in [21u64, 22, 23, 32, 33, 34, 42, 43, 44] {
        let needle = field(secret);
        assert!(
            !prover_output
                .stdout
                .windows(needle.len())
                .any(|window| window == needle),
            "TransactionV1 leaked witness field {secret}"
        );
    }
    PinnedVerifier::new()
        .unwrap()
        .verify_public_bytes(&transaction.public_inputs, &transaction.proof)
        .expect("actual Halo2 verification");

    let mut trailing = encoded_spend;
    trailing.push(0);
    assert!(DevelopmentClientRequestV1::decode(&trailing).is_err());
    let rejected = invoke(client, &trailing);
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
}

#[test]
fn legacy_opcodes_remain_byte_identical() {
    let client = env!("CARGO_BIN_EXE_shielded-development-client");
    let vectors = wallet_vectors();
    assert_eq!(vectors["schema"], "1soft.wallet-client.v1");
    assert_eq!(vectors["version"], 1);

    let genesis_request = DevelopmentClientRequestV1::GenesisCommitments {
        domain: sample_domain(),
        notes: vec![sample_input_note()],
    };
    let encoded_genesis = genesis_request.encode().expect("encode opcode 1");
    assert_eq!(
        encoded_genesis.len(),
        vector_usize(&vectors, "/legacy/opcode_1/request_length")
    );
    assert_eq!(
        &encoded_genesis[..12],
        vector_hex(&vectors, "/legacy/opcode_1/request_header_hex")
    );
    assert_eq!(
        sha256_hex(&encoded_genesis),
        vectors
            .pointer("/legacy/opcode_1/request_sha256")
            .unwrap()
            .as_str()
            .unwrap()
    );
    assert_eq!(
        DevelopmentClientRequestV1::decode(&encoded_genesis).unwrap(),
        genesis_request
    );

    let genesis_output = invoke(client, &encoded_genesis);
    assert!(
        genesis_output.status.success(),
        "{}",
        String::from_utf8_lossy(&genesis_output.stderr)
    );
    assert!(genesis_output.stderr.is_empty());
    assert_eq!(
        genesis_output.stdout.len(),
        vector_usize(&vectors, "/legacy/opcode_1/response_length")
    );
    assert_eq!(
        &genesis_output.stdout[..12],
        vector_hex(&vectors, "/legacy/opcode_1/response_header_hex")
    );
    assert_eq!(
        sha256_hex(&genesis_output.stdout),
        vectors
            .pointer("/legacy/opcode_1/response_sha256")
            .unwrap()
            .as_str()
            .unwrap()
    );
    let genesis =
        GenesisCommitmentsV1::decode(&genesis_output.stdout).expect("decode opcode 1 output");

    let spend_request = legacy_spend(genesis.commitments);
    let encoded_spend = spend_request.encode().expect("encode opcode 2");
    assert_eq!(
        encoded_spend.len(),
        vector_usize(&vectors, "/legacy/opcode_2/request_length")
    );
    assert_eq!(
        &encoded_spend[..12],
        vector_hex(&vectors, "/legacy/opcode_2/request_header_hex")
    );
    assert_eq!(
        sha256_hex(&encoded_spend),
        vectors
            .pointer("/legacy/opcode_2/request_sha256")
            .unwrap()
            .as_str()
            .unwrap()
    );
    assert_eq!(
        DevelopmentClientRequestV1::decode(&encoded_spend).unwrap(),
        spend_request
    );

    let prover_output = invoke(client, &encoded_spend);
    assert!(
        prover_output.status.success(),
        "{}",
        String::from_utf8_lossy(&prover_output.stderr)
    );
    assert!(prover_output.stderr.is_empty());
    assert_eq!(
        prover_output.stdout.len(),
        vector_usize(&vectors, "/legacy/opcode_2/response_length")
    );
    assert_eq!(
        &prover_output.stdout[..18],
        vector_hex(&vectors, "/legacy/opcode_2/response_header_hex")
    );
    assert_eq!(
        sha256_hex(&prover_output.stdout),
        vectors
            .pointer("/legacy/opcode_2/response_sha256")
            .unwrap()
            .as_str()
            .unwrap()
    );
    let prover_request =
        ProverRequestV1::decode(&prover_output.stdout).expect("decode frozen opcode 2 output");
    assert_eq!(
        prover_request.public_inputs,
        SyntheticFixture::one_note()
            .assignment
            .public
            .to_field_bytes()
    );
}

#[test]
fn derive_owner_key_uses_frozen_spend_key_relation() {
    let client = env!("CARGO_BIN_EXE_shielded-development-client");
    let vectors = wallet_vectors();
    let spend_secret: [u8; 32] = vector_hex(&vectors, "/derive_owner_key/spend_secret_hex")
        .try_into()
        .unwrap();
    let frozen_owner_key: [u8; 32] = vector_hex(&vectors, "/derive_owner_key/owner_key_hex")
        .try_into()
        .unwrap();
    let request = DevelopmentClientRequestV1::DeriveOwnerKey { spend_secret };

    let encoded = request.encode().expect("encode opcode 3");
    assert_eq!(
        encoded.len(),
        vector_usize(&vectors, "/derive_owner_key/request_length")
    );
    assert_eq!(&encoded[..12], b"1SFTCLI1\x01\x00\x03\x00");
    assert_eq!(
        sha256_hex(&encoded),
        vectors
            .pointer("/derive_owner_key/request_sha256")
            .unwrap()
            .as_str()
            .unwrap()
    );
    assert_eq!(
        DevelopmentClientRequestV1::decode(&encoded).unwrap(),
        request
    );

    let direct = request
        .derive()
        .expect("derive owner key")
        .encode()
        .expect("encode owner key");
    assert_eq!(
        direct.len(),
        vector_usize(&vectors, "/derive_owner_key/response_length")
    );
    assert_eq!(&direct[..10], b"1SFTKEY1\x01\x00");
    assert_eq!(
        sha256_hex(&direct),
        vectors
            .pointer("/derive_owner_key/response_sha256")
            .unwrap()
            .as_str()
            .unwrap()
    );
    assert_eq!(
        OwnerKeyV1::decode(&direct).unwrap(),
        OwnerKeyV1 {
            owner_key: frozen_owner_key
        }
    );

    let process = invoke(client, &encoded);
    assert!(
        process.status.success(),
        "{}",
        String::from_utf8_lossy(&process.stderr)
    );
    assert!(process.stderr.is_empty());
    assert_eq!(process.stdout, direct);
}

#[test]
fn public_recipient_spend_never_requires_recipient_secret() {
    let client = env!("CARGO_BIN_EXE_shielded-development-client");
    let prover = env!("CARGO_BIN_EXE_shielded-development-prover");
    let vectors = wallet_vectors();
    let genesis = sample_genesis(client);
    let recipient_owner_key: [u8; 32] =
        vector_hex(&vectors, "/public_recipient/recipient_owner_key_hex")
            .try_into()
            .unwrap();
    let change_owner_key: [u8; 32] = vector_hex(&vectors, "/public_recipient/change_owner_key_hex")
        .try_into()
        .unwrap();
    let request = DevelopmentClientRequestV1::SpendToRecipientKeys {
        genesis_sha256: [0x31; 32],
        deployment_id: [0x42; 32],
        header: sample_header(),
        commitments: genesis.commitments,
        input_position: 0,
        input_note: sample_input_note(),
        outputs: [
            RecipientNoteDefinitionV1 {
                expiry: 400,
                value: 40,
                owner_key: recipient_owner_key,
                note_secret: field(34),
                blinding: field(32),
            },
            RecipientNoteDefinitionV1 {
                expiry: 500,
                value: 59,
                owner_key: change_owner_key,
                note_secret: field(44),
                blinding: field(42),
            },
        ],
    };
    let encoded = request.encode().expect("encode opcode 4");
    let recipient_secret = field(43);
    assert_eq!(
        encoded.len(),
        vector_usize(&vectors, "/public_recipient/opcode_4_request_length")
    );
    assert_eq!(&encoded[..12], b"1SFTCLI1\x01\x00\x04\x00");
    assert_eq!(
        sha256_hex(&encoded),
        vectors
            .pointer("/public_recipient/opcode_4_request_sha256")
            .unwrap()
            .as_str()
            .unwrap()
    );
    assert!(!encoded.windows(32).any(|window| window == recipient_secret));
    assert_eq!(
        DevelopmentClientRequestV1::decode(&encoded).unwrap(),
        request
    );

    let client_output = invoke(client, &encoded);
    assert!(
        client_output.status.success(),
        "{}",
        String::from_utf8_lossy(&client_output.stderr)
    );
    assert!(client_output.stderr.is_empty());
    assert_eq!(
        client_output.stdout.len(),
        vector_usize(&vectors, "/public_recipient/prover_request_length")
    );
    assert_eq!(
        sha256_hex(&client_output.stdout),
        vectors
            .pointer("/public_recipient/prover_request_sha256")
            .unwrap()
            .as_str()
            .unwrap()
    );
    assert!(!client_output
        .stdout
        .windows(32)
        .any(|window| window == recipient_secret));
    let prover_request =
        ProverRequestV1::decode(&client_output.stdout).expect("decode opcode 4 output");
    assert_eq!(
        prover_request.witness.output_recipient_keys[0],
        recipient_owner_key
    );
    assert_eq!(
        prover_request.witness.output_recipient_keys[1],
        change_owner_key
    );
    assert_eq!(
        client_output
            .stdout
            .windows(32)
            .filter(|window| *window == recipient_owner_key)
            .count(),
        1
    );

    let prover_output = invoke(prover, &client_output.stdout);
    assert!(
        prover_output.status.success(),
        "{}",
        String::from_utf8_lossy(&prover_output.stderr)
    );
    assert!(prover_output.stderr.is_empty());
    assert!(!prover_output
        .stdout
        .windows(32)
        .any(|window| window == recipient_secret));
    let proof_length =
        prover_output.stdout.len() - shielded_consensus_halo2::constants::TRANSACTION_PREFIX_BYTES;
    let transaction = TransactionV1::decode(
        &prover_output.stdout,
        proof_length,
        shielded_consensus_halo2::constants::MAX_TRANSACTION_BYTES,
    )
    .expect("decode opcode 4 transaction");
    PinnedVerifier::new()
        .unwrap()
        .verify_public_bytes(&transaction.public_inputs, &transaction.proof)
        .expect("verify opcode 4 Halo2 proof");
}

#[test]
fn new_opcodes_reject_zero_noncanonical_trailing_and_overbound_input() {
    let vectors = wallet_vectors();
    let owner_key: [u8; 32] = vector_hex(&vectors, "/public_recipient/recipient_owner_key_hex")
        .try_into()
        .unwrap();
    let change_key: [u8; 32] = vector_hex(&vectors, "/public_recipient/change_owner_key_hex")
        .try_into()
        .unwrap();

    let zero_secret = DevelopmentClientRequestV1::DeriveOwnerKey {
        spend_secret: field(0),
    };
    assert_eq!(zero_secret.encode(), Err(EncodingError::InvalidValue));
    let mut zero_wire = b"1SFTCLI1\x01\x00\x03\x00".to_vec();
    zero_wire.extend_from_slice(&field(0));
    assert_eq!(
        DevelopmentClientRequestV1::decode(&zero_wire),
        Err(EncodingError::InvalidValue)
    );

    let mut noncanonical_wire = b"1SFTCLI1\x01\x00\x03\x00".to_vec();
    noncanonical_wire.extend_from_slice(&[0xff; 32]);
    assert_eq!(
        DevelopmentClientRequestV1::decode(&noncanonical_wire),
        Err(EncodingError::InvalidField)
    );

    let valid_key_request = DevelopmentClientRequestV1::DeriveOwnerKey {
        spend_secret: field(22),
    };
    let mut trailing = valid_key_request.encode().unwrap();
    trailing.push(0);
    assert_eq!(
        DevelopmentClientRequestV1::decode(&trailing),
        Err(EncodingError::TrailingBytes)
    );

    assert_eq!(
        OwnerKeyV1 {
            owner_key: field(0)
        }
        .encode(),
        Err(EncodingError::InvalidValue)
    );
    assert_eq!(
        OwnerKeyV1 {
            owner_key: [0xff; 32]
        }
        .encode(),
        Err(EncodingError::InvalidField)
    );
    let mut zero_owner_response = b"1SFTKEY1\x01\x00".to_vec();
    zero_owner_response.extend_from_slice(&field(0));
    assert_eq!(
        OwnerKeyV1::decode(&zero_owner_response),
        Err(EncodingError::InvalidValue)
    );
    let mut noncanonical_owner_response = b"1SFTKEY1\x01\x00".to_vec();
    noncanonical_owner_response.extend_from_slice(&[0xff; 32]);
    assert_eq!(
        OwnerKeyV1::decode(&noncanonical_owner_response),
        Err(EncodingError::InvalidField)
    );
    let mut owner_response = OwnerKeyV1 { owner_key }.encode().unwrap();
    owner_response.push(0);
    assert_eq!(
        OwnerKeyV1::decode(&owner_response),
        Err(EncodingError::TrailingBytes)
    );

    let recipient_request = DevelopmentClientRequestV1::SpendToRecipientKeys {
        genesis_sha256: [0x31; 32],
        deployment_id: [0x42; 32],
        header: sample_header(),
        commitments: vec![field(7)],
        input_position: 0,
        input_note: sample_input_note(),
        outputs: [
            RecipientNoteDefinitionV1 {
                expiry: 400,
                value: 40,
                owner_key: field(0),
                note_secret: field(34),
                blinding: field(32),
            },
            RecipientNoteDefinitionV1 {
                expiry: 500,
                value: 59,
                owner_key: change_key,
                note_secret: field(44),
                blinding: field(42),
            },
        ],
    };
    assert_eq!(recipient_request.encode(), Err(EncodingError::InvalidValue));

    let valid_recipient_request = DevelopmentClientRequestV1::SpendToRecipientKeys {
        genesis_sha256: [0x31; 32],
        deployment_id: [0x42; 32],
        header: sample_header(),
        commitments: vec![field(7)],
        input_position: 0,
        input_note: sample_input_note(),
        outputs: [
            RecipientNoteDefinitionV1 {
                expiry: 400,
                value: 40,
                owner_key,
                note_secret: field(34),
                blinding: field(32),
            },
            RecipientNoteDefinitionV1 {
                expiry: 500,
                value: 59,
                owner_key: change_key,
                note_secret: field(44),
                blinding: field(42),
            },
        ],
    };
    let valid_recipient_wire = valid_recipient_request.encode().unwrap();
    let owner_offset = valid_recipient_wire
        .windows(32)
        .position(|window| window == owner_key)
        .expect("recipient owner key offset");
    let mut zero_recipient_wire = valid_recipient_wire.clone();
    zero_recipient_wire[owner_offset..owner_offset + 32].copy_from_slice(&field(0));
    assert_eq!(
        DevelopmentClientRequestV1::decode(&zero_recipient_wire),
        Err(EncodingError::InvalidValue)
    );
    let mut noncanonical_recipient_wire = valid_recipient_wire.clone();
    noncanonical_recipient_wire[owner_offset..owner_offset + 32].copy_from_slice(&[0xff; 32]);
    assert_eq!(
        DevelopmentClientRequestV1::decode(&noncanonical_recipient_wire),
        Err(EncodingError::InvalidField)
    );
    let mut recipient_trailing = valid_recipient_wire;
    recipient_trailing.push(0);
    assert_eq!(
        DevelopmentClientRequestV1::decode(&recipient_trailing),
        Err(EncodingError::TrailingBytes)
    );

    let overbound = vec![0u8; MAX_CLIENT_REQUEST_BYTES + 1];
    assert_eq!(
        DevelopmentClientRequestV1::decode(&overbound),
        Err(EncodingError::LimitExceeded)
    );
}
