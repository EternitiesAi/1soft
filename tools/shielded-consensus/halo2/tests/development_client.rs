#![cfg(feature = "dev-prover")]

use std::{io::Write, process::{Command, Stdio}};

use shielded_consensus_halo2::{
    development_client::{
        DevelopmentClientRequestV1, GenesisCommitmentsV1, NoteDefinitionV1, NoteDomainV1,
        SpendHeaderV1,
    },
    encoding::{ProverRequestV1, TransactionV1},
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
    assert_eq!(DevelopmentClientRequestV1::decode(&full_encoded).unwrap(), full_genesis);
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
    assert!(genesis_output.status.success(), "{}", String::from_utf8_lossy(&genesis_output.stderr));
    assert!(genesis_output.stderr.is_empty());
    let genesis = GenesisCommitmentsV1::decode(&genesis_output.stdout).expect("decode genesis output");
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
    assert!(client_output.status.success(), "{}", String::from_utf8_lossy(&client_output.stderr));
    assert!(client_output.stderr.is_empty());
    let prover_request = ProverRequestV1::decode(&client_output.stdout).expect("decode prover request");
    assert_eq!(prover_request.public_inputs, SyntheticFixture::one_note().assignment.public.to_field_bytes());

    let prover_output = invoke(prover, &client_output.stdout);
    assert!(prover_output.status.success(), "{}", String::from_utf8_lossy(&prover_output.stderr));
    assert!(prover_output.stderr.is_empty());
    let proof_length = prover_output.stdout.len() - shielded_consensus_halo2::constants::TRANSACTION_PREFIX_BYTES;
    let transaction = TransactionV1::decode(
        &prover_output.stdout,
        proof_length,
        shielded_consensus_halo2::constants::MAX_TRANSACTION_BYTES,
    ).expect("decode transaction");
    for secret in [21u64, 22, 23, 32, 33, 34, 42, 43, 44] {
        let needle = field(secret);
        assert!(
            !prover_output.stdout.windows(needle.len()).any(|window| window == needle),
            "TransactionV1 leaked witness field {secret}"
        );
    }
    PinnedVerifier::new().unwrap()
        .verify_public_bytes(&transaction.public_inputs, &transaction.proof)
        .expect("actual Halo2 verification");

    let mut trailing = encoded_spend;
    trailing.push(0);
    assert!(DevelopmentClientRequestV1::decode(&trailing).is_err());
    let rejected = invoke(client, &trailing);
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
}
