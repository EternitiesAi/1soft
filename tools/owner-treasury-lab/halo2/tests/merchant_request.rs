use ff::PrimeField;
use owner_treasury_lab::{context, note_request, prover_request, relation, F};
use std::io::Write;
use std::process::{Command, Stdio};

fn source() -> Vec<u8> {
    let bootstrap = [17; 32];
    let (_, a, _) = relation::fixture_pair_domain(context::network_domain(bootstrap));
    let full = prover_request::encode(&a, bootstrap).unwrap();
    let mut raw = full[..1096].to_vec();
    for i in [12, 13, 14, 29, 30] {
        raw.extend(&full[1096 + i * 32..1128 + i * 32]);
    }
    raw
}
#[test]
fn merchant_projection_matches_frozen_relation_and_all_opening_domains() {
    let raw = source();
    let expected = raw[136 + 22 * 32..168 + 22 * 32].to_vec();
    assert_eq!(note_request::merchant(&raw).unwrap(), expected);
    for slot in 0..5 {
        let mut bad = raw.clone();
        // Large expiry stays inside the valid >= p16 range.
        let value = if slot == 3 { F::from(1000) } else { F::from(9191) };
        bad[1096 + slot * 32..1128 + slot * 32].copy_from_slice(&value.to_repr());
        assert_ne!(note_request::merchant(&bad).unwrap(), expected);
    }
    for slot in [2, 3, 18, 26, 28] {
        let mut bad = raw.clone();
        bad[136 + slot * 32..168 + slot * 32].copy_from_slice(&F::from(9191).to_repr());
        assert_ne!(note_request::merchant(&bad).unwrap(), expected);
    }
    let mut bad = raw.clone();bad[136 + 32] ^= 1;
    assert!(note_request::merchant(&bad).is_err()); // pinned network p1
    let mut bad = raw.clone();bad[136 + 22 * 32] ^= 1;
    assert_eq!(note_request::merchant(&bad).unwrap(), expected); // caller compares p22
}
#[test]
fn merchant_syntax_and_native_nonzero_expiry_guards() {
    let raw = source();
    for slot in 0..5 {
        let mut bad = raw.clone();bad[1096 + slot * 32..1128 + slot * 32].fill(0);
        assert!(note_request::merchant(&bad).is_err());
    }
    for slot in [1, 3] { // u64 opening overflow
        let mut bad = raw.clone();bad[1096 + slot * 32 + 8] = 1;
        assert!(note_request::merchant(&bad).is_err());
    }
    let mut bad = raw.clone();bad[1096..1128].fill(255);
    assert!(note_request::merchant(&bad).is_err());
    for index in [8, 40, 72, 104] {
        let mut bad=raw.clone();bad[index]^=1;
        assert!(note_request::merchant(&bad).is_err());
    }
    assert!(note_request::merchant(&raw[..raw.len()-1]).is_err());
    assert!(note_request::merchant(&[raw,vec![0]].concat()).is_err());
}
#[test]
fn actual_merchant_controller_fixed_output_and_static_error() {
    for (raw,okay) in [(source(),true),(vec![0;1257],false)] {
        let mut child=Command::new(env!("CARGO_BIN_EXE_owner-note-controller"))
            .arg("merchant").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(&raw).unwrap();
        let out=child.wait_with_output().unwrap();
        if okay {assert!(out.status.success());assert_eq!(out.stdout.len(),32);assert!(out.stderr.is_empty());}
        else {assert!(!out.status.success());assert!(out.stdout.is_empty());assert_eq!(out.stderr,b"P7 note controller refused\n");}
    }
}
