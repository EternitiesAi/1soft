use ff::{Field, PrimeField};
use owner_treasury_lab::{context, note_request, prover_request, relation, F};
use std::io::Write;
use std::process::{Command, Stdio};

fn source() -> (relation::Assignment, [u8; 32]) {
    let bootstrap = [17; 32];
    let (_, mut a, _) = relation::fixture_pair_domain(context::network_domain(bootstrap));
    a.witness.payment = 2;
    a.witness.change_value = 6;
    relation::derived(&mut a);
    relation::validate(&a).unwrap();
    (a, bootstrap)
}
fn raw(a: &relation::Assignment, bootstrap: [u8; 32]) -> Vec<u8> {
    let (source, _) = source();
    let mut v = prover_request::encode(&source, bootstrap).unwrap();
    v.truncate(136);
    for f in a
        .public
        .iter()
        .chain(prover_request::witness_fields(&a.witness).iter())
    {
        v.extend(f.to_repr());
    }
    v
}
#[test]
fn native_change_opening_path_and_next_request() {
    let (source, bootstrap) = source();
    let commitment = relation::change_note(&source);
    let notes = [
        relation::input_note(&source),
        F::from(123),
        relation::merchant_note(&source),
        commitment,
    ];
    let mut next = source.clone();
    next.witness.input_position = 3;
    next.witness.input_value = source.witness.change_value;
    next.witness.input_note_secret = source.witness.change_note_secret;
    next.witness.input_blind = source.witness.change_blind;
    let mut derive = raw(&next, bootstrap);
    derive.extend(4u16.to_le_bytes());
    for n in notes {
        derive.extend(n.to_repr());
    }
    let fields = owner_treasury_lab::wire::fields(&note_request::derive(&derive).unwrap()).unwrap();
    assert_eq!(fields.len(), 8);
    assert_eq!(fields[0], commitment);
    assert_eq!(fields[1], source.public[29]);
    let (root, paths) = relation::tree(&notes).unwrap();
    assert_eq!(fields[3], root);
    assert_eq!(fields[4..], paths[3]);
    assert_eq!(fields[2], relation::value_nullifier(&next));
    next.witness.parent_spent += 4;
    next.witness.parent_version += 1;
    next.witness.parent_blind = source.witness.parent_next_blind;
    next.witness.grant_spent += 4;
    next.witness.grant_version += 1;
    next.witness.grant_blind = source.witness.grant_next_blind;
    next.witness.parent_next_blind = F::from(5011);
    next.witness.grant_next_blind = F::from(5012);
    next.witness.path = paths[3];
    next.witness.payment = 1;
    next.witness.change_value = 3;
    next.witness.change_note_secret = F::from(5013);
    next.witness.change_blind = F::from(5014);
    next.witness.payment_note_secret = F::from(5015);
    next.witness.payment_blind = F::from(5016);
    next.public[4] = F::from(5017);
    next.public[7] = source.public[9];
    next.public[8] = source.public[10];
    next.public[15] = F::from(3);
    next.public[18] = F::from(5018);
    next.public[20] = root;
    for i in [9, 10, 11, 12, 13, 19, 21, 22, 23, 24] {
        next.public[i] = F::ZERO;
    }
    let partial = raw(&next, bootstrap);
    let complete = note_request::construct(&partial).unwrap();
    let built = prover_request::decode(&complete).unwrap();
    relation::validate(&built).unwrap();
    assert_eq!(built.public[7], source.public[9]);
    assert_eq!(built.public[8], source.public[10]);
    assert_eq!(built.public[20], root);
    assert_eq!(built.public[21], fields[2]);
    for idx in [7, 8, 20] {
        let mut bad = partial.clone();
        bad[136 + idx * 32] ^= 1;
        assert!(note_request::construct(&bad).is_err());
    }
    let mut bad = partial.clone();
    bad[136 + 9 * 32] = 1;
    assert!(note_request::construct(&bad).is_err());
    for value in [
        &derive[..derive.len() - 1],
        &[derive.clone(), vec![0]].concat(),
        &derive[..2088],
    ] {
        assert!(note_request::derive(value).is_err());
    }
    let mut bad = derive.clone();
    bad[136 + 30 * 32 + 15 * 32] = 16;
    assert!(note_request::derive(&bad).is_err());
    let mut bad = derive.clone();
    let end = bad.len() - 1;
    bad[end] ^= 1;
    assert!(note_request::derive(&bad).is_err());
    let mut bad = derive.clone();
    bad[8] ^= 1;
    assert!(note_request::derive(&bad).is_err());
}
#[test]
fn actual_controller_static_refusal_and_exact_output() {
    let (source, bootstrap) = source();
    let notes = [relation::input_note(&source)];
    let mut request = raw(&source, bootstrap);
    request.extend(1u16.to_le_bytes());
    request.extend(notes[0].to_repr());
    for (raw, okay) in [(request, true), (vec![b'x'; 2603], false)] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_owner-note-controller"))
            .arg("derive")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&raw).unwrap();
        let out = child.wait_with_output().unwrap();
        if okay {
            assert!(out.status.success());
            assert_eq!(out.stdout.len(), 256);
            assert!(out.stderr.is_empty());
        } else {
            assert!(!out.status.success());
            assert!(out.stdout.is_empty());
            assert_eq!(out.stderr, b"P7 note controller refused\n");
        }
    }
}
