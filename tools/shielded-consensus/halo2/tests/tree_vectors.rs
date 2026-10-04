use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use shielded_consensus_halo2::{
    field::{encode_field, F},
    tree::{append_two, empty_roots, tree_root, TreeError},
};

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-vectors/crypto-v1.json");
    serde_json::from_slice(&fs::read(path).expect("read vectors")).expect("parse vectors")
}

#[test]
fn empty_and_append_roots_match_frozen_vectors() {
    let vectors = vectors();
    let expected = vectors["tree"]["empty_roots"].as_array().expect("empty roots");
    assert_eq!(expected.len(), 5);
    for (root, expected) in empty_roots().iter().zip(expected) {
        assert_eq!(hex::encode(encode_field(*root)), expected.as_str().unwrap());
    }

    let expected_counts = vectors["tree"]["count_roots"]
        .as_array()
        .expect("count roots");
    assert_eq!(expected_counts.len(), 17);
    let mut growing = Vec::new();
    for (count, expected) in expected_counts.iter().enumerate() {
        if count > 0 {
            growing.push(F::from(count as u64));
        }
        assert_eq!(
            hex::encode(encode_field(tree_root(&growing).unwrap())),
            expected.as_str().unwrap()
        );
    }

    let commitments = vec![F::from(11), F::from(12), F::from(13)];
    assert_eq!(
        hex::encode(encode_field(tree_root(&commitments).unwrap())),
        vectors["tree"]["three_commitments_root"].as_str().unwrap()
    );

    let append = append_two(&commitments, F::from(14), F::from(15)).unwrap();
    assert_eq!(append.position_0, 3);
    assert_eq!(append.position_1, 4);
    assert_eq!(append.root_before, tree_root(&commitments).unwrap());
    assert_eq!(
        append.root_after,
        tree_root(&[F::from(11), F::from(12), F::from(13), F::from(14), F::from(15)])
            .unwrap()
    );

    let mut full = Vec::new();
    for value in 1..=16 {
        full.push(F::from(value));
        assert!(tree_root(&full).is_ok());
    }
    assert_eq!(tree_root(&[F::from(1); 17]), Err(TreeError::Capacity));
    assert_eq!(
        append_two(&full[..15], F::from(20), F::from(21)),
        Err(TreeError::Capacity)
    );
}

#[test]
fn tree_rejects_zero_duplicates_and_output_order_changes_root() {
    assert_eq!(tree_root(&[F::from(0)]), Err(TreeError::ZeroCommitment));
    assert_eq!(
        tree_root(&[F::from(1), F::from(1)]),
        Err(TreeError::DuplicateCommitment)
    );
    let left = append_two(&[F::from(1)], F::from(2), F::from(3)).unwrap();
    let right = append_two(&[F::from(1)], F::from(3), F::from(2)).unwrap();
    assert_ne!(left.root_after, right.root_after);
}
