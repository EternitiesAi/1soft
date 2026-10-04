use std::collections::HashSet;

use ff::Field;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};

use crate::{
    constants::{CAPACITY, DEPTH},
    field::{encode_field, F},
};

const WIDTH: usize = 3;
const RATE: usize = 2;

pub fn native_hash<const L: usize>(message: [F; L]) -> F {
    Hash::<F, P128Pow5T3, ConstantLength<L>, WIDTH, RATE>::init().hash(message)
}

fn domain(value: u64) -> F {
    F::from(value)
}

pub fn empty_leaf() -> F {
    native_hash([domain(101), F::ZERO])
}

pub fn present_leaf(commitment: F) -> F {
    native_hash([domain(101), commitment])
}

pub fn branch(left: F, right: F) -> F {
    native_hash([domain(102), left, right])
}

pub fn empty_roots() -> [F; DEPTH + 1] {
    let mut roots = [F::ZERO; DEPTH + 1];
    roots[0] = empty_leaf();
    for level in 1..=DEPTH {
        roots[level] = branch(roots[level - 1], roots[level - 1]);
    }
    roots
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeError {
    Capacity,
    ZeroCommitment,
    DuplicateCommitment,
    InvalidPosition,
    OutputConflict,
}

fn validate_commitments(commitments: &[F]) -> Result<(), TreeError> {
    if commitments.len() > CAPACITY {
        return Err(TreeError::Capacity);
    }
    let mut seen = HashSet::with_capacity(commitments.len());
    for commitment in commitments {
        if bool::from(commitment.is_zero()) {
            return Err(TreeError::ZeroCommitment);
        }
        if !seen.insert(encode_field(*commitment)) {
            return Err(TreeError::DuplicateCommitment);
        }
    }
    Ok(())
}

fn leaf_nodes(commitments: &[F]) -> Result<Vec<F>, TreeError> {
    validate_commitments(commitments)?;
    let empty = empty_leaf();
    let mut nodes = vec![empty; CAPACITY];
    for (index, commitment) in commitments.iter().enumerate() {
        nodes[index] = present_leaf(*commitment);
    }
    Ok(nodes)
}

pub fn tree_root(commitments: &[F]) -> Result<F, TreeError> {
    let mut nodes = leaf_nodes(commitments)?;
    for _ in 0..DEPTH {
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| branch(pair[0], pair[1]))
            .collect();
    }
    Ok(nodes[0])
}

pub fn authentication_path(
    commitments: &[F],
    position: usize,
) -> Result<[F; DEPTH], TreeError> {
    if position >= commitments.len() {
        return Err(TreeError::InvalidPosition);
    }
    let mut nodes = leaf_nodes(commitments)?;
    let mut current = position;
    let mut path = [F::ZERO; DEPTH];
    for sibling in &mut path {
        *sibling = nodes[current ^ 1];
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| branch(pair[0], pair[1]))
            .collect();
        current >>= 1;
    }
    Ok(path)
}

pub fn root_from_path(
    commitment: F,
    position: usize,
    path: [F; DEPTH],
) -> Result<F, TreeError> {
    if position >= CAPACITY || bool::from(commitment.is_zero()) {
        return Err(TreeError::InvalidPosition);
    }
    let mut current = present_leaf(commitment);
    for (level, sibling) in path.into_iter().enumerate() {
        current = if ((position >> level) & 1) == 0 {
            branch(current, sibling)
        } else {
            branch(sibling, current)
        };
    }
    Ok(current)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendResult {
    pub root_before: F,
    pub root_after: F,
    pub position_0: u16,
    pub position_1: u16,
}

pub fn append_two(commitments: &[F], output_0: F, output_1: F) -> Result<AppendResult, TreeError> {
    validate_commitments(commitments)?;
    if commitments.len().checked_add(2).ok_or(TreeError::Capacity)? > CAPACITY {
        return Err(TreeError::Capacity);
    }
    if bool::from(output_0.is_zero()) || bool::from(output_1.is_zero()) {
        return Err(TreeError::ZeroCommitment);
    }
    if output_0 == output_1
        || commitments.contains(&output_0)
        || commitments.contains(&output_1)
    {
        return Err(TreeError::OutputConflict);
    }
    let root_before = tree_root(commitments)?;
    let mut appended = commitments.to_vec();
    let position_0 = appended.len() as u16;
    appended.push(output_0);
    let position_1 = appended.len() as u16;
    appended.push(output_1);
    let root_after = tree_root(&appended)?;
    Ok(AppendResult {
        root_before,
        root_after,
        position_0,
        position_1,
    })
}
