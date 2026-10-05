//! Isolated owner-generation treasury payment experiment. Not a consensus protocol.
pub mod circuit;
pub mod context;
#[cfg(feature = "prover")]
pub mod proof;
pub mod relation;
pub use shielded_consensus_halo2::field::F;
pub const PROFILE: &str = "1soft/owner-treasury-lab/halo2-pasta/v1";
pub const K: u32 = 14;
pub const PUBLIC_COUNT: usize = 30;
pub const PROOF_BYTES: usize = 3200;

#[cfg(feature = "prover")]
pub mod fixtures;
#[cfg(feature = "prover")]
pub mod prover_request;
pub mod wire;
