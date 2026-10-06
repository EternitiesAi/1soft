//! Experimental P8 recipient transfers. Native proofs do not establish consensus execution.
pub mod circuit;
#[cfg(feature = "prover")]
pub mod fixtures;
pub mod profile_pins;
#[cfg(feature = "prover")]
pub mod proof;
pub mod relation;
#[cfg(feature = "prover")]
pub mod request;
pub mod verifier;
pub mod wire;
pub use shielded_consensus_halo2::field::F;
pub const K: u32 = 13;
pub const PUBLIC_COUNT: usize = 13;
pub const WITNESS_COUNT: usize = 19;
pub const PROOF_BYTES: usize = 3136;
