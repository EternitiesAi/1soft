//! Isolated authority proof experiment. No value-note spend or consensus integration.
pub mod circuit;
pub mod context;
pub mod proof;
pub mod relation;
pub use shielded_consensus_halo2::field::F;
pub const PROFILE: &str = "1soft/private-authority-lab/halo2-pasta/v1";
pub const K: u32 = 13;
pub const PUBLIC_COUNT: usize = 20;
pub const PROOF_BYTES: usize = 3136;
