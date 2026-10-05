//! Isolated atomic treasury payment experiment. Not a consensus protocol.
pub mod circuit;
pub mod context;
pub mod proof;
pub mod relation;
pub use shielded_consensus_halo2::field::F;
pub const PROFILE: &str = "1soft/private-treasury-payment-lab/halo2-pasta/v1";
pub const K: u32 = 14;
pub const PUBLIC_COUNT: usize = 25;
pub const PROOF_BYTES: usize = 3200;

pub mod fixtures;
pub mod wire;
