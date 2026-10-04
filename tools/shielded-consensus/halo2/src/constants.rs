pub const BACKEND_ID: u16 = 1;
pub const RELATION_VERSION: u32 = 1;
pub const PROFILE_DESCRIPTOR_VERSION: u16 = 1;
pub const DEPLOYMENT_BINDING_VERSION: u16 = 1;
pub const TRANSACTION_WIRE_VERSION: u16 = 1;
pub const WITNESS_VERSION: u16 = 1;
pub const PROVER_REQUEST_VERSION: u16 = 1;
pub const WORKER_PROTOCOL_VERSION: u16 = 1;

pub const K: u32 = 13;
pub const DEPTH: usize = 4;
pub const CAPACITY: usize = 1 << DEPTH;
pub const PUBLIC_INPUT_COUNT: usize = 14;
pub const MAX_PROOF_BYTES: usize = 60 * 1024;
pub const MAX_TRANSACTION_BYTES: usize = 64 * 1024;
pub const MAX_WORKER_FRAME_BYTES: usize = 1024 * 1024;
pub const TRANSACTION_PREFIX_BYTES: usize = 534;
pub const WITNESS_BYTES: usize = 480;
pub const PROVER_REQUEST_BYTES: usize = 1010;

pub const CIRCUIT_ID: &str = "1soft/shielded-consensus/halo2-pasta/v1";
pub const PUBLIC_INPUT_NAMES: [&str; PUBLIC_INPUT_COUNT] = [
    "relation_version",
    "genesis_field",
    "asset_field",
    "context_field",
    "authority_epoch",
    "valid_from",
    "valid_until",
    "policy_field",
    "anchor_root",
    "nullifier",
    "output_commitment_0",
    "output_commitment_1",
    "fee",
    "authorization_digest",
];

pub const PROFILE_MAGIC: [u8; 8] = *b"1SFTPFD1";
pub const DEPLOYMENT_MAGIC: [u8; 8] = *b"1SFTDEP1";
pub const KAT_MAGIC: [u8; 8] = *b"1SFTKAT1";
pub const TRANSACTION_MAGIC: [u8; 8] = *b"1SFTSHD1";
pub const WITNESS_MAGIC: [u8; 8] = *b"1SFTWIT1";
pub const PROVER_REQUEST_MAGIC: [u8; 8] = *b"1SFTPRV1";
pub const WORKER_REQUEST_MAGIC: [u8; 8] = *b"1SFTVRQ1";
pub const WORKER_RESPONSE_MAGIC: [u8; 8] = *b"1SFTVRS1";

pub const PROFILE_DOMAIN: &[u8] = b"1soft/shielded-profile/v1\0";
pub const DEPLOYMENT_DOMAIN: &[u8] = b"1soft/shielded-deployment/v1\0";
pub const KAT_DOMAIN: &[u8] = b"1soft/shielded-kat/v1\0";
pub const TXID_DOMAIN: &[u8] = b"1soft/shielded-txid/v1\0";
pub const FIELD_DOMAIN: &[u8] = b"1soft/shielded-field/v1\0";
