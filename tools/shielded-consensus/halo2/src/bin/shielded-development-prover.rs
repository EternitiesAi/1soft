use std::{io::{self, Read, Write}, process};

use shielded_consensus_halo2::{
    constants::PROVER_REQUEST_BYTES,
    encoding::{ProverRequestV1, TransactionV1},
    prover::ProvingProfile,
    relation::{Assignment, PublicStatement, SpendWitness},
};

fn run() -> Result<(), String> {
    let mut input = Vec::with_capacity(PROVER_REQUEST_BYTES + 1);
    io::stdin()
        .take((PROVER_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|error| format!("read request: {error}"))?;
    let request = ProverRequestV1::decode(&input)
        .map_err(|error| format!("decode request: {error}"))?;
    let assignment = Assignment {
        public: PublicStatement::from_field_bytes(request.public_inputs)
            .map_err(|_| "invalid public statement".to_string())?,
        witness: SpendWitness::try_from(request.witness)
            .map_err(|_| "invalid witness".to_string())?,
    };
    let proof = ProvingProfile::new()
        .map_err(|_| "construct proving profile failed".to_string())?
        .prove_live(assignment)
        .map_err(|_| "proof generation failed".to_string())?;
    let transaction = TransactionV1 {
        genesis_sha256: request.genesis_sha256,
        deployment_id: request.deployment_id,
        public_inputs: request.public_inputs,
        proof,
    };
    let output = transaction
        .encode()
        .map_err(|error| format!("encode transaction: {error}"))?;
    io::stdout()
        .write_all(&output)
        .map_err(|error| format!("write transaction: {error}"))?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("shielded development prover failed: {error}");
        process::exit(1);
    }
}
