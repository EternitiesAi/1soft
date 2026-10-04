use std::{
    env,
    fs::OpenOptions,
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use privacy_proof_benchmark_halo2::{run_benchmark, BenchmarkConfig};

fn take_value(arguments: &[String], index: &mut usize) -> Result<String> {
    *index += 1;
    arguments
        .get(*index)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("invalid benchmark arguments"))
}

fn parse() -> Result<(PathBuf, BenchmarkConfig)> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let mut report = None;
    let mut commit = None;
    let mut tree = None;
    let mut circuit_digest = None;
    let mut iterations = 3usize;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--report" if report.is_none() => {
                report = Some(PathBuf::from(take_value(&arguments, &mut index)?));
            }
            "--commit" if commit.is_none() => {
                commit = Some(take_value(&arguments, &mut index)?);
            }
            "--tree" if tree.is_none() => {
                tree = Some(take_value(&arguments, &mut index)?);
            }
            "--circuit-digest" if circuit_digest.is_none() => {
                circuit_digest = Some(take_value(&arguments, &mut index)?);
            }
            "--iterations" => {
                iterations = take_value(&arguments, &mut index)?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid benchmark arguments"))?;
            }
            _ => bail!("invalid benchmark arguments"),
        }
        index += 1;
    }
    let report = report.ok_or_else(|| anyhow::anyhow!("invalid benchmark arguments"))?;
    let config = BenchmarkConfig {
        commit: commit.ok_or_else(|| anyhow::anyhow!("invalid benchmark arguments"))?,
        tree: tree.ok_or_else(|| anyhow::anyhow!("invalid benchmark arguments"))?,
        circuit_digest: circuit_digest
            .ok_or_else(|| anyhow::anyhow!("invalid benchmark arguments"))?,
        iterations,
    };
    config.validate()?;
    Ok((report, config))
}

fn execute() -> Result<()> {
    let (report_path, config) = parse()?;
    let mut report = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&report_path)
        .context("could not exclusively create a new receipt file")?;

    let iterations = config.iterations;
    let receipt = run_benchmark(config)?;
    serde_json::to_writer(&mut report, &receipt)
        .context("could not write benchmark receipt")?;
    report.write_all(b"\n")?;
    report.sync_all().context("could not synchronize benchmark receipt")?;
    drop(report);

    serde_json::to_writer(
        io::stdout(),
        &serde_json::json!({
            "status": "passed",
            "cases": receipt.cases.len(),
            "iterations": iterations,
        }),
    )?;
    println!();
    Ok(())
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
