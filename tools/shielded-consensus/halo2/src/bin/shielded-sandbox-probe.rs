use std::{io::{self, Write}, process};

use shielded_consensus_halo2::sandbox_linux::{install_filter, probe_all_denied_syscalls};

fn main() {
    if install_filter().is_err() || probe_all_denied_syscalls().is_err() {
        process::exit(1);
    }
    if io::stdout().write_all(b"SANDBOX_OK\n").is_err() {
        process::exit(1);
    }
}
