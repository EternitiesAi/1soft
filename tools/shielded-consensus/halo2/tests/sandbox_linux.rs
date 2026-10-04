#![cfg(feature = "worker")]

use std::process::Command;

#[test]
fn seccomp_denies_every_pinned_syscall_and_sets_no_new_privs() {
    let output = Command::new(env!("CARGO_BIN_EXE_shielded-sandbox-probe"))
        .output()
        .expect("run sandbox probe");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, b"SANDBOX_OK\n");
    assert!(output.stderr.is_empty());

    let policy = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../profile/sandbox-policy-v1.json"),
    ).unwrap();
    for syscall in [
        "open", "openat", "openat2", "creat", "socket", "socketpair", "connect",
        "bind", "listen", "accept", "accept4", "execve", "execveat", "fork",
        "vfork", "clone", "clone3", "io_uring_setup",
    ] {
        assert!(policy.contains(&format!("\"{syscall}\"")), "missing {syscall}");
    }
}
