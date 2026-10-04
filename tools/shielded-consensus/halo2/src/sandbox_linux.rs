#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("the shielded verifier worker requires x86_64 Linux seccomp");

use std::{ffi::CString, io};

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

pub const DENIED_SYSCALLS: [libc::c_long; 18] = [
    libc::SYS_open,
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_creat,
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_io_uring_setup,
];

fn statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k: value }
}

fn jump(code: u16, value: u32, true_skip: u8, false_skip: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt: true_skip, jf: false_skip, k: value }
}

fn errno_is_permission_denied() -> bool {
    io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub fn close_non_stdio() -> Result<(), ()> {
    let result = unsafe { libc::syscall(libc::SYS_close_range, 2u32, u32::MAX, 0u32) };
    if result == 0 { return Ok(()); }
    let error = io::Error::last_os_error().raw_os_error();
    if error != Some(libc::ENOSYS) && error != Some(libc::EINVAL) {
        return Err(());
    }
    let maximum = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if maximum < 0 { return Err(()); }
    for descriptor in 2..maximum {
        unsafe { libc::close(descriptor as libc::c_int); }
    }
    Ok(())
}

pub fn install_filter() -> Result<(), ()> {
    let mut filter = Vec::with_capacity(5 + DENIED_SYSCALLS.len() * 2);
    filter.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET));
    filter.push(jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0));
    filter.push(statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    filter.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));
    for syscall in DENIED_SYSCALLS {
        filter.push(jump(BPF_JMP_JEQ_K, syscall as u32, 0, 1));
        filter.push(statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    filter.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len()).map_err(|_| ())?,
        filter: filter.as_mut_ptr(),
    };
    let no_new_privileges = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if no_new_privileges != 0 { return Err(()); }
    let installed = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &program as *const libc::sock_fprog,
        )
    };
    if installed != 0 { return Err(()); }
    Ok(())
}

pub fn probe_denials() -> Result<(), ()> {
    let path = CString::new("/proc/self/status").map_err(|_| ())?;
    let opened = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    if opened != -1 || !errno_is_permission_denied() { return Err(()); }
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if socket != -1 || !errno_is_permission_denied() { return Err(()); }
    Ok(())
}

pub fn install_worker_sandbox() -> Result<(), ()> {
    close_non_stdio()?;
    install_filter()?;
    probe_denials()
}

pub fn probe_all_denied_syscalls() -> Result<(), ()> {
    for syscall in DENIED_SYSCALLS {
        let result = unsafe { libc::syscall(syscall, 0, 0, 0, 0, 0, 0) };
        if result != -1 || !errno_is_permission_denied() { return Err(()); }
    }
    let no_new_privileges = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privileges != 1 { return Err(()); }
    Ok(())
}
