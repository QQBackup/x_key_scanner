//! Linux implementation: /proc maps enumeration + process_vm_readv.

use super::{MemRegion, ProcessAccess};
use std::io::{self, BufRead};

const WRAPPER_NODE: &str = "wrapper.node";

/// Enumerate PIDs whose `/proc/<pid>/maps` references `wrapper.node`.
pub fn find_wrapper_node_pids() -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if maps_has_wrapper(pid) {
            pids.push(pid);
        }
    }
    Ok(pids)
}

fn maps_has_wrapper(pid: u32) -> bool {
    let path = format!("/proc/{pid}/maps");
    let Ok(file) = std::fs::File::open(&path) else {
        return false;
    };
    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if line.contains(WRAPPER_NODE) {
            return true;
        }
    }
    false
}

pub struct PlatformAccess {
    pid: libc::pid_t,
}

impl ProcessAccess for PlatformAccess {
    fn open(pid: u32) -> io::Result<Self> {
        // Nothing to open up front; process_vm_readv operates on the pid. We
        // verify the process exists so failures surface early.
        let dir = format!("/proc/{pid}");
        if !std::path::Path::new(&dir).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("process {pid} not found under /proc"),
            ));
        }
        Ok(Self { pid: pid as libc::pid_t })
    }

    fn regions(&self) -> io::Result<Vec<MemRegion>> {
        let path = format!("/proc/{}/maps", self.pid);
        let file = std::fs::File::open(&path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "cannot read {path}: {e}. Reading another process's memory \
                     needs root (or CAP_SYS_PTRACE); check ptrace_scope."
                ),
            )
        })?;
        let mut regions = Vec::new();
        for line in io::BufReader::new(file).lines() {
            let Ok(line) = line else { break };
            // Format: "start-end perms offset dev inode pathname"
            let Some((range, rest)) = line.split_once(' ') else {
                continue;
            };
            let perms = rest.as_bytes();
            // perms[0] == 'r' means readable.
            if perms.first() != Some(&b'r') {
                continue;
            }
            let Some((start, end)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) else {
                continue;
            };
            if end > start {
                regions.push(MemRegion { base: start, size: end - start });
            }
        }
        Ok(regions)
    }

    fn read(&self, addr: usize, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: len,
        };
        // SAFETY: single local/remote iovec pair; buf is sized `len`.
        let n = unsafe { libc::process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(n as usize);
        Ok(buf)
    }
}
