//! macOS implementation.
//!
//! IMPORTANT: this module has been written without a macOS device to test on.
//! The syscall surface is kept deliberately minimal and is documented so it can
//! be validated on real hardware (CI will at least confirm it compiles).
//!
//! Strategy, chosen to minimise the privileged (`task_for_pid`) surface:
//!   * Process discovery + region enumeration use `proc_pidinfo`
//!     (PROC_PIDREGIONINFO) + `proc_regionfilename`. These work for same-user /
//!     root targets and do NOT need `task_for_pid`.
//!   * Only reading memory uses `task_for_pid` + `mach_vm_read`, which require
//!     root (hence the tool asks to be run under `sudo`).

use super::{MemRegion, ProcessAccess};
use std::io;

const WRAPPER_NODE: &str = "wrapper.node";

// --- libproc FFI (self-declared for version independence) ------------------

const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDREGIONINFO: libc::c_int = 7;
const VM_PROT_READ: u32 = 0x1;
const MAXPATHLEN: usize = 1024;

// proc_regioninfo, 96 bytes. We only read pri_protection (off 0), pri_address
// (off 80) and pri_size (off 88); the rest is laid out to get the size right.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcRegionInfo {
    pri_protection: u32,
    pri_max_protection: u32,
    pri_inheritance: u32,
    pri_flags: u32,
    pri_offset: u64,
    pri_behavior: u32,
    pri_user_wired_count: u32,
    pri_user_tag: u32,
    pri_pages_resident: u32,
    pri_pages_shared_now_private: u32,
    pri_pages_swapped_out: u32,
    pri_pages_dirtied: u32,
    pri_ref_count: u32,
    pri_shadow_depth: u32,
    pri_share_mode: u32,
    pri_private_pages_resident: u32,
    pri_shared_pages_resident: u32,
    pri_obj_id: u32,
    pri_depth: u32,
    pri_address: u64,
    pri_size: u64,
}

const _: () = assert!(size_of::<ProcRegionInfo>() == 96);

unsafe extern "C" {
    fn proc_listpids(
        r#type: u32,
        typeinfo: u32,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
    fn proc_regionfilename(
        pid: libc::c_int,
        address: u64,
        buffer: *mut libc::c_void,
        buffersize: u32,
    ) -> libc::c_int;
    fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void, buffersize: u32) -> libc::c_int;
    fn proc_name(pid: libc::c_int, buffer: *mut libc::c_void, buffersize: u32) -> libc::c_int;
}

// --- mach FFI (only for reading memory; needs root) ------------------------

type KernReturn = libc::c_int;
type MachPort = libc::c_uint;
type VmOffset = usize;
const KERN_SUCCESS: KernReturn = 0;

unsafe extern "C" {
    static mach_task_self_: MachPort;
    fn task_for_pid(target: MachPort, pid: libc::c_int, task: *mut MachPort) -> KernReturn;
    fn mach_vm_read(
        task: MachPort,
        address: u64,
        size: u64,
        data: *mut VmOffset,
        data_count: *mut u32,
    ) -> KernReturn;
    fn vm_deallocate(task: MachPort, address: VmOffset, size: usize) -> KernReturn;
}

/// Walk a pid's memory regions via proc_pidinfo. Returns (address, size,
/// protection) for each. Does not require task_for_pid.
fn walk_regions(pid: libc::c_int) -> Vec<(u64, u64, u32)> {
    let mut out = Vec::new();
    let mut addr: u64 = 0;
    loop {
        // SAFETY: proc_pidinfo fills a correctly-sized ProcRegionInfo or returns
        // <= 0 when no region at/after `addr` exists.
        let mut info: ProcRegionInfo = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDREGIONINFO,
                addr,
                &mut info as *mut _ as *mut libc::c_void,
                size_of::<ProcRegionInfo>() as libc::c_int,
            )
        };
        if rc <= 0 {
            break;
        }
        out.push((info.pri_address, info.pri_size, info.pri_protection));
        let next = info.pri_address.saturating_add(info.pri_size);
        if next <= addr {
            break;
        }
        addr = next;
        if out.len() > 1_000_000 {
            break; // safety valve
        }
    }
    out
}

fn region_path(pid: libc::c_int, address: u64) -> Option<String> {
    let mut buf = vec![0u8; MAXPATHLEN];
    // SAFETY: buffer is MAXPATHLEN bytes; return value is the path length.
    let n = unsafe {
        proc_regionfilename(pid, address, buf.as_mut_ptr() as *mut libc::c_void, MAXPATHLEN as u32)
    };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

/// The executable path of `pid` (one cheap syscall). Used to skip the expensive
/// per-region path lookups for processes that clearly aren't QQ.
fn pid_path(pid: libc::c_int) -> Option<String> {
    let mut buf = vec![0u8; MAXPATHLEN];
    // SAFETY: buffer is MAXPATHLEN bytes; return value is the path length.
    let n = unsafe {
        proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, MAXPATHLEN as u32)
    };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

/// The process name of `pid` (one cheap libproc call). Used to identify the QQ
/// process holding an account's database lock.
pub fn process_name(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; MAXPATHLEN];
    // SAFETY: buffer is MAXPATHLEN bytes; proc_name writes a NUL-terminated
    // string and returns its length.
    let n = unsafe {
        proc_name(pid as libc::c_int, buf.as_mut_ptr() as *mut libc::c_void, MAXPATHLEN as u32)
    };
    if n <= 0 {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(n as usize);
    String::from_utf8(buf[..end].to_vec()).ok()
}

/// Enumerate PIDs that have `wrapper.node` mapped.
pub fn find_wrapper_node_pids() -> io::Result<Vec<u32>> {
    // First pass: how many pids? proc_listpids with a null buffer returns the
    // needed byte count.
    // SAFETY: null buffer / 0 size is the documented "size query" form.
    let cap = unsafe { proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if cap <= 0 {
        return Err(io::Error::other(
            "proc_listpids returned no pids (are you running as root?)",
        ));
    }
    let count = cap as usize / size_of::<libc::c_int>();
    let mut pids = vec![0i32; count + 16];
    // SAFETY: buffer sized to hold `pids`.
    let n = unsafe {
        proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr() as *mut libc::c_void,
            (pids.len() * size_of::<libc::c_int>()) as libc::c_int,
        )
    };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    let got = n as usize / size_of::<libc::c_int>();
    pids.truncate(got);

    let mut matched = Vec::new();
    for &pid in &pids {
        if pid <= 0 {
            continue;
        }
        // Cheap pre-filter: one proc_pidpath call rules out the hundreds of
        // unrelated processes before we do the expensive per-region path walk.
        // wrapper.node only ever loads inside a QQ process, whose executable
        // path contains "QQ" (…/QQ.app/Contents/MacOS/QQ and its helpers).
        match pid_path(pid) {
            Some(p) if p.contains("QQ") => {}
            _ => continue,
        }
        let mut found = false;
        for (addr, _size, _prot) in walk_regions(pid) {
            if let Some(path) = region_path(pid, addr) {
                if path.contains(WRAPPER_NODE) {
                    found = true;
                    break;
                }
            }
        }
        if found {
            matched.push(pid as u32);
        }
    }
    Ok(matched)
}

pub struct PlatformAccess {
    pid: libc::c_int,
    task: MachPort,
}

impl ProcessAccess for PlatformAccess {
    fn open(pid: u32) -> io::Result<Self> {
        let pid = pid as libc::c_int;
        let mut task: MachPort = 0;
        // SAFETY: task_for_pid writes a task port on success.
        let kr = unsafe { task_for_pid(mach_task_self_, pid, &mut task) };
        if kr != KERN_SUCCESS {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "task_for_pid failed for pid {pid} (kern_return {kr}). Run with \
                     `sudo`. If it still fails, the target likely enables the \
                     hardened runtime and this macOS version won't grant a task \
                     port to root — memory scanning is not possible for it."
                ),
            ));
        }
        Ok(Self { pid, task })
    }

    fn regions(&self) -> io::Result<Vec<MemRegion>> {
        let mut regions = Vec::new();
        for (addr, size, prot) in walk_regions(self.pid) {
            if prot & VM_PROT_READ != 0 && size > 0 {
                regions.push(MemRegion { base: addr as usize, size: size as usize });
            }
        }
        Ok(regions)
    }

    fn read(&self, addr: usize, len: usize) -> io::Result<Vec<u8>> {
        let mut data: VmOffset = 0;
        let mut data_count: u32 = 0;
        // SAFETY: mach_vm_read allocates `data_count` bytes at `data` on success.
        let kr = unsafe {
            mach_vm_read(self.task, addr as u64, len as u64, &mut data, &mut data_count)
        };
        if kr != KERN_SUCCESS {
            return Err(io::Error::other(
                format!("mach_vm_read failed at {addr:#x} (kern_return {kr})"),
            ));
        }
        // SAFETY: mach handed us `data_count` valid bytes at `data`; we copy them
        // out and then hand the page(s) back with vm_deallocate.
        let out = unsafe {
            let slice = std::slice::from_raw_parts(data as *const u8, data_count as usize);
            let v = slice.to_vec();
            vm_deallocate(mach_task_self_, data, data_count as usize);
            v
        };
        Ok(out)
    }
}
