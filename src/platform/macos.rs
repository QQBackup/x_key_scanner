//! macOS implementation.
//!
//! IMPORTANT: this module has been written without a macOS device to test on.
//! The syscall surface is kept deliberately minimal and is documented so it can
//! be validated on real hardware (CI will at least confirm it compiles).
//!
//! Strategy, chosen to minimise the privileged (`task_for_pid`) surface:
//!   * QQ main-process discovery mirrors `nt_helper`: query
//!     `NSRunningApplication` by bundle id `com.tencent.qq` by default, or
//!     enumerate all PIDs via libproc and match the executable-path suffix
//!     `/QQ.app/Contents/MacOS/QQ` when headless. Neither needs `task_for_pid`.
//!   * Region enumeration for the scan uses `proc_pidinfo`
//!     (PROC_PIDREGIONINFO), which works for same-user / root targets and does
//!     NOT need `task_for_pid`.
//!   * Only reading memory uses `task_for_pid` + `mach_vm_read`, which require
//!     root (hence the tool asks to be run under `sudo`).

use super::{MemRegion, ProcessAccess};
use std::io;

// --- libproc FFI (self-declared for version independence) ------------------

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
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
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

/// Enumerate the QQ NT main process(es) — the process(es) that load
/// `wrapper.node`. On macOS that is the QQ main process, found via bundle id /
/// executable-path detection (see [`get_all_qq_processes`]).
pub fn find_wrapper_node_pids() -> io::Result<Vec<u32>> {
    get_all_qq_processes(None)
}

/// QQ main-process enumeration, ported from `nt_helper::injector::macos`.
///
/// Two mutually-exclusive paths (no automatic fallback, so a genuinely
/// not-running QQ isn't probed twice):
///   * `headless = false` (default): `NSRunningApplication` by bundle id
///     `com.tencent.qq`. Precise (survives renames), naturally multi-instance,
///     and never mixes in `QQ Helper (Renderer)` extension processes. Needs a
///     WindowServer/GUI session.
///   * `headless = true`: enumerate all PIDs via libproc and keep those whose
///     executable path ends with `/QQ.app/Contents/MacOS/QQ`.
pub fn get_all_qq_processes(headless: Option<bool>) -> io::Result<Vec<u32>> {
    Ok(if headless.unwrap_or(false) {
        libproc::qq_main_pids()
    } else {
        ns_running_application::qq_main_pids()
    })
}

/// libproc full PID enumeration + executable-path suffix matching. Needs no
/// entitlements (same level as `ps`); `proc_pidpath` returns 0 for zombies and
/// permission-less processes, which are skipped.
mod libproc {
    use std::ffi::{c_int, c_void};

    unsafe extern "C" {
        fn proc_listallpids(buffer: *mut c_int, buffersize: c_int) -> c_int;
        fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
    }

    /// Executable-path suffix of the QQ main process (measured on
    /// `/Applications/QQ.app`): helpers live under `Contents/Frameworks/QQ Helper*.app`.
    const QQ_MAIN_EXE_SUFFIX: &str = "/QQ.app/Contents/MacOS/QQ";

    pub fn qq_main_pids() -> Vec<u32> {
        // First pass returns the count, second pass fills the buffer; the extra
        // 16 slots tolerate processes spawned between the two calls.
        let count = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 {
            return Vec::new();
        }
        let mut pids = vec![0i32; count as usize + 16];
        let n = unsafe {
            proc_listallpids(
                pids.as_mut_ptr(),
                (pids.len() * std::mem::size_of::<c_int>()) as c_int,
            )
        };
        if n <= 0 {
            return Vec::new();
        }
        pids.truncate(n as usize);
        pids.into_iter()
            .map(|pid| pid as u32)
            .filter(|pid| is_qq_main_process(*pid))
            .collect()
    }

    fn is_qq_main_process(pid: u32) -> bool {
        let mut buf = [0u8; 4096];
        let len = unsafe {
            proc_pidpath(
                pid as c_int,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
            )
        };
        if len <= 0 {
            return false;
        }
        let end = buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(len as usize)
            .min(len as usize);
        let Ok(path) = std::str::from_utf8(&buf[..end]) else {
            return false;
        };
        path.ends_with(QQ_MAIN_EXE_SUFFIX)
    }
}

/// `NSRunningApplication.runningApplicationsWithBundleIdentifier:` direct query
/// for the main process. Hand-written minimal objc_msgSend FFI (zero new deps):
/// the class method returns every running instance for the bundle id in this
/// session; each is queried for `processIdentifier`. NSString is built via
/// CoreFoundation's `CFStringCreateWithCString` (toll-free bridged) and
/// released with `CFRelease`.
mod ns_running_application {
    use std::ffi::{CStr, c_char, c_int, c_void};

    const QQ_BUNDLE_ID: &CStr = c"com.tencent.qq";
    /// kCFStringEncodingUTF8
    const UTF8_ENCODING: u32 = 0x0800_0100;

    // objc_msgSend is variadic in C; each call site declares the fixed
    // signature it needs (pointer/integer params and returns agree under the
    // macOS ABI), hence the clashing extern declarations are intentional.
    #[allow(clashing_extern_declarations)]
    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> *const c_void;
        fn sel_registerName(name: *const c_char) -> *const c_void;
        #[link_name = "objc_msgSend"]
        fn msg_send1(obj: *const c_void, sel: *const c_void, arg: *const c_void) -> *const c_void;
        #[link_name = "objc_msgSend"]
        fn msg_send0_usize(obj: *const c_void, sel: *const c_void) -> usize;
        #[link_name = "objc_msgSend"]
        fn msg_send0_i32(obj: *const c_void, sel: *const c_void) -> c_int;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(
            alloc: *const c_void,
            c_str: *const c_char,
            encoding: u32,
        ) -> *const c_void;
        fn CFRelease(cf: *const c_void);
    }

    // NSRunningApplication lives in AppKit. Even for host processes that
    // wouldn't load it on their own (plain node/CLI), the class is registered
    // once the framework's dylib is pulled in by the linker.
    #[link(name = "AppKit", kind = "framework")]
    unsafe extern "C" {}

    fn sel(name: &'static CStr) -> *const c_void {
        unsafe { sel_registerName(name.as_ptr()) }
    }

    pub fn qq_main_pids() -> Vec<u32> {
        let cls = unsafe { objc_getClass(c"NSRunningApplication".as_ptr()) };
        if cls.is_null() {
            return Vec::new();
        }

        let bundle_id = unsafe {
            CFStringCreateWithCString(std::ptr::null(), QQ_BUNDLE_ID.as_ptr(), UTF8_ENCODING)
        };
        if bundle_id.is_null() {
            return Vec::new();
        }
        let apps = unsafe {
            msg_send1(
                cls,
                sel(c"runningApplicationsWithBundleIdentifier:"),
                bundle_id,
            )
        };
        unsafe { CFRelease(bundle_id) };
        if apps.is_null() {
            return Vec::new();
        }

        let count = unsafe { msg_send0_usize(apps, sel(c"count")) };
        let object_at_index = sel(c"objectAtIndex:");
        let process_identifier = sel(c"processIdentifier");

        let mut pids = Vec::with_capacity(count);
        for index in 0..count {
            let app = unsafe { msg_send1(apps, object_at_index, index as *const c_void) };
            if app.is_null() {
                continue;
            }
            let pid = unsafe { msg_send0_i32(app, process_identifier) };
            if pid > 0 {
                pids.push(pid as u32);
            }
        }
        pids
    }
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
