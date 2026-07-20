//! Windows implementation: Toolhelp module enumeration + ReadProcessMemory.

use super::{MemRegion, ProcessAccess};
use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    VirtualQueryEx,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

const WRAPPER_NODE: &str = "wrapper.node";

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Enumerate all PIDs that have `wrapper.node` among their loaded modules.
pub fn find_wrapper_node_pids() -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    // SAFETY: standard Toolhelp snapshot walk; handle is closed before return.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut pe);
        while ok != 0 {
            if process_has_wrapper(pe.th32ProcessID) {
                pids.push(pe.th32ProcessID);
            }
            ok = Process32NextW(snap, &mut pe);
        }
        CloseHandle(snap);
    }
    Ok(pids)
}

fn process_has_wrapper(pid: u32) -> bool {
    // SAFETY: module snapshot for one pid; handle closed before return. Access
    // failures (e.g. protected/system pids) simply yield an invalid snapshot,
    // which we treat as "no match".
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut me: MODULEENTRY32W = std::mem::zeroed();
        me.dwSize = size_of::<MODULEENTRY32W>() as u32;
        let mut found = false;
        let mut ok = Module32FirstW(snap, &mut me);
        while ok != 0 {
            let name = wide_to_string(&me.szModule);
            if name.eq_ignore_ascii_case(WRAPPER_NODE) {
                found = true;
                break;
            }
            ok = Module32NextW(snap, &mut me);
        }
        CloseHandle(snap);
        found
    }
}

/// Whether the current process token is elevated (Administrator).
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    const TOKEN_QUERY: u32 = 0x0008;

    // SAFETY: opens the current process token, queries elevation, closes it.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

pub struct PlatformAccess {
    handle: HANDLE,
}

// SAFETY: HANDLE is a raw pointer (hence !Send/!Sync by default), but a process
// handle opened for VM_READ is just a kernel object reference. ReadProcessMemory
// and VirtualQueryEx are thread-safe against the same handle, so sharing it
// across rayon worker threads for concurrent reads is sound.
unsafe impl Send for PlatformAccess {}
unsafe impl Sync for PlatformAccess {}

impl ProcessAccess for PlatformAccess {
    fn open(pid: u32) -> io::Result<Self> {
        // SAFETY: OpenProcess with read rights; the returned handle is stored and
        // closed in Drop.
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle.is_null() {
            let err = io::Error::last_os_error();
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "OpenProcess failed for pid {pid}: {err}. The target may be \
                     elevated or protected; run this tool as Administrator."
                ),
            ));
        }
        Ok(Self { handle })
    }

    fn regions(&self) -> io::Result<Vec<MemRegion>> {
        const READABLE: [u32; 6] = [
            PAGE_READONLY,
            PAGE_READWRITE,
            PAGE_WRITECOPY,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY,
        ];
        let mut regions = Vec::new();
        let mut addr: usize = 0;
        // SAFETY: repeated VirtualQueryEx over the target's address space.
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            while VirtualQueryEx(
                self.handle,
                addr as *const _,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) != 0
            {
                let base = mbi.BaseAddress as usize;
                let size = mbi.RegionSize;
                let committed = mbi.State == MEM_COMMIT;
                let guarded = mbi.Protect & PAGE_GUARD != 0;
                let readable = READABLE.contains(&(mbi.Protect & 0xff));
                if committed && !guarded && readable && size > 0 {
                    regions.push(MemRegion { base, size });
                }
                let next = base.checked_add(size);
                match next {
                    Some(n) if n > addr => addr = n,
                    _ => break,
                }
            }
        }
        Ok(regions)
    }

    fn read(&self, addr: usize, len: usize) -> io::Result<Vec<u8>> {
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        let mut buf = vec![0u8; len];
        let mut read_bytes: usize = 0;
        // SAFETY: reads into a buffer sized `len`; read_bytes reflects actual.
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                len,
                &mut read_bytes,
            )
        };
        if ok == 0 && read_bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(read_bytes);
        Ok(buf)
    }
}

impl Drop for PlatformAccess {
    fn drop(&mut self) {
        // SAFETY: handle was created by OpenProcess and is non-null here.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
