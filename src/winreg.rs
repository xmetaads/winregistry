//! Thin, safe wrapper over the Win32 registry API.
//!
//! Two rules this module exists to enforce:
//!
//! 1. **WOW64 view is always explicit.** On 64-bit Windows a 32-bit process is
//!    silently redirected to `Software\WOW6432Node`. Every open/create here takes
//!    an explicit `KEY_WOW64_64KEY` / `KEY_WOW64_32KEY` bit so behaviour never
//!    depends on how the binary happened to be built.
//! 2. **`RegLoadAppKeyW` is a first-class root.** It mounts a hive file as a
//!    private, process-scoped key *without* `SeRestorePrivilege` - i.e. without
//!    admin - unlike `RegLoadKey`/`reg load`. Everything downstream (export,
//!    apply, undo) is written against `&RegKey`, so it works identically on the
//!    live hives and on a mounted file.

// These names mirror the Win32 SDK exactly so the FFI declarations can be
// diffed against MSDN. Renaming them to satisfy a style lint would make that
// harder for no benefit.
#![allow(non_snake_case, clippy::upper_case_acronyms)]

use std::ffi::c_void;
use std::fmt;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

pub type HKEY = *mut c_void;
type HANDLE = *mut c_void;
pub type LSTATUS = i32;

pub const ERROR_SUCCESS: LSTATUS = 0;
pub const ERROR_FILE_NOT_FOUND: LSTATUS = 2;
pub const ERROR_ACCESS_DENIED: LSTATUS = 5;
pub const ERROR_INVALID_HANDLE: LSTATUS = 6;
pub const ERROR_INVALID_PARAMETER: LSTATUS = 87;
pub const ERROR_SHARING_VIOLATION: LSTATUS = 32;
pub const ERROR_MORE_DATA: LSTATUS = 234;
pub const ERROR_NO_MORE_ITEMS: LSTATUS = 259;
pub const ERROR_BADDB: LSTATUS = 1009;
pub const ERROR_NO_UNICODE_TRANSLATION: LSTATUS = 1113;

// The full set of access rights is kept together as documentation of the API
// surface; not all of them are exercised by the current command set.
#[allow(dead_code)]
pub const KEY_QUERY_VALUE: u32 = 0x0001;
pub const KEY_SET_VALUE: u32 = 0x0002;
pub const KEY_CREATE_SUB_KEY: u32 = 0x0004;
pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
pub const KEY_NOTIFY: u32 = 0x0010;
pub const KEY_READ: u32 = 0x0002_0019;
pub const KEY_WRITE: u32 = 0x0002_0006;
#[allow(dead_code)]
pub const KEY_ALL_ACCESS: u32 = 0x000F_003F;
pub const KEY_WOW64_64KEY: u32 = 0x0100;
pub const KEY_WOW64_32KEY: u32 = 0x0200;
#[allow(dead_code)]
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;

/// `RegLoadAppKeyW` option: hold the hive exclusively for this process.
pub const REG_PROCESS_APPKEY: u32 = 0x0000_0001;

const fn predefined(v: usize) -> HKEY {
    v as HKEY
}
pub fn hkey_classes_root() -> HKEY {
    predefined(0x8000_0000)
}
pub fn hkey_current_user() -> HKEY {
    predefined(0x8000_0001)
}
pub fn hkey_local_machine() -> HKEY {
    predefined(0x8000_0002)
}
pub fn hkey_users() -> HKEY {
    predefined(0x8000_0003)
}
pub fn hkey_current_config() -> HKEY {
    predefined(0x8000_0005)
}

#[repr(C)]
struct FILETIME {
    lo: u32,
    hi: u32,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegConnectRegistryW(machine: *const u16, key: HKEY, out: *mut HKEY) -> LSTATUS;
    fn RegOpenKeyExW(k: HKEY, sub: *const u16, opts: u32, sam: u32, out: *mut HKEY) -> LSTATUS;
    fn RegCreateKeyExW(
        k: HKEY,
        sub: *const u16,
        reserved: u32,
        class: *const u16,
        options: u32,
        sam: u32,
        sa: *const c_void,
        out: *mut HKEY,
        disposition: *mut u32,
    ) -> LSTATUS;
    fn RegCloseKey(k: HKEY) -> LSTATUS;
    fn RegFlushKey(k: HKEY) -> LSTATUS;
    fn RegSetValueExW(
        k: HKEY,
        name: *const u16,
        reserved: u32,
        ty: u32,
        data: *const u8,
        cb: u32,
    ) -> LSTATUS;
    fn RegQueryValueExW(
        k: HKEY,
        name: *const u16,
        reserved: *mut u32,
        ty: *mut u32,
        data: *mut u8,
        cb: *mut u32,
    ) -> LSTATUS;
    fn RegEnumKeyExW(
        k: HKEY,
        index: u32,
        name: *mut u16,
        cch: *mut u32,
        reserved: *mut u32,
        class: *mut u16,
        cch_class: *mut u32,
        ft: *mut FILETIME,
    ) -> LSTATUS;
    fn RegEnumValueW(
        k: HKEY,
        index: u32,
        name: *mut u16,
        cch: *mut u32,
        reserved: *mut u32,
        ty: *mut u32,
        data: *mut u8,
        cb: *mut u32,
    ) -> LSTATUS;
    fn RegDeleteKeyExW(k: HKEY, sub: *const u16, sam: u32, reserved: u32) -> LSTATUS;
    fn RegDeleteValueW(k: HKEY, name: *const u16) -> LSTATUS;
    fn RegDeleteTreeW(k: HKEY, sub: *const u16) -> LSTATUS;
    fn RegLoadAppKeyW(
        file: *const u16,
        out: *mut HKEY,
        sam: u32,
        options: u32,
        reserved: u32,
    ) -> LSTATUS;
    fn RegNotifyChangeKeyValue(
        k: HKEY,
        watch_subtree: i32,
        filter: u32,
        event: HANDLE,
        asynchronous: i32,
    ) -> LSTATUS;
    fn GetSecurityInfo(
        handle: HANDLE,
        object_type: u32,
        security_info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor: *const c_void,
        revision: u32,
        security_info: u32,
        text: *mut *mut u16,
        length: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *mut u8, text: *mut *mut u16) -> i32;
    fn GetSecurityDescriptorControl(
        descriptor: *const c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateEventW(
        attributes: *const c_void,
        manual_reset: i32,
        initial_state: i32,
        name: *const u16,
    ) -> HANDLE;
    fn WaitForMultipleObjects(
        count: u32,
        handles: *const HANDLE,
        wait_all: i32,
        milliseconds: u32,
    ) -> u32;
    fn CloseHandle(handle: HANDLE) -> i32;
    fn GetLastError() -> u32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

const REG_NOTIFY_CHANGE_NAME: u32 = 0x0000_0001;
const REG_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x0000_0002;
const REG_NOTIFY_CHANGE_LAST_SET: u32 = 0x0000_0004;
const REG_NOTIFY_CHANGE_SECURITY: u32 = 0x0000_0008;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const SE_REGISTRY_KEY: u32 = 4;
const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const SDDL_REVISION_1: u32 = 1;
const SE_DACL_PROTECTED: u16 = 0x1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: LSTATUS,
    pub op: &'static str,
    pub target: String,
}

impl Error {
    pub fn is_access_denied(&self) -> bool {
        self.code == ERROR_ACCESS_DENIED
    }
    pub fn is_not_found(&self) -> bool {
        self.code == ERROR_FILE_NOT_FOUND
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hint = match self.code {
            ERROR_FILE_NOT_FOUND => "key or value does not exist",
            ERROR_ACCESS_DENIED => "access denied (this build never elevates - see `regx probe`)",
            ERROR_SHARING_VIOLATION => "the hive file is already loaded or open in another process",
            ERROR_BADDB => "the file is not a valid registry hive",
            ERROR_NO_UNICODE_TRANSLATION => {
                "registry name contains malformed UTF-16 and cannot be represented safely"
            }
            ERROR_INVALID_HANDLE => "invalid handle",
            ERROR_INVALID_PARAMETER => "invalid parameter",
            _ => "",
        };
        // Plain display, not `{:?}`: a registry path is full of backslashes and
        // Debug escaping turns every one of them into `\\`.
        if hint.is_empty() {
            write!(
                f,
                "{} failed on {} (error {})",
                self.op, self.target, self.code
            )
        } else {
            write!(
                f,
                "{} failed on {}: {hint} (error {})",
                self.op, self.target, self.code
            )
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn checked_subkey(sub: &str, op: &'static str, target: &str) -> Result<Vec<u16>> {
    if sub.contains('\0') {
        return Err(invalid_name(op, target, "subkey contains an embedded NUL"));
    }
    if sub.chars().any(forbidden_name_control) {
        return Err(invalid_name(
            op,
            target,
            "subkey contains a control character",
        ));
    }
    if sub
        .split('\\')
        .any(|component| component.encode_utf16().count() > 255)
    {
        return Err(invalid_name(
            op,
            target,
            "subkey component exceeds 255 UTF-16 code units",
        ));
    }
    Ok(wide(sub))
}

fn checked_value_name(name: &str, op: &'static str, target: &str) -> Result<Vec<u16>> {
    if name.contains('\0') {
        return Err(invalid_name(
            op,
            target,
            "value name contains an embedded NUL",
        ));
    }
    if name.chars().any(forbidden_name_control) {
        return Err(invalid_name(
            op,
            target,
            "value name contains a control character",
        ));
    }
    if name.encode_utf16().count() > 16_383 {
        return Err(invalid_name(
            op,
            target,
            "value name exceeds 16,383 UTF-16 code units",
        ));
    }
    Ok(wide(name))
}

fn forbidden_name_control(character: char) -> bool {
    let code = character as u32;
    code < 0x20 || code == 0x7f
}

fn invalid_name(op: &'static str, target: &str, reason: &str) -> Error {
    Error {
        code: ERROR_INVALID_PARAMETER,
        op,
        target: format!("{target} ({reason})"),
    }
}

fn wide_path(p: &Path) -> Vec<u16> {
    let mut v: Vec<u16> = p.as_os_str().encode_wide().collect();
    v.push(0);
    v
}

/// Which WOW64 view an operation targets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum View {
    Native,
    Bits32,
    Bits64,
}

impl View {
    pub fn flag(self) -> u32 {
        match self {
            View::Native => 0,
            View::Bits32 => KEY_WOW64_32KEY,
            View::Bits64 => KEY_WOW64_64KEY,
        }
    }
}

/// An owned registry key handle. Predefined roots are borrowed, never closed.
pub struct RegKey {
    h: HKEY,
    owned: bool,
    /// Human-readable path, used only for error messages.
    label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityInfo {
    pub owner_sid: String,
    pub sddl: String,
    pub inheritance_enabled: bool,
}

impl RegKey {
    /// Borrow a predefined root (HKCU, HKLM, ...). Never closed on drop.
    pub fn predefined(h: HKEY, label: &str) -> RegKey {
        RegKey {
            h,
            owned: false,
            label: label.to_string(),
        }
    }

    /// Connect to one predefined hive on another Windows computer.
    ///
    /// Callers deliberately expose this only through read commands. The
    /// returned handle itself is technically capable of writes when the remote
    /// ACL permits them, so keeping mutation commands away from it is the
    /// safety boundary.
    pub fn connect(computer: &str, root: HKEY, root_label: &str) -> Result<RegKey> {
        let computer = normalize_computer(computer);
        if computer.contains('\0') {
            return Err(invalid_name(
                "RegConnectRegistry",
                root_label,
                "computer name contains an embedded NUL",
            ));
        }
        let w = wide(&computer);
        let mut out: HKEY = std::ptr::null_mut();
        // SAFETY: `w` is NUL-terminated and outlives the call; `out` is a valid
        // result slot. `root` is one of the predefined handles accepted by
        // RegConnectRegistryW.
        let rc = unsafe { RegConnectRegistryW(w.as_ptr(), root, &mut out) };
        let label = format!("{computer}\\{root_label}");
        if rc != ERROR_SUCCESS {
            return Err(Error {
                code: rc,
                op: "RegConnectRegistry",
                target: label,
            });
        }
        Ok(RegKey {
            h: out,
            owned: true,
            label,
        })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn open(&self, sub: &str, sam: u32, view: View) -> Result<RegKey> {
        let w = checked_subkey(sub, "RegOpenKeyEx", &self.label)?;
        let mut out: HKEY = std::ptr::null_mut();
        // SAFETY: `w` is NUL-terminated and outlives the call; `out` is a valid
        // writable slot for the returned handle.
        let rc = unsafe {
            RegOpenKeyExW(
                self.h,
                if sub.is_empty() {
                    std::ptr::null()
                } else {
                    w.as_ptr()
                },
                0,
                sam | view.flag(),
                &mut out,
            )
        };
        self.wrap(rc, "RegOpenKeyEx", sub, out)
    }

    /// Create the key (and any missing parents). Returns `(key, created)` where
    /// `created` distinguishes REG_CREATED_NEW_KEY from REG_OPENED_EXISTING_KEY -
    /// the undo engine needs this to know whether to delete the key on rollback.
    pub fn create(&self, sub: &str, sam: u32, view: View) -> Result<(RegKey, bool)> {
        let w = checked_subkey(sub, "RegCreateKeyEx", &self.label)?;
        let mut out: HKEY = std::ptr::null_mut();
        let mut disp: u32 = 0;
        // SAFETY: as above; `class`/`sa` are optional and passed as null.
        let rc = unsafe {
            RegCreateKeyExW(
                self.h,
                w.as_ptr(),
                0,
                std::ptr::null(),
                0,
                sam | view.flag(),
                std::ptr::null(),
                &mut out,
                &mut disp,
            )
        };
        let key = self.wrap(rc, "RegCreateKeyEx", sub, out)?;
        Ok((key, disp == 1)) // REG_CREATED_NEW_KEY == 1
    }

    fn wrap(&self, rc: LSTATUS, op: &'static str, sub: &str, out: HKEY) -> Result<RegKey> {
        let target = self.child_label(sub);
        if rc != ERROR_SUCCESS {
            return Err(Error {
                code: rc,
                op,
                target,
            });
        }
        Ok(RegKey {
            h: out,
            owned: true,
            label: target,
        })
    }

    fn child_label(&self, sub: &str) -> String {
        if sub.is_empty() {
            self.label.clone()
        } else {
            format!("{}\\{}", self.label, sub)
        }
    }

    pub fn set_value(&self, name: &str, ty: u32, data: &[u8]) -> Result<()> {
        let w = checked_value_name(name, "RegSetValueEx", &self.label)?;
        let data_len = u32::try_from(data.len()).map_err(|_| Error {
            code: ERROR_INVALID_PARAMETER,
            op: "RegSetValueEx",
            target: format!("{name} (value data exceeds the Win32 u32 length limit)"),
        })?;
        // SAFETY: `data`'s pointer/length describe the same slice; an empty slice
        // still yields a valid (dangling but unread) pointer because cb is 0.
        let rc = unsafe { RegSetValueExW(self.h, w.as_ptr(), 0, ty, data.as_ptr(), data_len) };
        self.status(rc, "RegSetValueEx", name)
    }

    /// Returns `(type, bytes)`, or `None` when the value does not exist.
    pub fn get_value(&self, name: &str) -> Result<Option<(u32, Vec<u8>)>> {
        let w = checked_value_name(name, "RegQueryValueEx", &self.label)?;
        let mut ty: u32 = 0;
        let mut cb: u32 = 0;
        // SAFETY: probe call with a null data pointer is the documented way to
        // learn the required buffer size.
        let rc = unsafe {
            RegQueryValueExW(
                self.h,
                w.as_ptr(),
                std::ptr::null_mut(),
                &mut ty,
                std::ptr::null_mut(),
                &mut cb,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA {
            return Err(Error {
                code: rc,
                op: "RegQueryValueEx",
                target: self.child_label(name),
            });
        }
        let mut buf = vec![0u8; cb as usize];
        // A value can grow between the two calls; retry once on ERROR_MORE_DATA.
        for _ in 0..2 {
            let mut len = cb;
            // SAFETY: `buf` has `len` writable bytes.
            let rc = unsafe {
                RegQueryValueExW(
                    self.h,
                    w.as_ptr(),
                    std::ptr::null_mut(),
                    &mut ty,
                    if len == 0 {
                        std::ptr::null_mut()
                    } else {
                        buf.as_mut_ptr()
                    },
                    &mut len,
                )
            };
            match rc {
                ERROR_SUCCESS => {
                    buf.truncate(len as usize);
                    return Ok(Some((ty, buf)));
                }
                ERROR_MORE_DATA => {
                    cb = len;
                    buf = vec![0u8; cb as usize];
                }
                ERROR_FILE_NOT_FOUND => return Ok(None),
                _ => {
                    return Err(Error {
                        code: rc,
                        op: "RegQueryValueEx",
                        target: self.child_label(name),
                    })
                }
            }
        }
        Err(Error {
            code: ERROR_MORE_DATA,
            op: "RegQueryValueEx",
            target: self.child_label(name),
        })
    }

    pub fn delete_value(&self, name: &str) -> Result<()> {
        let w = checked_value_name(name, "RegDeleteValue", &self.label)?;
        // SAFETY: NUL-terminated name pointer.
        let rc = unsafe { RegDeleteValueW(self.h, w.as_ptr()) };
        self.status(rc, "RegDeleteValue", name)
    }

    /// Delete an empty subkey. Fails if it still has children - use
    /// [`RegKey::delete_tree`] for the recursive form.
    pub fn delete_key(&self, sub: &str, view: View) -> Result<()> {
        let w = checked_subkey(sub, "RegDeleteKeyEx", &self.label)?;
        // SAFETY: NUL-terminated subkey pointer.
        let rc = unsafe { RegDeleteKeyExW(self.h, w.as_ptr(), view.flag(), 0) };
        self.status(rc, "RegDeleteKeyEx", sub)
    }

    pub fn delete_tree(&self, sub: &str) -> Result<()> {
        let w = checked_subkey(sub, "RegDeleteTree", &self.label)?;
        // SAFETY: NUL-terminated subkey pointer; empty string means "this key's
        // contents", which RegDeleteTreeW accepts as a null pointer.
        let rc = unsafe {
            RegDeleteTreeW(
                self.h,
                if sub.is_empty() {
                    std::ptr::null()
                } else {
                    w.as_ptr()
                },
            )
        };
        self.status(rc, "RegDeleteTree", sub)
    }

    pub fn subkeys(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut idx = 0u32;
        loop {
            // 256 accounts for the 255-character key-name limit plus NUL.
            let mut buf = vec![0u16; 256];
            let mut cch = buf.len() as u32;
            // SAFETY: `buf` has `cch` writable UTF-16 units.
            let rc = unsafe {
                RegEnumKeyExW(
                    self.h,
                    idx,
                    buf.as_mut_ptr(),
                    &mut cch,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            match rc {
                ERROR_SUCCESS => {
                    out.push(decode_registry_name(
                        &buf[..cch as usize],
                        "RegEnumKeyEx",
                        &self.label,
                    )?);
                    idx += 1;
                }
                ERROR_NO_MORE_ITEMS => return Ok(out),
                _ => {
                    return Err(Error {
                        code: rc,
                        op: "RegEnumKeyEx",
                        target: self.label.clone(),
                    })
                }
            }
        }
    }

    /// Enumerate `(name, type, data)` triples. Name is `""` for the default value.
    pub fn values(&self) -> Result<Vec<(String, u32, Vec<u8>)>> {
        let mut out = Vec::new();
        let mut idx = 0u32;
        loop {
            // 16384 = the 16,383-character value-name limit plus NUL.
            let mut name = vec![0u16; 16_384];
            let mut cch = name.len() as u32;
            let mut ty = 0u32;
            let mut cb = 0u32;
            // SAFETY: probe for the data size while reading the name in full.
            let rc = unsafe {
                RegEnumValueW(
                    self.h,
                    idx,
                    name.as_mut_ptr(),
                    &mut cch,
                    std::ptr::null_mut(),
                    &mut ty,
                    std::ptr::null_mut(),
                    &mut cb,
                )
            };
            match rc {
                ERROR_SUCCESS | ERROR_MORE_DATA => {
                    let n =
                        decode_registry_name(&name[..cch as usize], "RegEnumValue", &self.label)?;
                    // Re-read by name: RegEnumValueW's own data buffer has awkward
                    // resize semantics, and get_value already handles growth.
                    let data = self.get_value(&n)?.map(|(_, d)| d).unwrap_or_default();
                    out.push((n, ty, data));
                    idx += 1;
                }
                ERROR_NO_MORE_ITEMS => return Ok(out),
                _ => {
                    return Err(Error {
                        code: rc,
                        op: "RegEnumValue",
                        target: self.label.clone(),
                    })
                }
            }
        }
    }

    /// Force pending writes to disk. Required before dropping an app-hive key if
    /// the caller cares about durability.
    pub fn flush(&self) -> Result<()> {
        // SAFETY: `self.h` is a live key handle for the lifetime of `self`.
        let rc = unsafe { RegFlushKey(self.h) };
        self.status(rc, "RegFlushKey", "")
    }

    /// Wait for a change notification without polling. Returns `false` on
    /// timeout and re-arms on every call, as required by the Win32 API.
    pub fn wait_for_change(self, recursive: bool, timeout_ms: u32) -> Result<bool> {
        wait_for_any_change(vec![self], recursive, timeout_ms).map(|index| index.is_some())
    }

    pub fn security_info(&self) -> Result<SecurityInfo> {
        let requested =
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut owner = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: output pointers are writable and the returned descriptor is
        // released with LocalFree below, per GetSecurityInfo's contract.
        let rc = unsafe {
            GetSecurityInfo(
                self.h,
                SE_REGISTRY_KEY,
                requested,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if rc != ERROR_SUCCESS as u32 {
            return Err(Error {
                code: rc as i32,
                op: "GetSecurityInfo",
                target: self.label.clone(),
            });
        }

        let converted = (|| {
            let owner_sid =
                local_wide_string(|out| unsafe { ConvertSidToStringSidW(owner.cast(), out) })
                    .ok_or_else(|| Error {
                        code: unsafe { GetLastError() } as i32,
                        op: "ConvertSidToStringSid",
                        target: self.label.clone(),
                    })?;
            let sddl = local_wide_string(|out| unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor,
                    SDDL_REVISION_1,
                    requested,
                    out,
                    std::ptr::null_mut(),
                )
            })
            .ok_or_else(|| Error {
                code: unsafe { GetLastError() } as i32,
                op: "ConvertSecurityDescriptorToStringSecurityDescriptor",
                target: self.label.clone(),
            })?;
            let mut control = 0u16;
            let mut revision = 0u32;
            let ok =
                unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
            if ok == 0 {
                return Err(Error {
                    code: unsafe { GetLastError() } as i32,
                    op: "GetSecurityDescriptorControl",
                    target: self.label.clone(),
                });
            }
            Ok(SecurityInfo {
                owner_sid,
                sddl,
                inheritance_enabled: control & SE_DACL_PROTECTED == 0,
            })
        })();
        unsafe {
            LocalFree(descriptor);
        }
        converted
    }

    fn status(&self, rc: LSTATUS, op: &'static str, target: &str) -> Result<()> {
        if rc == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(Error {
                code: rc,
                op,
                target: self.child_label(target),
            })
        }
    }
}

/// Arm several registry notifications and wait for the first one without
/// polling. The returned index identifies the signalled key; `None` is timeout.
pub fn wait_for_any_change(
    keys: Vec<RegKey>,
    recursive: bool,
    timeout_ms: u32,
) -> Result<Option<usize>> {
    if keys.is_empty() || keys.len() > 64 {
        return Err(Error {
            code: 87,
            op: "WaitForMultipleObjects",
            target: format!("{} registry notification handle(s)", keys.len()),
        });
    }
    let target = keys
        .iter()
        .map(|key| key.label.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let mut events = Vec::with_capacity(keys.len());
    for _ in &keys {
        // SAFETY: null attributes/name request an unnamed event owned below.
        let event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if event.is_null() {
            let code = unsafe { GetLastError() } as i32;
            drop(keys);
            for event in events {
                unsafe {
                    CloseHandle(event);
                }
            }
            return Err(Error {
                code,
                op: "CreateEvent",
                target,
            });
        }
        events.push(event);
    }
    let filter = REG_NOTIFY_CHANGE_NAME
        | REG_NOTIFY_CHANGE_ATTRIBUTES
        | REG_NOTIFY_CHANGE_LAST_SET
        | REG_NOTIFY_CHANGE_SECURITY;
    for (key, event) in keys.iter().zip(events.iter()) {
        // SAFETY: both handles remain live through the wait and cleanup.
        let notify = unsafe { RegNotifyChangeKeyValue(key.h, recursive as i32, filter, *event, 1) };
        if notify != ERROR_SUCCESS {
            drop(keys);
            for event in events {
                unsafe {
                    CloseHandle(event);
                }
            }
            return Err(Error {
                code: notify,
                op: "RegNotifyChangeKeyValue",
                target,
            });
        }
    }
    // SAFETY: the event slice is non-empty, contains `count` live handles, and
    // remains allocated until after this call returns.
    let event_count = events.len() as u32;
    let waited = unsafe { WaitForMultipleObjects(event_count, events.as_ptr(), 0, timeout_ms) };
    // Closing watched keys cancels every still-pending registration. Do this
    // before closing the events so the kernel can never signal a stale handle.
    drop(keys);
    for event in events {
        unsafe {
            CloseHandle(event);
        }
    }
    if waited == WAIT_TIMEOUT {
        Ok(None)
    } else if waited < WAIT_OBJECT_0 + event_count {
        Ok(Some((waited - WAIT_OBJECT_0) as usize))
    } else {
        Err(Error {
            code: waited as i32,
            op: "WaitForMultipleObjects",
            target,
        })
    }
}

fn decode_registry_name(units: &[u16], op: &'static str, target: &str) -> Result<String> {
    String::from_utf16(units).map_err(|_| Error {
        code: ERROR_NO_UNICODE_TRANSLATION,
        op,
        target: target.to_string(),
    })
}

fn normalize_computer(computer: &str) -> String {
    let trimmed = computer.trim().trim_start_matches('\\');
    format!(r"\\{trimmed}")
}

fn local_wide_string(convert: impl FnOnce(*mut *mut u16) -> i32) -> Option<String> {
    let mut raw = std::ptr::null_mut();
    if convert(&mut raw) == 0 || raw.is_null() {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: conversion APIs return a NUL-terminated LocalAlloc string.
    unsafe {
        while *raw.add(len) != 0 {
            len += 1;
        }
    }
    let text = unsafe { String::from_utf16(std::slice::from_raw_parts(raw, len)).ok() };
    unsafe {
        LocalFree(raw.cast());
    }
    text
}

impl fmt::Debug for RegKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegKey({:?})", self.label)
    }
}

impl Drop for RegKey {
    fn drop(&mut self) {
        if self.owned && !self.h.is_null() {
            // SAFETY: handle was produced by Reg*KeyEx / RegLoadAppKeyW and is
            // closed exactly once because `owned` is only true for owned handles.
            unsafe {
                RegCloseKey(self.h);
            }
        }
    }
}

/// Mount a hive **file** as a private key, without `SeRestorePrivilege`.
///
/// This is the whole point of the offline engine: `RegLoadKey` / `reg load`
/// require `SeRestorePrivilege` (admin), `RegLoadAppKeyW` does not. What it needs
/// instead is plain NTFS access to the file and *exclusive* use of it.
///
/// Constraints that matter in practice, all enforced or reported by callers:
///   * The handle is **process-scoped**. When this process exits the hive is
///     unloaded - so a `mount` / `set` / `unmount` sequence across three separate
///     process launches cannot work. See `hive::Session`.
///   * The file must not already be loaded. A logged-on user's `NTUSER.DAT` is
///     mounted by the OS, so it fails with `ERROR_SHARING_VIOLATION`.
///   * The path must be absolute and must not traverse a symbolic link.
///   * Opening for write requires NTFS write access to the file itself.
pub fn load_app_key(path: &Path, sam: u32, exclusive: bool) -> Result<RegKey> {
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    // canonicalize() yields a \\?\ extended path, which RegLoadAppKeyW accepts.
    let w = wide_path(&abs);
    let mut out: HKEY = std::ptr::null_mut();
    let options = if exclusive { REG_PROCESS_APPKEY } else { 0 };
    // SAFETY: `w` is a NUL-terminated absolute path that outlives the call.
    let rc = unsafe { RegLoadAppKeyW(w.as_ptr(), &mut out, sam, options, 0) };
    if rc != ERROR_SUCCESS {
        return Err(Error {
            code: rc,
            op: "RegLoadAppKey",
            target: abs.display().to_string(),
        });
    }
    Ok(RegKey {
        h: out,
        owned: true,
        label: format!("<hive:{}>", path.display()),
    })
}

/// Cheap structural check so we can fail with a clear message instead of a bare
/// `ERROR_BADDB`. A registry hive starts with the ASCII signature `regf`.
pub fn looks_like_hive(path: &Path) -> std::io::Result<bool> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut magic = [0u8; 4];
    match f.read_exact(&mut magic) {
        Ok(()) => Ok(&magic == b"regf"),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_wait_rejects_an_empty_handle_set() {
        let error = wait_for_any_change(Vec::new(), false, 0).unwrap_err();
        assert_eq!(error.op, "WaitForMultipleObjects");
    }

    #[test]
    fn hkcu_is_readable_and_enumerable() {
        let root = RegKey::predefined(hkey_current_user(), "HKEY_CURRENT_USER");
        let sw = root.open("Software", KEY_READ, View::Native).unwrap();
        assert!(!sw.subkeys().unwrap().is_empty());
    }

    #[test]
    fn remote_computer_names_are_normalized_once() {
        assert_eq!(normalize_computer("server"), r"\\server");
        assert_eq!(normalize_computer(r"\\server"), r"\\server");
        assert_eq!(normalize_computer(r"\server"), r"\\server");
    }

    #[test]
    fn malformed_registry_names_are_errors_not_replacement_text() {
        let error = decode_registry_name(&[0xd800], "RegEnumValue", "HKCU\\Software").unwrap_err();
        assert_eq!(error.code, ERROR_NO_UNICODE_TRANSLATION);
        assert!(error.to_string().contains("malformed UTF-16"));
        assert!(!error.to_string().contains('\u{fffd}'));
    }

    #[test]
    fn live_enumeration_refuses_a_native_malformed_value_name() {
        let file =
            std::env::temp_dir().join(format!("regx-malformed-name-{}.hiv", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let session = crate::hive::open(&file, true, true, true).unwrap();
        let path = crate::model::RegPath::parse("HKCU").unwrap();
        let (key, _) = session.roots.resolve(&path);
        let malformed_name = [0xd800, 0];
        let data = [1u8, 2, 3];
        // SAFETY: all buffers remain alive for the call. Win32 accepts UTF-16
        // code units here; this deliberately bypasses regx's String boundary
        // to model a malformed name left by native software.
        let status = unsafe {
            RegSetValueExW(
                key.h,
                malformed_name.as_ptr(),
                0,
                crate::model::REG_BINARY,
                data.as_ptr(),
                data.len() as u32,
            )
        };
        if status == ERROR_SUCCESS {
            let error = key.values().unwrap_err();
            assert_eq!(error.code, ERROR_NO_UNICODE_TRANSLATION);
        } else {
            panic!("native malformed-name setup failed with error {status}");
        }
        drop(session);
        std::fs::remove_file(file).unwrap();
    }

    #[test]
    fn rejects_names_win32_would_truncate_or_cannot_represent() {
        let nul_key = checked_subkey("Software\\Safe\0Hidden", "test", "HKCU").unwrap_err();
        assert_eq!(nul_key.code, ERROR_INVALID_PARAMETER);
        assert!(nul_key.to_string().contains("embedded NUL"));

        let long_component = "😀".repeat(128); // 256 UTF-16 code units.
        let long_key = checked_subkey(&long_component, "test", "HKCU").unwrap_err();
        assert!(long_key.to_string().contains("255 UTF-16"));

        let nul_value = checked_value_name("Visible\0Hidden", "test", "HKCU").unwrap_err();
        assert!(nul_value.to_string().contains("embedded NUL"));

        let control_value = checked_value_name("Visible\nHidden", "test", "HKCU").unwrap_err();
        assert!(control_value.to_string().contains("control character"));

        let long_value = "x".repeat(16_384);
        let long_value = checked_value_name(&long_value, "test", "HKCU").unwrap_err();
        assert!(long_value.to_string().contains("16,383 UTF-16"));
    }

    #[test]
    fn round_trips_a_value_in_a_scratch_key() {
        let root = RegKey::predefined(hkey_current_user(), "HKEY_CURRENT_USER");
        if root.open("Software", KEY_WRITE, View::Native).is_err() {
            eprintln!("SKIPPED: HKCU\\Software is not writable on this host");
            return;
        }
        let path = "Software\\regx-selftest";
        let (k, _) = root
            .create(path, KEY_READ | KEY_WRITE, View::Native)
            .unwrap();

        k.set_value("probe", 1, &[0x41, 0x00, 0x00, 0x00]).unwrap(); // "A" as REG_SZ
        let got = k.get_value("probe").unwrap().unwrap();
        assert_eq!(got, (1, vec![0x41, 0x00, 0x00, 0x00]));

        assert!(k.values().unwrap().iter().any(|(n, _, _)| n == "probe"));
        k.delete_value("probe").unwrap();
        assert!(k.get_value("probe").unwrap().is_none());

        drop(k);
        root.delete_tree(path).unwrap();
        assert!(root.open(path, KEY_READ, View::Native).is_err());
    }

    #[test]
    fn missing_key_reports_not_found_not_panic() {
        let root = RegKey::predefined(hkey_current_user(), "HKEY_CURRENT_USER");
        let e = root
            .open("Software\\regx-does-not-exist-9f2a", KEY_READ, View::Native)
            .unwrap_err();
        assert!(e.is_not_found(), "{e}");
    }

    #[test]
    fn hklm_write_is_denied_without_elevation() {
        // Documents the core product premise: this build never elevates, so an
        // HKLM write must fail cleanly rather than being virtualised away.
        let root = RegKey::predefined(hkey_local_machine(), "HKEY_LOCAL_MACHINE");
        match root.create("SOFTWARE\\regx-selftest", KEY_WRITE, View::Native) {
            Err(e) => assert!(e.is_access_denied(), "unexpected error: {e}"),
            Ok((k, _)) => {
                // Only reachable if the test host runs elevated; clean up.
                drop(k);
                let _ = root.delete_tree("SOFTWARE\\regx-selftest");
            }
        }
    }
}
