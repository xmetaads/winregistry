//! Native Windows Shell Link (`.lnk`) engine.
//!
//! The implementation talks directly to `IShellLinkW` and `IPersistFile`.
//! It deliberately does not invoke PowerShell, `cmd.exe`, or `WScript.Shell`.

use crate::{file_io, shell};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const MAX_LINK_TEXT: usize = 32_768;
const CLSCTX_INPROC_SERVER: u32 = 0x1;
const COINIT_APARTMENTTHREADED: u32 = 0x2;
const RPC_E_CHANGED_MODE: i32 = 0x80010106_u32 as i32;
const STGM_READ: u32 = 0;
const SLGP_RAWPATH: u32 = 0x4;
const SW_SHOWNORMAL: i32 = 1;
const SW_SHOWMINNOACTIVE: i32 = 7;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const fn guid(data1: u32, data2: u16, data3: u16, tail: u64) -> Guid {
    Guid {
        data1,
        data2,
        data3,
        data4: tail.to_be_bytes(),
    }
}

const CLSID_SHELL_LINK: Guid = guid(0x00021401, 0x0000, 0x0000, 0xc000000000000046);
const IID_ISHELL_LINK_W: Guid = guid(0x000214f9, 0x0000, 0x0000, 0xc000000000000046);
const IID_IPERSIST_FILE: Guid = guid(0x0000010b, 0x0000, 0x0000, 0xc000000000000046);

#[repr(C)]
struct IShellLinkW {
    vtable: *const IShellLinkWVtbl,
}

#[repr(C)]
struct IShellLinkWVtbl {
    query_interface:
        unsafe extern "system" fn(*mut IShellLinkW, *const Guid, *mut *mut c_void) -> i32,
    add_ref: unsafe extern "system" fn(*mut IShellLinkW) -> u32,
    release: unsafe extern "system" fn(*mut IShellLinkW) -> u32,
    get_path: unsafe extern "system" fn(*mut IShellLinkW, *mut u16, i32, *mut c_void, u32) -> i32,
    get_id_list: unsafe extern "system" fn(*mut IShellLinkW, *mut *mut c_void) -> i32,
    set_id_list: unsafe extern "system" fn(*mut IShellLinkW, *const c_void) -> i32,
    get_description: unsafe extern "system" fn(*mut IShellLinkW, *mut u16, i32) -> i32,
    set_description: unsafe extern "system" fn(*mut IShellLinkW, *const u16) -> i32,
    get_working_directory: unsafe extern "system" fn(*mut IShellLinkW, *mut u16, i32) -> i32,
    set_working_directory: unsafe extern "system" fn(*mut IShellLinkW, *const u16) -> i32,
    get_arguments: unsafe extern "system" fn(*mut IShellLinkW, *mut u16, i32) -> i32,
    set_arguments: unsafe extern "system" fn(*mut IShellLinkW, *const u16) -> i32,
    get_hotkey: unsafe extern "system" fn(*mut IShellLinkW, *mut u16) -> i32,
    set_hotkey: unsafe extern "system" fn(*mut IShellLinkW, u16) -> i32,
    get_show_cmd: unsafe extern "system" fn(*mut IShellLinkW, *mut i32) -> i32,
    set_show_cmd: unsafe extern "system" fn(*mut IShellLinkW, i32) -> i32,
    get_icon_location: unsafe extern "system" fn(*mut IShellLinkW, *mut u16, i32, *mut i32) -> i32,
    set_icon_location: unsafe extern "system" fn(*mut IShellLinkW, *const u16, i32) -> i32,
    set_relative_path: unsafe extern "system" fn(*mut IShellLinkW, *const u16, u32) -> i32,
    resolve: unsafe extern "system" fn(*mut IShellLinkW, *mut c_void, u32) -> i32,
    set_path: unsafe extern "system" fn(*mut IShellLinkW, *const u16) -> i32,
}

#[repr(C)]
struct IPersistFile {
    vtable: *const IPersistFileVtbl,
}

#[repr(C)]
struct IPersistFileVtbl {
    query_interface:
        unsafe extern "system" fn(*mut IPersistFile, *const Guid, *mut *mut c_void) -> i32,
    add_ref: unsafe extern "system" fn(*mut IPersistFile) -> u32,
    release: unsafe extern "system" fn(*mut IPersistFile) -> u32,
    get_class_id: unsafe extern "system" fn(*mut IPersistFile, *mut Guid) -> i32,
    is_dirty: unsafe extern "system" fn(*mut IPersistFile) -> i32,
    load: unsafe extern "system" fn(*mut IPersistFile, *const u16, u32) -> i32,
    save: unsafe extern "system" fn(*mut IPersistFile, *const u16, i32) -> i32,
    save_completed: unsafe extern "system" fn(*mut IPersistFile, *const u16) -> i32,
    get_cur_file: unsafe extern "system" fn(*mut IPersistFile, *mut *mut u16) -> i32,
}

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoInitializeEx(reserved: *const c_void, coinit: u32) -> i32;
    fn CoUninitialize();
    fn CoCreateInstance(
        clsid: *const Guid,
        outer: *mut c_void,
        context: u32,
        iid: *const Guid,
        object: *mut *mut c_void,
    ) -> i32;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShowStyle {
    Normal,
    Hidden,
    Minimized,
}

impl ShowStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Hidden => "hidden",
            Self::Minimized => "minimized",
        }
    }

    fn win32(self) -> i32 {
        match self {
            Self::Normal => SW_SHOWNORMAL,
            Self::Hidden | Self::Minimized => SW_SHOWMINNOACTIVE,
        }
    }

    fn from_win32(value: i32) -> Self {
        if value == SW_SHOWMINNOACTIVE {
            Self::Minimized
        } else {
            Self::Normal
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateOptions {
    pub target: PathBuf,
    pub output: PathBuf,
    pub working_directory: Option<PathBuf>,
    pub arguments: Option<String>,
    pub description: Option<String>,
    pub icon_path: Option<PathBuf>,
    pub icon_index: i32,
    pub style: ShowStyle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    pub file: PathBuf,
    pub target: PathBuf,
    pub working_directory: Option<PathBuf>,
    pub arguments: String,
    pub description: String,
    pub icon_path: Option<PathBuf>,
    pub icon_index: i32,
    pub style: ShowStyle,
}

pub fn parse_icon_spec(spec: &str) -> Result<(PathBuf, i32), String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err("shortcut icon specification is empty".into());
    }
    if let Some((path, index)) = trimmed.rsplit_once(',') {
        if let Ok(index) = index.trim().parse::<i32>() {
            let path = path.trim();
            if path.is_empty() {
                return Err("shortcut icon path is empty".into());
            }
            return Ok((PathBuf::from(path), index));
        }
    }
    Ok((PathBuf::from(trimmed), 0))
}

pub fn resolve_options(options: &CreateOptions) -> Result<CreateOptions, String> {
    Ok(CreateOptions {
        target: shell::resolve_path(&options.target)?,
        output: shell::resolve_path(&options.output)?,
        working_directory: options
            .working_directory
            .as_deref()
            .map(shell::resolve_path)
            .transpose()?,
        arguments: options
            .arguments
            .as_deref()
            .map(shell::resolve_text)
            .transpose()?,
        description: options.description.clone(),
        icon_path: options
            .icon_path
            .as_deref()
            .map(shell::resolve_path)
            .transpose()?,
        icon_index: options.icon_index,
        style: options.style,
    })
}

pub fn validate(options: &CreateOptions) -> Result<(), String> {
    if !options.target.is_absolute() {
        return Err(format!(
            "shortcut target must be an absolute path: {}",
            options.target.display()
        ));
    }
    let target_metadata = std::fs::metadata(&options.target).map_err(|error| {
        format!(
            "cannot inspect shortcut target {}: {error}",
            options.target.display()
        )
    })?;
    if !target_metadata.is_file() {
        return Err(format!(
            "shortcut target is not a regular file: {}",
            options.target.display()
        ));
    }
    if !options.output.is_absolute() {
        return Err(format!(
            "shortcut output must resolve to an absolute path: {}",
            options.output.display()
        ));
    }
    if !has_lnk_extension(&options.output) {
        return Err(format!(
            "shortcut output must use the .lnk extension: {}",
            options.output.display()
        ));
    }
    let parent = options
        .output
        .parent()
        .ok_or_else(|| "shortcut output has no parent directory".to_string())?;
    if !parent.is_dir() {
        return Err(format!(
            "shortcut output directory does not exist: {}",
            parent.display()
        ));
    }
    if let Some(workdir) = &options.working_directory {
        if !workdir.is_absolute() || !workdir.is_dir() {
            return Err(format!(
                "shortcut working directory must be an existing absolute directory: {}",
                workdir.display()
            ));
        }
    }
    if let Some(icon) = &options.icon_path {
        if !icon.is_absolute() || !icon.is_file() {
            return Err(format!(
                "shortcut icon must be an existing absolute file: {}",
                icon.display()
            ));
        }
    }
    for (name, text) in [
        ("arguments", options.arguments.as_deref()),
        ("description", options.description.as_deref()),
    ] {
        if text.is_some_and(|value| value.contains('\0')) {
            return Err(format!("shortcut {name} contains a NUL character"));
        }
    }
    Ok(())
}

pub fn create(options: &CreateOptions, overwrite: bool) -> Result<LinkInfo, String> {
    validate(options)?;
    if options.output.exists() && !overwrite {
        return Err(format!(
            "shortcut already exists (use -y to replace it): {}",
            options.output.display()
        ));
    }

    let _apartment = ComApartment::initialize()?;
    let link = ShellLink::create()?;
    link.set_path(&options.target)?;
    if let Some(arguments) = &options.arguments {
        link.set_arguments(arguments)?;
    }
    if let Some(workdir) = &options.working_directory {
        link.set_working_directory(workdir)?;
    }
    if let Some(description) = &options.description {
        link.set_description(description)?;
    }
    if let Some(icon) = &options.icon_path {
        link.set_icon(icon, options.icon_index)?;
    }
    link.set_show_style(options.style)?;

    let (temporary_file, temporary) =
        file_io::create_temporary(&options.output).map_err(|error| {
            format!(
                "cannot allocate temporary shortcut beside {}: {error}",
                options.output.display()
            )
        })?;
    drop(temporary_file);
    let result = (|| {
        link.save(&temporary)?;
        let verified = inspect_inner(&temporary)?;
        verify(options, &verified)?;
        if overwrite {
            file_io::replace(&temporary, &options.output)
        } else {
            std::fs::rename(&temporary, &options.output)
        }
        .map_err(|error| {
            format!(
                "cannot commit shortcut {}: {error}",
                options.output.display()
            )
        })?;
        inspect_inner(&options.output)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub fn inspect(path: &Path) -> Result<LinkInfo, String> {
    let resolved = shell::resolve_path(path)?;
    if !has_lnk_extension(&resolved) {
        return Err(format!(
            "shortcut path must use the .lnk extension: {}",
            resolved.display()
        ));
    }
    inspect_inner(&resolved)
}

fn inspect_inner(path: &Path) -> Result<LinkInfo, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect shortcut {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "shortcut is not a regular non-symlink file: {}",
            path.display()
        ));
    }
    let _apartment = ComApartment::initialize()?;
    let link = ShellLink::create()?;
    link.load(path)?;
    let target = PathBuf::from(link.get_path()?);
    let working = link.get_working_directory()?;
    let icon = link.get_icon()?;
    Ok(LinkInfo {
        file: path.to_path_buf(),
        target,
        working_directory: (!working.is_empty()).then(|| PathBuf::from(working)),
        arguments: link.get_arguments()?,
        description: link.get_description()?,
        icon_path: (!icon.0.is_empty()).then(|| PathBuf::from(icon.0)),
        icon_index: icon.1,
        style: ShowStyle::from_win32(link.get_show_cmd()?),
    })
}

pub fn delete(path: &Path) -> Result<PathBuf, String> {
    let resolved = shell::resolve_path(path)?;
    let _ = inspect_inner(&resolved)?;
    std::fs::remove_file(&resolved)
        .map_err(|error| format!("cannot delete shortcut {}: {error}", resolved.display()))?;
    Ok(resolved)
}

fn verify(expected: &CreateOptions, actual: &LinkInfo) -> Result<(), String> {
    if !same_path(&expected.target, &actual.target)
        || expected.arguments.as_deref().unwrap_or("") != actual.arguments
        || !same_optional_path(
            expected.working_directory.as_deref(),
            actual.working_directory.as_deref(),
        )
        || expected.description.as_deref().unwrap_or("") != actual.description
        || expected.icon_index != actual.icon_index
        || !same_optional_path(expected.icon_path.as_deref(), actual.icon_path.as_deref())
        || expected.style.win32() != actual.style.win32()
    {
        return Err("native Shell Link verification did not match the requested fields".into());
    }
    Ok(())
}

fn same_optional_path(left: Option<&Path>, right: Option<&Path>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => same_path(left, right),
        (None, None) => true,
        _ => false,
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

fn has_lnk_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("lnk"))
}

struct ComApartment(bool);

impl ComApartment {
    fn initialize() -> Result<Self, String> {
        // SAFETY: null reserved pointer and documented apartment flag.
        let hr = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED) };
        if hr >= 0 {
            Ok(Self(true))
        } else if hr == RPC_E_CHANGED_MODE {
            // COM is already initialized on this thread in another mode. It is
            // usable, but this call must not be balanced with CoUninitialize.
            Ok(Self(false))
        } else {
            Err(hr_error("CoInitializeEx", hr))
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances this thread's successful CoInitializeEx call.
            unsafe { CoUninitialize() }
        }
    }
}

struct ShellLink(*mut IShellLinkW);

impl ShellLink {
    fn create() -> Result<Self, String> {
        let mut object = std::ptr::null_mut();
        // SAFETY: valid CLSID/IID and writable out pointer; aggregation is null.
        let hr = unsafe {
            CoCreateInstance(
                &CLSID_SHELL_LINK,
                std::ptr::null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_ISHELL_LINK_W,
                &mut object,
            )
        };
        check_hr("CoCreateInstance(CLSID_ShellLink)", hr)?;
        if object.is_null() {
            return Err("CoCreateInstance returned a null IShellLinkW".into());
        }
        Ok(Self(object.cast()))
    }

    fn vtable(&self) -> &IShellLinkWVtbl {
        // SAFETY: constructor guarantees a non-null COM interface pointer.
        unsafe { &*(*self.0).vtable }
    }

    fn set_path(&self, path: &Path) -> Result<(), String> {
        let wide = wide_path(path)?;
        // SAFETY: COM pointer and NUL-terminated UTF-16 input are valid.
        check_hr("IShellLinkW::SetPath", unsafe {
            (self.vtable().set_path)(self.0, wide.as_ptr())
        })
    }

    fn set_arguments(&self, arguments: &str) -> Result<(), String> {
        let wide = wide_text(arguments, "shortcut arguments")?;
        check_hr("IShellLinkW::SetArguments", unsafe {
            (self.vtable().set_arguments)(self.0, wide.as_ptr())
        })
    }

    fn set_working_directory(&self, path: &Path) -> Result<(), String> {
        let wide = wide_path(path)?;
        check_hr("IShellLinkW::SetWorkingDirectory", unsafe {
            (self.vtable().set_working_directory)(self.0, wide.as_ptr())
        })
    }

    fn set_description(&self, description: &str) -> Result<(), String> {
        let wide = wide_text(description, "shortcut description")?;
        check_hr("IShellLinkW::SetDescription", unsafe {
            (self.vtable().set_description)(self.0, wide.as_ptr())
        })
    }

    fn set_icon(&self, path: &Path, index: i32) -> Result<(), String> {
        let wide = wide_path(path)?;
        check_hr("IShellLinkW::SetIconLocation", unsafe {
            (self.vtable().set_icon_location)(self.0, wide.as_ptr(), index)
        })
    }

    fn set_show_style(&self, style: ShowStyle) -> Result<(), String> {
        check_hr("IShellLinkW::SetShowCmd", unsafe {
            (self.vtable().set_show_cmd)(self.0, style.win32())
        })
    }

    fn persist(&self) -> Result<PersistFile, String> {
        let mut persist = std::ptr::null_mut();
        check_hr("IUnknown::QueryInterface(IPersistFile)", unsafe {
            (self.vtable().query_interface)(self.0, &IID_IPERSIST_FILE, &mut persist)
        })?;
        if persist.is_null() {
            return Err("QueryInterface returned a null IPersistFile".into());
        }
        Ok(PersistFile(persist.cast()))
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        self.persist()?.save(path)
    }

    fn load(&self, path: &Path) -> Result<(), String> {
        self.persist()?.load(path)
    }

    fn get_path(&self) -> Result<String, String> {
        self.get_string("IShellLinkW::GetPath", |buffer, length| unsafe {
            (self.vtable().get_path)(self.0, buffer, length, std::ptr::null_mut(), SLGP_RAWPATH)
        })
    }

    fn get_working_directory(&self) -> Result<String, String> {
        self.get_string(
            "IShellLinkW::GetWorkingDirectory",
            |buffer, length| unsafe {
                (self.vtable().get_working_directory)(self.0, buffer, length)
            },
        )
    }

    fn get_arguments(&self) -> Result<String, String> {
        self.get_string("IShellLinkW::GetArguments", |buffer, length| unsafe {
            (self.vtable().get_arguments)(self.0, buffer, length)
        })
    }

    fn get_description(&self) -> Result<String, String> {
        self.get_string("IShellLinkW::GetDescription", |buffer, length| unsafe {
            (self.vtable().get_description)(self.0, buffer, length)
        })
    }

    fn get_icon(&self) -> Result<(String, i32), String> {
        let mut buffer = vec![0_u16; MAX_LINK_TEXT];
        let mut index = 0_i32;
        check_hr("IShellLinkW::GetIconLocation", unsafe {
            (self.vtable().get_icon_location)(
                self.0,
                buffer.as_mut_ptr(),
                buffer.len() as i32,
                &mut index,
            )
        })?;
        Ok((buffer_to_string(&buffer)?, index))
    }

    fn get_show_cmd(&self) -> Result<i32, String> {
        let mut show = 0_i32;
        check_hr("IShellLinkW::GetShowCmd", unsafe {
            (self.vtable().get_show_cmd)(self.0, &mut show)
        })?;
        Ok(show)
    }

    fn get_string(
        &self,
        operation: &str,
        call: impl FnOnce(*mut u16, i32) -> i32,
    ) -> Result<String, String> {
        let mut buffer = vec![0_u16; MAX_LINK_TEXT];
        check_hr(operation, call(buffer.as_mut_ptr(), buffer.len() as i32))?;
        buffer_to_string(&buffer)
    }
}

impl Drop for ShellLink {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this object owns one COM reference.
            unsafe { (self.vtable().release)(self.0) };
        }
    }
}

struct PersistFile(*mut IPersistFile);

impl PersistFile {
    fn vtable(&self) -> &IPersistFileVtbl {
        // SAFETY: QueryInterface guarantees a valid interface pointer.
        unsafe { &*(*self.0).vtable }
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        let wide = wide_path(path)?;
        check_hr("IPersistFile::Save", unsafe {
            (self.vtable().save)(self.0, wide.as_ptr(), 1)
        })
    }

    fn load(&self, path: &Path) -> Result<(), String> {
        let wide = wide_path(path)?;
        check_hr("IPersistFile::Load", unsafe {
            (self.vtable().load)(self.0, wide.as_ptr(), STGM_READ)
        })
    }
}

impl Drop for PersistFile {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this object owns one COM reference from QueryInterface.
            unsafe { (self.vtable().release)(self.0) };
        }
    }
}

fn wide_path(path: &Path) -> Result<Vec<u16>, String> {
    if path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(format!("path contains a NUL character: {}", path.display()));
    }
    Ok(path.as_os_str().encode_wide().chain(Some(0)).collect())
}

fn wide_text(text: &str, field: &str) -> Result<Vec<u16>, String> {
    if text.contains('\0') {
        return Err(format!("{field} contains a NUL character"));
    }
    Ok(text.encode_utf16().chain(Some(0)).collect())
}

fn buffer_to_string(buffer: &[u16]) -> Result<String, String> {
    let len = buffer
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| "Shell Link string is not NUL-terminated".to_string())?;
    String::from_utf16(&buffer[..len])
        .map_err(|_| "Shell Link contains malformed UTF-16".to_string())
}

fn check_hr(operation: &str, hr: i32) -> Result<(), String> {
    if hr >= 0 {
        Ok(())
    } else {
        Err(hr_error(operation, hr))
    }
}

fn hr_error(operation: &str, hr: i32) -> String {
    format!("{operation} failed with HRESULT 0x{:08x}", hr as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "regx-link-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn native_link_round_trip_preserves_requested_fields() {
        let output = scratch("roundtrip.lnk");
        let target = std::env::current_exe().unwrap();
        let workdir = target.parent().unwrap().to_path_buf();
        let options = CreateOptions {
            target: target.clone(),
            output: output.clone(),
            working_directory: Some(workdir.clone()),
            arguments: Some("--version \"Unicode ✓\"".into()),
            description: Some("regx native shortcut test".into()),
            icon_path: Some(target.clone()),
            icon_index: 0,
            style: ShowStyle::Hidden,
        };
        let info = create(&options, false).unwrap();
        assert!(same_path(&info.target, &target));
        assert_eq!(info.working_directory.as_deref(), Some(workdir.as_path()));
        assert_eq!(info.arguments, "--version \"Unicode ✓\"");
        assert_eq!(info.description, "regx native shortcut test");
        assert_eq!(info.style, ShowStyle::Minimized);
        delete(&output).unwrap();
        assert!(!output.exists());
    }

    #[test]
    fn refuses_non_lnk_output_and_missing_target() {
        let missing = scratch("missing.exe");
        let options = CreateOptions {
            target: missing,
            output: scratch("bad.txt"),
            working_directory: None,
            arguments: None,
            description: None,
            icon_path: None,
            icon_index: 0,
            style: ShowStyle::Normal,
        };
        assert!(validate(&options)
            .unwrap_err()
            .contains("cannot inspect shortcut target"));
    }

    #[test]
    fn icon_spec_uses_the_last_comma_only_when_it_has_an_integer_index() {
        assert_eq!(
            parse_icon_spec(r"C:\\Icons, Set\\app.dll,-2").unwrap(),
            (PathBuf::from(r"C:\\Icons, Set\\app.dll"), -2)
        );
        assert_eq!(
            parse_icon_spec(r"C:\\Icons, Set\\app.dll").unwrap(),
            (PathBuf::from(r"C:\\Icons, Set\\app.dll"), 0)
        );
    }
}
