//! Native Windows Shell Known Folder resolution.
//!
//! `shell:Startup`, `shell:Desktop`, and `shell:Programs` are resolved through
//! the Known Folder API, never by expanding environment variables or invoking
//! a shell. Matching is ASCII case-insensitive and tokens may appear in any
//! path-bearing CLI or manifest field.

use std::ffi::c_void;
use std::path::{Path, PathBuf};

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const FOLDERID_STARTUP: Guid = guid(0xb97d20bb, 0xf46a, 0x4c97, 0xba105e3608430854);
const FOLDERID_DESKTOP: Guid = guid(0xb4bfcc3a, 0xdb2c, 0x424c, 0xb0297fe99a87c641);
const FOLDERID_PROGRAMS: Guid = guid(0xa77f5d77, 0x2e2b, 0x44c3, 0xa6a2aba601054a51);

const CSIDL_STARTUP: i32 = 0x0007;
const CSIDL_DESKTOPDIRECTORY: i32 = 0x0010;
const CSIDL_PROGRAMS: i32 = 0x0002;
const KF_FLAG_DEFAULT: u32 = 0;
const SHGFP_TYPE_CURRENT: u32 = 0;

const fn guid(data1: u32, data2: u16, data3: u16, tail: u64) -> Guid {
    Guid {
        data1,
        data2,
        data3,
        data4: tail.to_be_bytes(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnownFolder {
    Startup,
    Desktop,
    Programs,
}

impl KnownFolder {
    fn token(self) -> &'static str {
        match self {
            Self::Startup => "shell:Startup",
            Self::Desktop => "shell:Desktop",
            Self::Programs => "shell:Programs",
        }
    }

    fn id(self) -> &'static Guid {
        match self {
            Self::Startup => &FOLDERID_STARTUP,
            Self::Desktop => &FOLDERID_DESKTOP,
            Self::Programs => &FOLDERID_PROGRAMS,
        }
    }

    fn csidl(self) -> i32 {
        match self {
            Self::Startup => CSIDL_STARTUP,
            Self::Desktop => CSIDL_DESKTOPDIRECTORY,
            Self::Programs => CSIDL_PROGRAMS,
        }
    }
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(
        rfid: *const Guid,
        flags: u32,
        token: *mut c_void,
        path: *mut *mut u16,
    ) -> i32;
    fn SHGetFolderPathW(
        hwnd: *mut c_void,
        csidl: i32,
        token: *mut c_void,
        flags: u32,
        path: *mut u16,
    ) -> i32;
}

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemFree(memory: *const c_void);
}

/// Resolve every supported `shell:NAME` token in a path-bearing string.
pub fn resolve_text(input: &str) -> Result<String, String> {
    let mut output = input.to_owned();
    for folder in [
        KnownFolder::Startup,
        KnownFolder::Desktop,
        KnownFolder::Programs,
    ] {
        if find_ascii_case_insensitive(&output, folder.token()).is_some() {
            output = replace_ascii_case_insensitive(&output, folder.token(), &folder_path(folder)?)
        }
    }
    if let Some(token) = find_shell_token(&output) {
        return Err(format!(
            "unsupported Windows Shell Known Folder token {token:?}; supported tokens are shell:Startup, shell:Desktop, and shell:Programs"
        ));
    }
    Ok(output)
}

pub fn resolve_path(input: &Path) -> Result<PathBuf, String> {
    let text = input
        .to_str()
        .ok_or_else(|| format!("path is not valid Unicode: {}", input.display()))?;
    resolve_text(text).map(PathBuf::from)
}

pub fn folder_path(folder: KnownFolder) -> Result<String, String> {
    let mut allocated = std::ptr::null_mut();
    // SAFETY: the folder ID and out pointer are valid for this synchronous call.
    let hr = unsafe {
        SHGetKnownFolderPath(
            folder.id(),
            KF_FLAG_DEFAULT,
            std::ptr::null_mut(),
            &mut allocated,
        )
    };
    if hr >= 0 && !allocated.is_null() {
        let result = wide_ptr_to_string(allocated);
        // SAFETY: successful SHGetKnownFolderPath returns CoTaskMem allocation.
        unsafe { CoTaskMemFree(allocated.cast()) };
        return result;
    }

    // Windows Vista and later support Known Folders, but the documented CSIDL
    // fallback keeps the CLI usable in constrained compatibility environments.
    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: buffer has space for a maximum extended-length Windows path.
    let fallback = unsafe {
        SHGetFolderPathW(
            std::ptr::null_mut(),
            folder.csidl(),
            std::ptr::null_mut(),
            SHGFP_TYPE_CURRENT,
            buffer.as_mut_ptr(),
        )
    };
    if fallback < 0 {
        return Err(format!(
            "cannot resolve {} (SHGetKnownFolderPath=0x{:08x}, SHGetFolderPathW=0x{:08x})",
            folder.token(),
            hr as u32,
            fallback as u32
        ));
    }
    let len = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..len])
        .map_err(|_| format!("{} resolved to malformed UTF-16", folder.token()))
}

fn wide_ptr_to_string(path: *const u16) -> Result<String, String> {
    let mut len = 0_usize;
    // SAFETY: Shell returns a NUL-terminated PWSTR. The explicit bound avoids
    // walking arbitrary memory if the platform contract is violated.
    unsafe {
        while len < 32_768 && *path.add(len) != 0 {
            len += 1;
        }
        if len == 32_768 {
            return Err("Known Folder path is not NUL-terminated within 32768 UTF-16 units".into());
        }
        String::from_utf16(std::slice::from_raw_parts(path, len))
            .map_err(|_| "Known Folder path contains malformed UTF-16".into())
    }
}

fn replace_ascii_case_insensitive(input: &str, needle: &str, replacement: &str) -> String {
    let mut output = String::with_capacity(input.len() + replacement.len());
    let mut rest = input;
    while let Some(index) = find_ascii_case_insensitive(rest, needle) {
        output.push_str(&rest[..index]);
        output.push_str(replacement);
        rest = &rest[index + needle.len()..];
    }
    output.push_str(rest);
    output
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn find_shell_token(input: &str) -> Option<&str> {
    let index = find_ascii_case_insensitive(input, "shell:")?;
    let tail = &input[index..];
    let end = tail
        .find(['\\', '/', ' ', '\t', '\r', '\n', '"', '\''])
        .unwrap_or(tail.len());
    Some(&tail[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_is_case_insensitive_and_replaces_every_occurrence() {
        assert_eq!(
            replace_ascii_case_insensitive(
                r"shell:startup\\A;SHELL:STARTUP\\B",
                "shell:Startup",
                r"C:\\Startup"
            ),
            r"C:\\Startup\\A;C:\\Startup\\B"
        );
    }

    #[test]
    fn supported_known_folders_resolve_to_absolute_paths() {
        for folder in [
            KnownFolder::Startup,
            KnownFolder::Desktop,
            KnownFolder::Programs,
        ] {
            let path = PathBuf::from(folder_path(folder).unwrap());
            assert!(path.is_absolute(), "{}", path.display());
        }
    }

    #[test]
    fn unknown_shell_token_fails_closed() {
        let error = resolve_text(r"shell:NotARealFolder\\x").unwrap_err();
        assert!(error.contains("unsupported Windows Shell Known Folder"));
    }
}
