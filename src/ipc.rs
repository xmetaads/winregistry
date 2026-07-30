//! Bounded, one-shot Windows named-pipe input.
//!
//! Registry data often originates in another process rather than on disk.
//! `pipe:NAME` is the portable CLI spelling for `\\.\pipe\NAME`; the native
//! spelling is accepted too. The producer must create a byte-mode pipe and
//! close its write side after one complete registry-data document.

use std::path::{Path, PathBuf};
use std::time::Duration;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const URI_PREFIX: &str = "pipe:";
const WIN32_PREFIX: &str = r"\\.\pipe\";
const SLASH_PREFIX: &str = "//./pipe/";

pub fn is_named_pipe(path: &Path) -> bool {
    let text = path.as_os_str().to_string_lossy();
    starts_ci(&text, URI_PREFIX) || starts_ci(&text, WIN32_PREFIX) || starts_ci(&text, SLASH_PREFIX)
}

pub fn label(path: &Path) -> String {
    let text = path.as_os_str().to_string_lossy();
    if starts_ci(&text, URI_PREFIX) {
        format!("<pipe:{}>", &text[URI_PREFIX.len()..])
    } else {
        format!("<pipe:{}>", pipe_name(&text).unwrap_or_default())
    }
}

pub fn read(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let native = native_path(path)?;
    platform::read(&native, max_bytes, CONNECT_TIMEOUT, &label(path))
}

fn native_path(path: &Path) -> Result<PathBuf, String> {
    let text = path.as_os_str().to_string_lossy();
    let name = pipe_name(&text).ok_or_else(|| {
        format!(
            "{} is not a named-pipe source; use pipe:NAME or \\\\.\\pipe\\NAME",
            path.display()
        )
    })?;
    validate_name(name)?;
    Ok(PathBuf::from(format!("{WIN32_PREFIX}{name}")))
}

fn pipe_name(text: &str) -> Option<&str> {
    if starts_ci(text, URI_PREFIX) {
        Some(&text[URI_PREFIX.len()..])
    } else if starts_ci(text, WIN32_PREFIX) {
        Some(&text[WIN32_PREFIX.len()..])
    } else if starts_ci(text, SLASH_PREFIX) {
        Some(&text[SLASH_PREFIX.len()..])
    } else {
        None
    }
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("named-pipe source has an empty name".into());
    }
    if name.contains(['\\', '/']) {
        return Err(format!(
            "named-pipe name {name:?} contains a path separator"
        ));
    }
    if name.encode_utf16().count() > 256 {
        return Err(format!(
            "named-pipe name {name:?} exceeds the 256 UTF-16-code-unit limit"
        ));
    }
    Ok(())
}

fn starts_ci(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

#[cfg(windows)]
mod platform {
    use std::fs::File;
    use std::io::Read;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::time::{Duration, Instant};

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn WaitNamedPipeW(name: *const u16, timeout_ms: u32) -> i32;
    }

    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_SEM_TIMEOUT: i32 = 121;
    const ERROR_PIPE_BUSY: i32 = 231;

    pub fn read(
        path: &Path,
        max_bytes: u64,
        timeout: Duration,
        label: &str,
    ) -> Result<Vec<u8>, String> {
        let mut file = connect(path, timeout, label)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read {label}: {error}"))?;
        if bytes.len() as u64 > max_bytes {
            return Err(format!(
                "registry-data input exceeds the {max_bytes}-byte size limit: {label}"
            ));
        }
        Ok(bytes)
    }

    fn connect(path: &Path, timeout: Duration, label: &str) -> Result<File, String> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let deadline = Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "timed out after {} ms waiting for {label}",
                    timeout.as_millis()
                ));
            }
            let wait_ms = u32::try_from(remaining.as_millis().min(250)).unwrap_or(250);
            // SAFETY: `wide` is NUL-terminated and remains alive for the
            // duration of this synchronous call.
            let ready = unsafe { WaitNamedPipeW(wide.as_ptr(), wait_ms) };
            if ready != 0 {
                match File::open(path) {
                    Ok(file) => return Ok(file),
                    Err(error) if retryable(error.raw_os_error()) => continue,
                    Err(error) => return Err(format!("cannot connect to {label}: {error}")),
                }
            }

            let error = std::io::Error::last_os_error();
            if retryable(error.raw_os_error()) || error.raw_os_error() == Some(ERROR_SEM_TIMEOUT) {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(format!("cannot wait for {label}: {error}"));
        }
    }

    fn retryable(code: Option<i32>) -> bool {
        matches!(code, Some(ERROR_FILE_NOT_FOUND) | Some(ERROR_PIPE_BUSY))
    }
}

#[cfg(not(windows))]
mod platform {
    use std::path::Path;
    use std::time::Duration;

    pub fn read(
        _path: &Path,
        _max_bytes: u64,
        _timeout: Duration,
        label: &str,
    ) -> Result<Vec<u8>, String> {
        Err(format!("{label} is only supported on Windows"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_uri_and_native_spellings_case_insensitively() {
        for source in [
            "pipe:regx-input",
            "PIPE:regx-input",
            r"\\.\pipe\regx-input",
            r"\\.\PIPE\regx-input",
            "//./pipe/regx-input",
        ] {
            assert!(is_named_pipe(Path::new(source)), "{source}");
        }
        assert!(!is_named_pipe(Path::new("input.reg")));
    }

    #[test]
    fn normalises_uri_and_rejects_ambiguous_names() {
        assert_eq!(
            native_path(Path::new("pipe:regx-input")).unwrap(),
            PathBuf::from(r"\\.\pipe\regx-input")
        );
        assert!(native_path(Path::new("pipe:")).is_err());
        assert!(native_path(Path::new("pipe:nested\\name")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn missing_pipe_obeys_the_connection_timeout() {
        let name = format!(
            r"\\.\pipe\regx-missing-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        );
        let error = platform::read(
            Path::new(&name),
            1024,
            Duration::from_millis(50),
            "<pipe:missing>",
        )
        .unwrap_err();
        assert!(error.contains("timed out"), "{error}");
    }
}
