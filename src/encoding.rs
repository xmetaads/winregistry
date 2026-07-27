//! Byte-level decoding of `.reg` files.
//!
//! `.reg` files come in two dialects that differ in *encoding*, not just header:
//!   * `Windows Registry Editor Version 5.00` -> UTF-16LE, always BOM-prefixed
//!   * `REGEDIT4`                             -> ANSI, in the *machine's* codepage
//!
//! The ANSI case is the nasty one: a REGEDIT4 file written on a CP1258 (Vietnamese)
//! machine and read on a CP1252 machine decodes to different text. We decode via
//! `MultiByteToWideChar(CP_ACP)` so behaviour matches regedit.exe exactly, and we
//! record which encoding we saw so `convert` can round-trip faithfully.

use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SourceEncoding {
    Utf16Le,
    Utf16Be,
    Utf8,
    /// System ANSI codepage (CP_ACP). Carries the codepage actually used.
    Ansi(u32),
}

impl fmt::Display for SourceEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceEncoding::Utf16Le => write!(f, "UTF-16LE"),
            SourceEncoding::Utf16Be => write!(f, "UTF-16BE"),
            SourceEncoding::Utf8 => write!(f, "UTF-8"),
            SourceEncoding::Ansi(cp) => write!(f, "ANSI(CP{cp})"),
        }
    }
}

/// Sniff the encoding by BOM, then by the heuristic regedit itself uses:
/// a UTF-16LE file without BOM still starts with an ASCII letter followed by
/// a NUL byte.
pub fn decode(bytes: &[u8]) -> (String, SourceEncoding) {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => (utf16le(rest), SourceEncoding::Utf16Le),
        [0xFE, 0xFF, rest @ ..] => (utf16be(rest), SourceEncoding::Utf16Be),
        [0xEF, 0xBB, 0xBF, rest @ ..] => (
            String::from_utf8_lossy(rest).into_owned(),
            SourceEncoding::Utf8,
        ),
        [a, 0x00, ..] if a.is_ascii_graphic() => (utf16le(bytes), SourceEncoding::Utf16Le),
        _ if std::str::from_utf8(bytes).is_ok() && bytes.is_ascii() => (
            String::from_utf8_lossy(bytes).into_owned(),
            SourceEncoding::Ansi(acp()),
        ),
        _ => (ansi_to_string(bytes), SourceEncoding::Ansi(acp())),
    }
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn utf16be(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Encode a string back to UTF-16LE bytes with BOM - the on-disk form of a
/// "Version 5.00" file.
pub fn encode_utf16le_bom(s: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

#[cfg(windows)]
mod win {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub safe fn GetACP() -> u32;
        pub unsafe fn MultiByteToWideChar(
            codepage: u32,
            flags: u32,
            mb: *const u8,
            cb_mb: i32,
            wide: *mut u16,
            cch_wide: i32,
        ) -> i32;
    }
}

#[cfg(windows)]
pub fn acp() -> u32 {
    win::GetACP()
}

#[cfg(windows)]
fn ansi_to_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let cp = acp();
    // SAFETY: pointer/length pairs describe the same slice; the probe call with a
    // null destination is the documented way to size the output buffer.
    unsafe {
        let needed =
            win::MultiByteToWideChar(cp, 0, bytes.as_ptr(), bytes.len() as i32, std::ptr::null_mut(), 0);
        if needed <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut buf = vec![0u16; needed as usize];
        let written = win::MultiByteToWideChar(
            cp,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            buf.as_mut_ptr(),
            needed,
        );
        String::from_utf16_lossy(&buf[..written.max(0) as usize])
    }
}

#[cfg(not(windows))]
pub fn acp() -> u32 {
    1252
}

/// Non-Windows fallback (used only so the parser is testable off-Windows):
/// treat bytes as Latin-1.
#[cfg(not(windows))]
fn ansi_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}
