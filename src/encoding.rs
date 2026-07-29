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
    match (source_encoding(bytes), bytes) {
        (SourceEncoding::Utf16Le, [0xFF, 0xFE, rest @ ..]) => {
            (utf16le(rest), SourceEncoding::Utf16Le)
        }
        (SourceEncoding::Utf16Be, [0xFE, 0xFF, rest @ ..]) => {
            (utf16be(rest), SourceEncoding::Utf16Be)
        }
        (SourceEncoding::Utf8, [0xEF, 0xBB, 0xBF, rest @ ..]) => (
            String::from_utf8_lossy(rest).into_owned(),
            SourceEncoding::Utf8,
        ),
        (SourceEncoding::Utf16Le, _) => (utf16le(bytes), SourceEncoding::Utf16Le),
        (SourceEncoding::Ansi(cp), _) if bytes.is_ascii() => (
            String::from_utf8_lossy(bytes).into_owned(),
            SourceEncoding::Ansi(cp),
        ),
        (SourceEncoding::Ansi(cp), _) => (ansi_to_string(bytes), SourceEncoding::Ansi(cp)),
        (SourceEncoding::Utf8, _) | (SourceEncoding::Utf16Be, _) => unreachable!(),
    }
}

pub fn source_encoding(bytes: &[u8]) -> SourceEncoding {
    match bytes {
        [0xff, 0xfe, ..] => SourceEncoding::Utf16Le,
        [0xfe, 0xff, ..] => SourceEncoding::Utf16Be,
        [0xef, 0xbb, 0xbf, ..] => SourceEncoding::Utf8,
        [a, 0x00, ..] if a.is_ascii_graphic() => SourceEncoding::Utf16Le,
        _ => SourceEncoding::Ansi(acp()),
    }
}

/// Decode without dropping odd bytes or replacing malformed Unicode.
///
/// Format detection may use [`decode`] because it only sniffs a prefix. Every
/// parser must use this strict path before interpreting user data.
pub fn decode_strict(bytes: &[u8]) -> Result<(String, SourceEncoding), String> {
    let encoding = source_encoding(bytes);
    let text = match (encoding, bytes) {
        (SourceEncoding::Utf16Le, [0xff, 0xfe, rest @ ..]) => utf16le_strict(rest)?,
        (SourceEncoding::Utf16Be, [0xfe, 0xff, rest @ ..]) => utf16be_strict(rest)?,
        (SourceEncoding::Utf8, [0xef, 0xbb, 0xbf, rest @ ..]) => {
            String::from_utf8(rest.to_vec()).map_err(|error| format!("invalid UTF-8: {error}"))?
        }
        (SourceEncoding::Utf16Le, _) => utf16le_strict(bytes)?,
        (SourceEncoding::Ansi(_), _) => ansi_to_string_strict(bytes)?,
        _ => return Err("encoding signature does not match input bytes".into()),
    };
    Ok((text, encoding))
}

fn utf16le_strict(bytes: &[u8]) -> Result<String, String> {
    utf16_strict(bytes, u16::from_le_bytes, "UTF-16LE")
}

fn utf16be_strict(bytes: &[u8]) -> Result<String, String> {
    utf16_strict(bytes, u16::from_be_bytes, "UTF-16BE")
}

fn utf16_strict(bytes: &[u8], unit: fn([u8; 2]) -> u16, label: &str) -> Result<String, String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(format!("{label} input has an odd trailing byte"));
    }
    let units = bytes
        .chunks_exact(2)
        .map(|pair| unit([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|_| format!("{label} input contains an unpaired surrogate"))
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
        pub unsafe fn WideCharToMultiByte(
            codepage: u32,
            flags: u32,
            wide: *const u16,
            cch_wide: i32,
            mb: *mut u8,
            cb_mb: i32,
            default_char: *const u8,
            used_default: *mut i32,
        ) -> i32;
    }
}

/// Encode a REGEDIT4 stream in the active Windows ANSI code page.
///
/// Best-fit substitution is rejected: a file that silently replaces a key,
/// value name, or string character is not a successful conversion.
#[cfg(windows)]
pub fn encode_ansi(text: &str) -> Result<Vec<u8>, String> {
    const CP_UTF8: u32 = 65_001;
    const WC_NO_BEST_FIT_CHARS: u32 = 0x0000_0400;

    let units: Vec<u16> = text.encode_utf16().collect();
    if units.is_empty() {
        return Ok(Vec::new());
    }
    let length =
        i32::try_from(units.len()).map_err(|_| "REGEDIT4 output exceeds the Win32 length limit")?;
    let cp = acp();
    let flags = if cp == CP_UTF8 {
        0
    } else {
        WC_NO_BEST_FIT_CHARS
    };
    let mut used_default = 0i32;
    let used_default_ptr = if cp == CP_UTF8 {
        std::ptr::null_mut()
    } else {
        &mut used_default
    };
    // SAFETY: pointer/length pairs describe `units`; null output is the
    // documented sizing call. UTF-8 forbids the default-character pointers.
    let needed = unsafe {
        win::WideCharToMultiByte(
            cp,
            flags,
            units.as_ptr(),
            length,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            used_default_ptr,
        )
    };
    if needed <= 0 {
        return Err(format!(
            "cannot encode REGEDIT4 output using ANSI code page {cp}"
        ));
    }
    let mut bytes = vec![0u8; needed as usize];
    used_default = 0;
    let used_default_ptr = if cp == CP_UTF8 {
        std::ptr::null_mut()
    } else {
        &mut used_default
    };
    // SAFETY: `bytes` has exactly `needed` writable bytes and both input/output
    // buffers remain alive for the call.
    let written = unsafe {
        win::WideCharToMultiByte(
            cp,
            flags,
            units.as_ptr(),
            length,
            bytes.as_mut_ptr(),
            needed,
            std::ptr::null(),
            used_default_ptr,
        )
    };
    if written <= 0 || used_default != 0 {
        return Err(format!(
            "REGEDIT4 output contains text not representable in ANSI code page {cp}; use Version 5.00"
        ));
    }
    bytes.truncate(written as usize);
    Ok(bytes)
}

#[cfg(not(windows))]
pub fn encode_ansi(text: &str) -> Result<Vec<u8>, String> {
    text.chars()
        .map(cp1252_byte)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            "REGEDIT4 output contains text not representable in Windows-1252; use Version 5.00"
                .into()
        })
}

#[cfg(not(windows))]
fn cp1252_byte(character: char) -> Option<u8> {
    Some(match character as u32 {
        code @ 0x00..=0x7f | code @ 0xa0..=0xff => code as u8,
        0x20ac => 0x80,
        0x201a => 0x82,
        0x0192 => 0x83,
        0x201e => 0x84,
        0x2026 => 0x85,
        0x2020 => 0x86,
        0x2021 => 0x87,
        0x02c6 => 0x88,
        0x2030 => 0x89,
        0x0160 => 0x8a,
        0x2039 => 0x8b,
        0x0152 => 0x8c,
        0x017d => 0x8e,
        0x2018 => 0x91,
        0x2019 => 0x92,
        0x201c => 0x93,
        0x201d => 0x94,
        0x2022 => 0x95,
        0x2013 => 0x96,
        0x2014 => 0x97,
        0x02dc => 0x98,
        0x2122 => 0x99,
        0x0161 => 0x9a,
        0x203a => 0x9b,
        0x0153 => 0x9c,
        0x017e => 0x9e,
        0x0178 => 0x9f,
        _ => return None,
    })
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
    let Ok(byte_len) = i32::try_from(bytes.len()) else {
        // MultiByteToWideChar accepts a signed 32-bit byte count. Avoid wrapping
        // a larger allocation into a negative length; lossy UTF-8 is the same
        // deterministic fallback used when Windows rejects the conversion.
        return String::from_utf8_lossy(bytes).into_owned();
    };
    let cp = acp();
    // SAFETY: pointer/length pairs describe the same slice; the probe call with a
    // null destination is the documented way to size the output buffer.
    unsafe {
        let needed =
            win::MultiByteToWideChar(cp, 0, bytes.as_ptr(), byte_len, std::ptr::null_mut(), 0);
        if needed <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut buf = vec![0u16; needed as usize];
        let written =
            win::MultiByteToWideChar(cp, 0, bytes.as_ptr(), byte_len, buf.as_mut_ptr(), needed);
        String::from_utf16_lossy(&buf[..written.max(0) as usize])
    }
}

#[cfg(windows)]
fn ansi_to_string_strict(bytes: &[u8]) -> Result<String, String> {
    const MB_ERR_INVALID_CHARS: u32 = 0x0000_0008;

    if bytes.is_empty() {
        return Ok(String::new());
    }
    let byte_len =
        i32::try_from(bytes.len()).map_err(|_| "ANSI input exceeds the Win32 length limit")?;
    let cp = acp();
    let needed = unsafe {
        win::MultiByteToWideChar(
            cp,
            MB_ERR_INVALID_CHARS,
            bytes.as_ptr(),
            byte_len,
            std::ptr::null_mut(),
            0,
        )
    };
    if needed <= 0 {
        return Err(format!("invalid byte sequence for ANSI code page {cp}"));
    }
    let mut units = vec![0u16; needed as usize];
    let written = unsafe {
        win::MultiByteToWideChar(
            cp,
            MB_ERR_INVALID_CHARS,
            bytes.as_ptr(),
            byte_len,
            units.as_mut_ptr(),
            needed,
        )
    };
    if written != needed {
        return Err(format!("failed to decode ANSI code page {cp}"));
    }
    String::from_utf16(&units).map_err(|_| format!("ANSI code page {cp} produced invalid UTF-16"))
}

#[cfg(not(windows))]
pub fn acp() -> u32 {
    1252
}

/// Non-Windows fallback (used only so the parser is testable off-Windows).
#[cfg(not(windows))]
fn ansi_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| cp1252_char(byte)).collect()
}

#[cfg(not(windows))]
fn ansi_to_string_strict(bytes: &[u8]) -> Result<String, String> {
    Ok(ansi_to_string(bytes))
}

#[cfg(not(windows))]
fn cp1252_char(byte: u8) -> char {
    match byte {
        0x80 => '\u{20ac}',
        0x82 => '\u{201a}',
        0x83 => '\u{0192}',
        0x84 => '\u{201e}',
        0x85 => '\u{2026}',
        0x86 => '\u{2020}',
        0x87 => '\u{2021}',
        0x88 => '\u{02c6}',
        0x89 => '\u{2030}',
        0x8a => '\u{0160}',
        0x8b => '\u{2039}',
        0x8c => '\u{0152}',
        0x8e => '\u{017d}',
        0x91 => '\u{2018}',
        0x92 => '\u{2019}',
        0x93 => '\u{201c}',
        0x94 => '\u{201d}',
        0x95 => '\u{2022}',
        0x96 => '\u{2013}',
        0x97 => '\u{2014}',
        0x98 => '\u{02dc}',
        0x99 => '\u{2122}',
        0x9a => '\u{0161}',
        0x9b => '\u{203a}',
        0x9c => '\u{0153}',
        0x9e => '\u{017e}',
        0x9f => '\u{0178}',
        other => other as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_encoder_emits_regedit4_ascii_without_a_bom() {
        let text = "REGEDIT4\r\n\r\n[HKEY_CURRENT_USER\\Software\\A]\r\n";
        let bytes = encode_ansi(text).unwrap();
        assert_eq!(bytes, text.as_bytes());
        assert!(!bytes.starts_with(&[0xff, 0xfe]));
    }

    #[cfg(windows)]
    #[test]
    fn ansi_encoder_never_best_fit_substitutes_unicode() {
        let encoded = encode_ansi("😀");
        if acp() == 65_001 {
            assert_eq!(encoded.unwrap(), "😀".as_bytes());
        } else {
            assert!(encoded.is_err());
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn cp1252_fallback_rejects_loss_instead_of_substituting() {
        assert_eq!(encode_ansi("€").unwrap(), vec![0x80]);
        assert!(encode_ansi("😀").is_err());
    }

    #[test]
    fn strict_decoder_rejects_truncated_or_malformed_unicode() {
        assert!(decode_strict(&[0xff, 0xfe, 0x41])
            .unwrap_err()
            .contains("odd trailing byte"));
        assert!(decode_strict(&[0xff, 0xfe, 0x00, 0xd8])
            .unwrap_err()
            .contains("unpaired surrogate"));
        assert!(decode_strict(&[0xef, 0xbb, 0xbf, 0xff])
            .unwrap_err()
            .contains("invalid UTF-8"));
    }

    #[cfg(not(windows))]
    #[test]
    fn cp1252_fallback_decodes_extension_characters_consistently() {
        assert_eq!(decode_strict(&[0x80]).unwrap().0, "€");
    }
}
