//! In-memory model of a `.reg` file.
//!
//! Design rule: **byte-exact round-trip**. Anything we cannot losslessly model as
//! a typed value is kept as raw `hex(N)` bytes. A merge/convert tool that silently
//! reinterprets data is worse than useless, so decoding to `String`/`u64` is an
//! opt-in accessor, never the storage form.

use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hive {
    Hklm,
    Hkcu,
    Hkcr,
    Hku,
    Hkcc,
}

impl Hive {
    pub fn parse(s: &str) -> Option<Hive> {
        let up = s.to_ascii_uppercase();
        Some(match up.as_str() {
            "HKEY_LOCAL_MACHINE" | "HKLM" => Hive::Hklm,
            "HKEY_CURRENT_USER" | "HKCU" => Hive::Hkcu,
            "HKEY_CLASSES_ROOT" | "HKCR" => Hive::Hkcr,
            "HKEY_USERS" | "HKU" => Hive::Hku,
            "HKEY_CURRENT_CONFIG" | "HKCC" => Hive::Hkcc,
            _ => return None,
        })
    }

    pub fn long_name(self) -> &'static str {
        match self {
            Hive::Hklm => "HKEY_LOCAL_MACHINE",
            Hive::Hkcu => "HKEY_CURRENT_USER",
            Hive::Hkcr => "HKEY_CLASSES_ROOT",
            Hive::Hku => "HKEY_USERS",
            Hive::Hkcc => "HKEY_CURRENT_CONFIG",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegPath {
    pub hive: Hive,
    /// Subkey path with no leading/trailing backslash. May be empty (hive root).
    pub sub: String,
}

impl RegPath {
    pub fn parse(raw: &str) -> Option<RegPath> {
        let raw = raw.trim();
        let (head, rest) = match raw.split_once('\\') {
            Some((h, r)) => (h, r),
            None => (raw, ""),
        };
        Some(RegPath {
            hive: Hive::parse(head)?,
            sub: rest.trim_matches('\\').to_string(),
        })
    }

    /// Case-insensitive comparison key - registry paths are case-insensitive but
    /// case-preserving, so we never mutate `sub` itself. Uses full Unicode
    /// uppercasing, not ASCII-only: `HKCU\Phần Mềm` and `HKCU\PHẦN MỀM` are the
    /// same key to Windows.
    pub fn fold(&self) -> String {
        format!("{}\\{}", self.hive.long_name(), fold_str(&self.sub))
    }
}

impl fmt::Display for RegPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sub.is_empty() {
            write!(f, "{}", self.hive.long_name())
        } else {
            write!(f, "{}\\{}", self.hive.long_name(), self.sub)
        }
    }
}

/// Case-folding used everywhere identifiers are compared (key paths, value names).
///
/// Deliberately **not** `str::to_uppercase`. That applies full Unicode case
/// mapping, where one character can expand to several: `ß` becomes `SS`, `ﬁ`
/// becomes `FI`. Windows does not do that — the kernel uppercases the registry
/// path one character at a time through `RtlUpcaseUnicodeChar`, so a mapping
/// that would expand is simply not applied.
///
/// The difference is not cosmetic. `HKCU\Software\straße` and
/// `HKCU\Software\STRASSE` are two distinct keys to Windows, and folding them
/// together made `coalesce` merge them and `diff` call them equal — silently
/// discarding one key's values. Anything that expands is therefore left alone.
pub fn fold_str(s: &str) -> String {
    s.chars()
        .map(|c| {
            let mut upper = c.to_uppercase();
            let first = upper.next().unwrap_or(c);
            if upper.next().is_some() {
                c // a 1:many mapping; Windows would not apply it either
            } else {
                first
            }
        })
        .collect()
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ValueName {
    /// `@=` - the key's unnamed default value.
    Default,
    Named(String),
}

impl fmt::Display for ValueName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValueName::Default => write!(f, "(Default)"),
            ValueName::Named(n) => write!(f, "{n}"),
        }
    }
}

// Win32 registry type ids.
pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RegData {
    /// `"name"=-` - delete this value.
    Delete,
    /// Written as a quoted string; always REG_SZ.
    Sz(String),
    /// Written as `dword:xxxxxxxx`.
    Dword(u32),
    /// Written as `hex:` (ty == REG_BINARY) or `hex(N):`. Bytes kept verbatim.
    Hex { ty: u32, bytes: Vec<u8> },
}

impl RegData {
    pub fn type_id(&self) -> Option<u32> {
        match self {
            RegData::Delete => None,
            RegData::Sz(_) => Some(REG_SZ),
            RegData::Dword(_) => Some(REG_DWORD),
            RegData::Hex { ty, .. } => Some(*ty),
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self.type_id() {
            None => "(delete)",
            Some(REG_NONE) => "REG_NONE",
            Some(REG_SZ) => "REG_SZ",
            Some(REG_EXPAND_SZ) => "REG_EXPAND_SZ",
            Some(REG_BINARY) => "REG_BINARY",
            Some(REG_DWORD) => "REG_DWORD",
            Some(REG_DWORD_BIG_ENDIAN) => "REG_DWORD_BIG_ENDIAN",
            Some(REG_LINK) => "REG_LINK",
            Some(REG_MULTI_SZ) => "REG_MULTI_SZ",
            Some(REG_QWORD) => "REG_QWORD",
            Some(_) => "REG_<other>",
        }
    }

    /// Best-effort text rendering for `--output text`. Never used for writing.
    pub fn preview(&self) -> String {
        match self {
            RegData::Delete => "<delete>".into(),
            RegData::Sz(s) => s.clone(),
            RegData::Dword(v) => format!("0x{v:08x} ({v})"),
            RegData::Hex { ty, bytes } => match *ty {
                REG_EXPAND_SZ | REG_SZ | REG_LINK => utf16_from_bytes(bytes).join(""),
                REG_MULTI_SZ => utf16_from_bytes(bytes).join(" | "),
                REG_QWORD if bytes.len() == 8 => {
                    let mut a = [0u8; 8];
                    a.copy_from_slice(bytes);
                    let v = u64::from_le_bytes(a);
                    format!("0x{v:016x} ({v})")
                }
                _ => {
                    let head: Vec<String> =
                        bytes.iter().take(16).map(|b| format!("{b:02x}")).collect();
                    let more = if bytes.len() > 16 { " ..." } else { "" };
                    format!("{}{} [{} bytes]", head.join(" "), more, bytes.len())
                }
            },
        }
    }
}

/// Decode UTF-16LE bytes into NUL-separated strings, dropping the terminator.
/// Handles the classic bug source: MULTI_SZ is double-NUL terminated, and a
/// missing terminator means the consuming app reads garbage past the value.
pub fn utf16_from_bytes(bytes: &[u8]) -> Vec<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    units
        .split(|&u| u == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

#[derive(Clone, Debug)]
pub struct ValueEntry {
    pub name: ValueName,
    pub data: RegData,
    pub line: usize,
}

#[derive(Clone, Debug)]
pub struct KeyBlock {
    pub path: RegPath,
    /// `[-HKEY_...]` - recursively delete the key.
    pub delete: bool,
    pub values: Vec<ValueEntry>,
    pub line: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegFormat {
    /// `Windows Registry Editor Version 5.00`
    V5,
    /// `REGEDIT4`
    V4,
}

impl RegFormat {
    pub fn header(self) -> &'static str {
        match self {
            RegFormat::V5 => "Windows Registry Editor Version 5.00",
            RegFormat::V4 => "REGEDIT4",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RegFile {
    pub format: RegFormat,
    pub encoding: crate::encoding::SourceEncoding,
    pub keys: Vec<KeyBlock>,
}
