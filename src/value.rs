//! Pure registry-value conversion shared by file parsers and the Win32 engine.
//!
//! Keeping this free of registry handles lets every text/binary reader run
//! under libFuzzer without linking the live-registry implementation.

use crate::model::*;

/// Model value -> `(type, bytes)` ready for `RegSetValueEx`.
/// Returns `None` for `RegData::Delete`, which is not a write.
pub fn data_to_raw(d: &RegData) -> Option<(u32, Vec<u8>)> {
    match d {
        RegData::Delete => None,
        RegData::Sz(s) => Some((REG_SZ, utf16_nul(s))),
        RegData::Dword(v) => Some((REG_DWORD, v.to_le_bytes().to_vec())),
        RegData::Hex { ty, bytes } => Some((*ty, bytes.clone())),
    }
}

/// `(type, bytes)` from the API -> model value.
pub fn raw_to_data(ty: u32, bytes: &[u8]) -> RegData {
    match ty {
        REG_SZ => match clean_string(bytes) {
            Some(s) => RegData::Sz(s),
            None => RegData::Hex {
                ty,
                bytes: bytes.to_vec(),
            },
        },
        REG_DWORD if bytes.len() == 4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(bytes);
            RegData::Dword(u32::from_le_bytes(a))
        }
        _ => RegData::Hex {
            ty,
            bytes: bytes.to_vec(),
        },
    }
}

pub fn utf16_nul(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2 + 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

pub(crate) fn clean_string(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }
    if !bytes.len().is_multiple_of(2) || !bytes.ends_with(&[0, 0]) {
        return None;
    }
    let units: Vec<u16> = bytes[..bytes.len() - 2]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    if units.contains(&0) {
        return None;
    }
    let s = String::from_utf16(&units).ok()?;
    if s.chars().any(|c| (c as u32) < 0x20) {
        return None;
    }
    Some(s)
}

/// Parse a `-t TYPE -d DATA` pair into a model value.
pub fn parse_typed(ty: &str, data: &str) -> Result<RegData, String> {
    let t = ty.trim().to_ascii_uppercase();
    let t = t.strip_prefix("REG_").unwrap_or(&t);
    match t {
        "SZ" => Ok(RegData::Sz(data.to_string())),
        "EXPAND_SZ" => Ok(RegData::Hex {
            ty: REG_EXPAND_SZ,
            bytes: utf16_nul(data),
        }),
        "MULTI_SZ" => {
            let mut bytes = Vec::new();
            for part in data.split("\\0").filter(|s| !s.is_empty()) {
                bytes.extend_from_slice(&utf16_nul(part));
            }
            bytes.extend_from_slice(&[0, 0]);
            Ok(RegData::Hex {
                ty: REG_MULTI_SZ,
                bytes,
            })
        }
        "DWORD" => parse_int(data)
            .and_then(|v| u32::try_from(v).ok())
            .map(RegData::Dword)
            .ok_or_else(|| format!("invalid DWORD value {data:?}")),
        "QWORD" => parse_int(data)
            .map(|v| RegData::Hex {
                ty: REG_QWORD,
                bytes: v.to_le_bytes().to_vec(),
            })
            .ok_or_else(|| format!("invalid QWORD value {data:?}")),
        "BINARY" | "NONE" => {
            let cleaned: String = data
                .chars()
                .filter(|c| !matches!(c, ' ' | ',' | '-' | ':'))
                .collect();
            if !cleaned.len().is_multiple_of(2) {
                return Err("binary data must have an even number of hex digits".into());
            }
            let mut bytes = Vec::with_capacity(cleaned.len() / 2);
            for pair in cleaned.as_bytes().chunks(2) {
                let s = std::str::from_utf8(pair).map_err(|_| "invalid hex".to_string())?;
                bytes.push(
                    u8::from_str_radix(s, 16).map_err(|_| format!("invalid hex byte {s:?}"))?,
                );
            }
            Ok(RegData::Hex {
                ty: if t == "BINARY" { REG_BINARY } else { REG_NONE },
                bytes,
            })
        }
        _ => Err(format!(
            "unknown type {ty:?}; expected one of REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, \
             REG_DWORD, REG_QWORD, REG_BINARY, REG_NONE"
        )),
    }
}

fn parse_int(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse::<u64>().ok(),
    }
}
