//! JSON input — the format to generate from another program.
//!
//! Two shapes are accepted. The **compact** form is what you write by hand:
//!
//! ```json
//! {
//!   "HKCU\\Software\\Acme": {
//!     "Server": "acme.test",
//!     "Port":   8080,
//!     "Enabled": true,
//!     "Blob":   { "type": "REG_BINARY", "data": "01 02 ff" },
//!     "Legacy": null
//!   }
//! }
//! ```
//!
//! JSON types map on sight: string → `REG_SZ`, integer → `REG_DWORD` (or
//! `REG_QWORD` when it does not fit), boolean → `REG_DWORD` 0/1, array of
//! strings → `REG_MULTI_SZ`, `null` → delete the value.
//!
//! The **explicit** form is what a tool emits, and can express key deletion and
//! any type by name:
//!
//! ```json
//! { "keys": [
//!     { "path": "HKCU\\Software\\Acme", "delete": false,
//!       "values": [ { "name": "Port", "type": "REG_DWORD", "data": 8080 } ] }
//! ] }
//! ```
//!
//! The parser is hand-written: pulling in a JSON crate for this would be the
//! only dependency in the whole binary.

use crate::model::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

pub fn read(bytes: &[u8]) -> Result<(Vec<KeyBlock>, Vec<String>), String> {
    let (text, _) = crate::encoding::decode(bytes);
    let v = parse(&text)?;
    let mut notes = Vec::new();
    let mut blocks = Vec::new();

    let root = match &v {
        // { "keys": [...] } or the compact map.
        Json::Obj(fields) => {
            if let Some((_, keys)) = fields.iter().find(|(k, _)| k == "keys") {
                notes.push("explicit form ({\"keys\": [...]})".into());
                return explicit(keys, notes);
            }
            notes.push("compact form (path -> {name: value})".into());
            fields.clone()
        }
        // A bare array is always the explicit form.
        Json::Arr(_) => {
            notes.push("explicit form (top-level array)".into());
            return explicit(&v, notes);
        }
        other => {
            return Err(format!(
                "top level must be an object or array, found {}",
                kind(other)
            ))
        }
    };

    for (path, body) in root {
        let mut block = crate::formats::block(&path, 0)?;
        match body {
            Json::Null => block.delete = true,
            Json::Obj(values) => {
                for (name, raw) in values {
                    block.values.push(ValueEntry {
                        name: crate::formats::value_name(&name),
                        data: data_of(&raw, &name)?,
                        line: 0,
                    });
                }
            }
            other => {
                return Err(format!(
                    "{path:?} must map to an object of values or null, found {}",
                    kind(&other)
                ))
            }
        }
        blocks.push(block);
    }
    Ok((blocks, notes))
}

fn explicit(v: &Json, notes: Vec<String>) -> Result<(Vec<KeyBlock>, Vec<String>), String> {
    let Json::Arr(items) = v else {
        return Err(format!("\"keys\" must be an array, found {}", kind(v)));
    };
    let mut blocks = Vec::new();

    for (i, item) in items.iter().enumerate() {
        let Json::Obj(f) = item else {
            return Err(format!("keys[{i}] must be an object, found {}", kind(item)));
        };
        let get = |n: &str| f.iter().find(|(k, _)| k == n).map(|(_, v)| v);

        let path = match get("path").or_else(|| get("key")) {
            Some(Json::Str(s)) => s.clone(),
            _ => return Err(format!("keys[{i}] is missing a string \"path\"")),
        };
        let mut block = crate::formats::block(&path, i + 1)?;
        block.delete = matches!(get("delete"), Some(Json::Bool(true)));

        if let Some(values) = get("values") {
            match values {
                Json::Arr(list) => {
                    for (j, entry) in list.iter().enumerate() {
                        let Json::Obj(vf) = entry else {
                            return Err(format!(
                                "keys[{i}].values[{j}] must be an object, found {}",
                                kind(entry)
                            ));
                        };
                        let vget = |n: &str| vf.iter().find(|(k, _)| k == n).map(|(_, v)| v);
                        let name = match vget("name") {
                            Some(Json::Str(s)) => s.clone(),
                            None => String::new(),
                            Some(o) => {
                                return Err(format!(
                                    "keys[{i}].values[{j}].name must be a string, found {}",
                                    kind(o)
                                ))
                            }
                        };
                        let raw = vget("data").cloned().unwrap_or(Json::Null);
                        let data = match vget("type") {
                            Some(Json::Str(t)) => {
                                typed(t, &raw).map_err(|e| format!("keys[{i}].values[{j}]: {e}"))?
                            }
                            None => data_of(&raw, &name)?,
                            Some(o) => {
                                return Err(format!(
                                    "keys[{i}].values[{j}].type must be a string, found {}",
                                    kind(o)
                                ))
                            }
                        };
                        block.values.push(ValueEntry {
                            name: crate::formats::value_name(&name),
                            data,
                            line: i + 1,
                        });
                    }
                }
                // Also accept the compact {name: value} map inside an entry.
                Json::Obj(map) => {
                    for (name, raw) in map {
                        block.values.push(ValueEntry {
                            name: crate::formats::value_name(name),
                            data: data_of(raw, name)?,
                            line: i + 1,
                        });
                    }
                }
                o => {
                    return Err(format!(
                        "keys[{i}].values must be an array or object, found {}",
                        kind(o)
                    ))
                }
            }
        }
        blocks.push(block);
    }
    Ok((blocks, notes))
}

/// Infer the registry type from the JSON type.
fn data_of(v: &Json, name: &str) -> Result<RegData, String> {
    Ok(match v {
        Json::Null => RegData::Delete,
        Json::Str(s) => RegData::Sz(s.clone()),
        Json::Bool(b) => RegData::Dword(u32::from(*b)),
        Json::Int(i) => {
            if let Ok(v) = u32::try_from(*i) {
                RegData::Dword(v)
            } else {
                // Too wide for a DWORD: widen rather than truncate.
                RegData::Hex {
                    ty: REG_QWORD,
                    bytes: (*i as u64).to_le_bytes().to_vec(),
                }
            }
        }
        Json::Num(f) => {
            return Err(format!(
                "{name:?}: the registry has no floating-point type ({f}); \
                 use a string, or an explicit \"type\""
            ))
        }
        Json::Arr(items) => {
            let mut bytes = Vec::new();
            for it in items {
                match it {
                    Json::Str(s) => bytes.extend_from_slice(&crate::engine::utf16_nul(s)),
                    other => {
                        return Err(format!(
                            "{name:?}: an array must hold strings for REG_MULTI_SZ, found {}",
                            kind(other)
                        ))
                    }
                }
            }
            bytes.extend_from_slice(&[0, 0]);
            RegData::Hex {
                ty: REG_MULTI_SZ,
                bytes,
            }
        }
        // { "type": ..., "data": ... } used as a value directly.
        Json::Obj(f) => {
            let t = f.iter().find(|(k, _)| k == "type").map(|(_, v)| v);
            let d = f
                .iter()
                .find(|(k, _)| k == "data")
                .map(|(_, v)| v)
                .cloned()
                .unwrap_or(Json::Null);
            match t {
                Some(Json::Str(t)) => typed(t, &d).map_err(|e| format!("{name:?}: {e}"))?,
                _ => return Err(format!("{name:?}: an object value needs a string \"type\"")),
            }
        }
    })
}

/// Explicit `"type"` wins over the JSON type; the data is coerced to match.
fn typed(t: &str, v: &Json) -> Result<RegData, String> {
    if matches!(v, Json::Null) {
        return Ok(RegData::Delete);
    }
    let as_text = match v {
        Json::Str(s) => s.clone(),
        Json::Int(i) => i.to_string(),
        Json::Bool(b) => u8::from(*b).to_string(),
        Json::Arr(items) => {
            let mut parts = Vec::new();
            for it in items {
                match it {
                    Json::Str(s) => parts.push(s.clone()),
                    other => {
                        return Err(format!(
                            "array elements must be strings, found {}",
                            kind(other)
                        ))
                    }
                }
            }
            // parse_typed uses the reg.exe convention for REG_MULTI_SZ.
            parts.join("\\0")
        }
        other => return Err(format!("cannot use {} as {t} data", kind(other))),
    };
    crate::engine::parse_typed(t, &as_text)
}

fn kind(v: &Json) -> &'static str {
    match v {
        Json::Null => "null",
        Json::Bool(_) => "a boolean",
        Json::Num(_) | Json::Int(_) => "a number",
        Json::Str(_) => "a string",
        Json::Arr(_) => "an array",
        Json::Obj(_) => "an object",
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub fn parse(text: &str) -> Result<Json, String> {
    let b: Vec<char> = text.chars().collect();
    let mut p = P { b: &b, i: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i < p.b.len() {
        return Err(format!("trailing content at character {}", p.i + 1));
    }
    Ok(v)
}

struct P<'a> {
    b: &'a [char],
    i: usize,
}

impl<'a> P<'a> {
    fn ws(&mut self) {
        while let Some(c) = self.b.get(self.i) {
            if c.is_whitespace() {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn at(&self) -> Result<char, String> {
        self.b
            .get(self.i)
            .copied()
            .ok_or_else(|| "unexpected end of JSON".to_string())
    }

    fn eat(&mut self, c: char) -> Result<(), String> {
        if self.at()? != c {
            return Err(format!(
                "expected {c:?} at character {}, found {:?}",
                self.i + 1,
                self.b[self.i]
            ));
        }
        self.i += 1;
        Ok(())
    }

    fn lit(&mut self, s: &str) -> bool {
        if self.b[self.i..].starts_with(&s.chars().collect::<Vec<_>>()[..]) {
            self.i += s.chars().count();
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.at()? {
            '{' => self.object(),
            '[' => self.array(),
            '"' => Ok(Json::Str(self.string()?)),
            't' if self.lit("true") => Ok(Json::Bool(true)),
            'f' if self.lit("false") => Ok(Json::Bool(false)),
            'n' if self.lit("null") => Ok(Json::Null),
            c if c == '-' || c.is_ascii_digit() => self.number(),
            c => Err(format!("unexpected {c:?} at character {}", self.i + 1)),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.eat('{')?;
        let mut out = Vec::new();
        let mut seen = BTreeMap::new();
        self.ws();
        if self.at()? == '}' {
            self.i += 1;
            return Ok(Json::Obj(out));
        }
        loop {
            self.ws();
            let k = self.string()?;
            // Duplicate keys in a registry document are always a mistake.
            if let Some(prev) = seen.insert(k.clone(), self.i) {
                return Err(format!(
                    "duplicate key {k:?} (first seen at character {})",
                    prev + 1
                ));
            }
            self.ws();
            self.eat(':')?;
            let v = self.value()?;
            out.push((k, v));
            self.ws();
            match self.at()? {
                ',' => self.i += 1,
                '}' => {
                    self.i += 1;
                    return Ok(Json::Obj(out));
                }
                c => {
                    return Err(format!(
                        "expected ',' or '}}' at character {}, found {c:?}",
                        self.i + 1
                    ))
                }
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.eat('[')?;
        let mut out = Vec::new();
        self.ws();
        if self.at()? == ']' {
            self.i += 1;
            return Ok(Json::Arr(out));
        }
        loop {
            out.push(self.value()?);
            self.ws();
            match self.at()? {
                ',' => self.i += 1,
                ']' => {
                    self.i += 1;
                    return Ok(Json::Arr(out));
                }
                c => {
                    return Err(format!(
                        "expected ',' or ']' at character {}, found {c:?}",
                        self.i + 1
                    ))
                }
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.eat('"')?;
        let mut s = String::new();
        loop {
            let c = self.at()?;
            self.i += 1;
            match c {
                '"' => return Ok(s),
                '\\' => {
                    let e = self.at()?;
                    self.i += 1;
                    match e {
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        '/' => s.push('/'),
                        'b' => s.push('\u{8}'),
                        'f' => s.push('\u{c}'),
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        'u' => {
                            let hi = self.hex4()?;
                            // Surrogate pair.
                            if (0xD800..0xDC00).contains(&hi) {
                                if self.at()? == '\\' {
                                    self.i += 1;
                                    self.eat('u')?;
                                    let lo = self.hex4()?;
                                    let cp = 0x10000
                                        + ((hi as u32 - 0xD800) << 10)
                                        + (lo as u32 - 0xDC00);
                                    s.push(char::from_u32(cp).ok_or("invalid surrogate pair")?);
                                    continue;
                                }
                                return Err("lone high surrogate in \\u escape".into());
                            }
                            s.push(char::from_u32(hi as u32).ok_or("invalid \\u escape")?);
                        }
                        // Far and away the most common authoring mistake here
                        // is a Windows path written with single backslashes,
                        // so name the fix instead of just the rule.
                        other if other.is_alphanumeric() => {
                            return Err(format!(
                            "invalid escape \\{other} at character {}: JSON has no such escape. \
                                 A Windows registry path needs doubled backslashes — \
                                 write \"HKCU\\\\Software\\\\Acme\", not \"HKCU\\Software\\Acme\".",
                            self.i
                        ))
                        }
                        other => {
                            return Err(format!("invalid escape \\{other} at character {}", self.i))
                        }
                    }
                }
                c if (c as u32) < 0x20 => {
                    return Err(format!(
                        "raw control character U+{:04X} in string",
                        c as u32
                    ))
                }
                c => s.push(c),
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, String> {
        let mut v: u16 = 0;
        for _ in 0..4 {
            let c = self.at()?;
            self.i += 1;
            v = v
                .checked_mul(16)
                .and_then(|v| c.to_digit(16).map(|d| v + d as u16))
                .ok_or("invalid \\u escape")?;
        }
        Ok(v)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.at()? == '-' {
            self.i += 1;
        }
        while matches!(self.b.get(self.i), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
        let mut float = false;
        if matches!(self.b.get(self.i), Some('.')) {
            float = true;
            self.i += 1;
            while matches!(self.b.get(self.i), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if matches!(self.b.get(self.i), Some('e') | Some('E')) {
            float = true;
            self.i += 1;
            if matches!(self.b.get(self.i), Some('+') | Some('-')) {
                self.i += 1;
            }
            while matches!(self.b.get(self.i), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        let s: String = self.b[start..self.i].iter().collect();
        if float {
            s.parse::<f64>()
                .map(Json::Num)
                .map_err(|_| format!("invalid number {s:?}"))
        } else {
            s.parse::<i64>()
                .map(Json::Int)
                .map_err(|_| format!("number {s:?} is out of range"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_form_infers_types() {
        let src = r#"{
          "HKCU\\Software\\Acme": {
            "Server": "acme.test",
            "Port": 8080,
            "Enabled": true,
            "Big": 5000000000,
            "List": ["a", "b"],
            "Blob": { "type": "REG_BINARY", "data": "01 02 ff" },
            "Legacy": null
          }
        }"#;
        let (blocks, _) = read(src.as_bytes()).unwrap();
        assert_eq!(blocks.len(), 1);
        let v = |n: &str| {
            blocks[0]
                .values
                .iter()
                .find(|v| matches!(&v.name, ValueName::Named(x) if x == n))
                .unwrap()
                .data
                .clone()
        };
        assert_eq!(v("Server"), RegData::Sz("acme.test".into()));
        assert_eq!(v("Port"), RegData::Dword(8080));
        assert_eq!(v("Enabled"), RegData::Dword(1));
        assert_eq!(
            v("Big").type_id(),
            Some(REG_QWORD),
            "widen rather than truncate"
        );
        assert_eq!(v("List").type_id(), Some(REG_MULTI_SZ));
        assert_eq!(
            v("Blob"),
            RegData::Hex {
                ty: REG_BINARY,
                bytes: vec![1, 2, 255]
            }
        );
        assert_eq!(v("Legacy"), RegData::Delete);
    }

    #[test]
    fn explicit_form_supports_key_delete() {
        let src = r#"{ "keys": [
            { "path": "HKCU\\Software\\Gone", "delete": true },
            { "path": "HKCU\\Software\\Acme",
              "values": [ { "name": "Port", "type": "REG_DWORD", "data": 8080 } ] }
        ] }"#;
        let (blocks, _) = read(src.as_bytes()).unwrap();
        assert!(blocks[0].delete);
        assert_eq!(blocks[1].values[0].data, RegData::Dword(8080));
    }

    #[test]
    fn null_key_body_deletes_the_key() {
        let (blocks, _) = read(br#"{ "HKCU\\Software\\Gone": null }"#).unwrap();
        assert!(blocks[0].delete);
    }

    #[test]
    fn floats_are_rejected_with_a_reason() {
        let e = read(br#"{ "HKCU\\A": { "X": 1.5 } }"#).unwrap_err();
        assert!(e.contains("floating-point"), "{e}");
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let e = parse(r#"{ "a": 1, "a": 2 }"#).unwrap_err();
        assert!(e.contains("duplicate"), "{e}");
    }

    #[test]
    fn parses_escapes_and_surrogate_pairs() {
        let Json::Str(s) = parse(r#""aA\n\\\"😀""#).unwrap() else {
            panic!()
        };
        assert_eq!(s, "aA\n\\\"\u{1F600}");
        assert!(
            parse("\"raw\ttab\"").is_err(),
            "control chars must be escaped"
        );
    }

    #[test]
    fn rejects_trailing_content_and_bad_roots() {
        assert!(parse("{} {}").is_err());
        assert!(read(b"42").is_err());
    }
}
