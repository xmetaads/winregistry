//! Multi-format input.
//!
//! `.reg` is only one of the shapes registry data arrives in. A locked-down
//! machine hands you a `Registry.pol` from a Group Policy cache; an application
//! ships an `.inf` with an `[AddReg]` section; a colleague sends a spreadsheet.
//! Every reader here funnels into the same [`RegFile`] model, so redirection,
//! coalescing, undo snapshots and apply all work on them unchanged — a new
//! format costs one parser, not a parallel pipeline.

pub mod admx;
pub mod csv;
pub mod gpp;
pub mod inf;
pub mod ini;
pub mod json;
pub mod pol;

use crate::model::*;
use std::fmt;
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// `.reg` — regedit's own text format.
    Reg,
    /// `Registry.pol` — the Group Policy PReg binary.
    Pol,
    /// Setup information file; reads `[AddReg]` / `[DelReg]` sections.
    Inf,
    Json,
    Csv,
    Ini,
    /// Group Policy administrative template (`.admx`, with `.adml` strings).
    Admx,
    /// Group Policy Preferences `Registry.xml`.
    Gpp,
    /// A raw hive file. Not read here — that is `regx hive`.
    Hive,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Reg => "reg",
            Format::Pol => "pol",
            Format::Inf => "inf",
            Format::Json => "json",
            Format::Csv => "csv",
            Format::Ini => "ini",
            Format::Admx => "admx",
            Format::Gpp => "gpp",
            Format::Hive => "hive",
        }
    }

    pub fn parse_name(s: &str) -> Option<Format> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "reg" => Format::Reg,
            "pol" | "preg" | "policy" => Format::Pol,
            "inf" => Format::Inf,
            "json" => Format::Json,
            "csv" | "tsv" => Format::Csv,
            "ini" | "cfg" | "conf" => Format::Ini,
            "admx" | "adml" | "template" => Format::Admx,
            "gpp" | "preferences" => Format::Gpp,
            "hive" | "dat" => Format::Hive,
            _ => return None,
        })
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Knobs a specific reader needs that the file itself cannot supply.
#[derive(Clone, Debug)]
pub struct ReadOptions {
    /// Root that a `Registry.pol`'s relative paths hang off. A .pol records no
    /// hive of its own: the same bytes mean HKLM under `Machine\` and HKCU
    /// under `User\`, so it has to come from outside the file.
    pub pol_root: Hive,
    /// Restrict an INF to one `[AddReg]` section instead of every one found.
    pub inf_section: Option<String>,
    /// Which state of an ADMX policy to render. An ADMX declares both.
    pub admx_state: admx::State,
    /// Restrict an ADMX to a single named policy.
    pub admx_policy: Option<String>,
}

impl Default for ReadOptions {
    fn default() -> Self {
        ReadOptions {
            pol_root: Hive::Hklm,
            inf_section: None,
            admx_state: admx::State::Enabled,
            admx_policy: None,
        }
    }
}

#[derive(Debug)]
pub struct ReadOutcome {
    pub file: RegFile,
    pub format: Format,
    pub notes: Vec<String>,
}

/// Identify the format of `bytes`, using `path` only as a tie-breaker.
///
/// Content wins over extension deliberately: a `Registry.pol` renamed to
/// `.txt` is still a PReg file, and a `.reg` that is really JSON is a mistake
/// worth catching before it reaches the registry.
pub fn detect(bytes: &[u8], path: Option<&Path>) -> Format {
    if bytes.starts_with(b"PReg") {
        return Format::Pol;
    }
    if bytes.starts_with(b"regf") {
        return Format::Hive;
    }

    let (text, _) = crate::encoding::decode(bytes);
    let head: String = text.chars().take(4096).collect();
    let trimmed = head.trim_start();

    let lower = head.to_ascii_lowercase();
    if lower.contains("windows registry editor version") || trimmed.starts_with("REGEDIT4") {
        return Format::Reg;
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') && looks_like_json_array(trimmed) {
        return Format::Json;
    }
    // Both XML dialects are identified by their root element, not the file name:
    // GPP files are always called Registry.xml, and an ADMX may be renamed.
    if trimmed.starts_with("<?xml") || trimmed.starts_with('<') {
        if lower.contains("<policydefinitions") {
            return Format::Admx;
        }
        if lower.contains("<registrysettings") || lower.contains("clsid=\"{9cd4b2f4") {
            return Format::Gpp;
        }
    }
    // An INF is an INI with a [Version] section and at least one AddReg/DelReg
    // directive; checking both avoids claiming every INI file.
    if lower.contains("[version]") && (lower.contains("addreg") || lower.contains("delreg")) {
        return Format::Inf;
    }

    match path.and_then(|p| p.extension()).and_then(|e| e.to_str()) {
        Some(ext) => match ext.to_ascii_lowercase().as_str() {
            "reg" => Format::Reg,
            "pol" => Format::Pol,
            "inf" => Format::Inf,
            "json" => Format::Json,
            "csv" | "tsv" => Format::Csv,
            "ini" | "cfg" | "conf" => Format::Ini,
            "admx" | "adml" => Format::Admx,
            // A bare .xml that reached here matched neither root element above.
            "xml" => Format::Gpp,
            "dat" | "hiv" | "hive" => Format::Hive,
            _ => sniff_text(&head),
        },
        None => sniff_text(&head),
    }
}

/// `[` opens a JSON array only if the first meaningful token inside it looks
/// like JSON. `[HKEY_CURRENT_USER\...]` opens a .reg or .ini key instead.
fn looks_like_json_array(trimmed: &str) -> bool {
    let rest = trimmed[1..].trim_start();
    rest.starts_with('{') || rest.starts_with('"') || rest.starts_with('[') || rest.starts_with(']')
}

fn sniff_text(head: &str) -> Format {
    let first = head
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with(';') && !l.starts_with('#'));

    if let Some(line) = first {
        let l = line.to_ascii_lowercase();
        // A CSV header must name a key column plus at least one of the others.
        if l.contains("key") && (l.contains("type") || l.contains("data") || l.contains("name")) {
            let seps = line.matches(',').count().max(line.matches('\t').count());
            if seps >= 2 {
                return Format::Csv;
            }
        }
        if line.starts_with('[') {
            return Format::Ini;
        }
    }
    Format::Reg
}

/// Read any supported format into the common model.
pub fn read(
    bytes: &[u8],
    path: Option<&Path>,
    forced: Option<Format>,
    opts: &ReadOptions,
) -> Result<ReadOutcome, String> {
    let format = forced.unwrap_or_else(|| detect(bytes, path));

    let (keys, mut notes) = match format {
        Format::Reg => {
            let outcome = crate::parser::parse_bytes(bytes);
            let errs: Vec<String> = outcome
                .diagnostics
                .iter()
                .filter(|d| d.severity == crate::parser::Severity::Error)
                .map(|d| format!("line {}: {}", d.line, d.message))
                .collect();
            if !errs.is_empty() {
                return Err(format!(".reg parse failed:\n  {}", errs.join("\n  ")));
            }
            let notes = outcome
                .diagnostics
                .iter()
                .map(|d| format!("line {}: {}", d.line, d.message))
                .collect();
            (outcome.file.keys, notes)
        }
        Format::Pol => pol::read(bytes, opts.pol_root, path)?,
        Format::Inf => inf::read(bytes, opts.inf_section.as_deref())?,
        Format::Json => json::read(bytes)?,
        Format::Csv => csv::read(bytes)?,
        Format::Ini => ini::read(bytes)?,
        Format::Admx => admx::read(bytes, path, opts.admx_state, opts.admx_policy.as_deref())?,
        Format::Gpp => gpp::read(bytes)?,
        Format::Hive => {
            return Err(
                "this is a registry hive file, not a text format. Use `regx hive <FILE> ...` \
                 to read or write it without administrator rights."
                    .into(),
            )
        }
    };

    // Every reader can emit the same key more than once; fold once here so no
    // downstream stage has to care which format the data came from.
    let (keys, report) = crate::coalesce::coalesce(keys);
    if report.blocks_merged > 0 {
        notes.push(format!(
            "merged {} duplicate key block(s), {} value conflict(s) resolved last-write-wins",
            report.blocks_merged,
            report.conflicts.len()
        ));
    }

    Ok(ReadOutcome {
        file: RegFile {
            format: RegFormat::V5,
            encoding: crate::encoding::SourceEncoding::Utf16Le,
            keys,
        },
        format,
        notes,
    })
}

/// Shared helper: build a key block from a full path string.
pub(crate) fn block(path: &str, line: usize) -> Result<KeyBlock, String> {
    let p = RegPath::parse(path)
        .ok_or_else(|| format!("line {line}: unknown root hive in {path:?}"))?;
    Ok(KeyBlock {
        path: p,
        delete: false,
        values: Vec::new(),
        line,
    })
}

/// Shared helper: `""` and `@` both mean the key's default value.
pub(crate) fn value_name(raw: &str) -> ValueName {
    if raw.is_empty() || raw == "@" {
        ValueName::Default
    } else {
        ValueName::Named(raw.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_by_magic_before_extension() {
        assert_eq!(
            detect(b"PReg\x01\x00\x00\x00", Some(Path::new("x.txt"))),
            Format::Pol
        );
        assert_eq!(detect(b"regf....", Some(Path::new("x.reg"))), Format::Hive);
    }

    #[test]
    fn reg_bracket_is_not_a_json_array() {
        let reg = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\A]\r\n";
        assert_eq!(detect(reg.as_bytes(), None), Format::Reg);
        let ini = "[HKEY_CURRENT_USER\\A]\r\nName=x\r\n";
        assert_eq!(
            detect(ini.as_bytes(), Some(Path::new("a.ini"))),
            Format::Ini
        );
        assert_eq!(detect(b"[ {\"path\": \"HKCU\\\\A\"} ]", None), Format::Json);
    }

    #[test]
    fn inf_needs_both_version_and_addreg() {
        let inf = "[Version]\r\nSignature=\"$WINDOWS NT$\"\r\n[Inst]\r\nAddReg=R\r\n";
        assert_eq!(detect(inf.as_bytes(), None), Format::Inf);
        // A plain INI with a [Version] section must not be claimed as an INF.
        let ini = "[Version]\r\nBuild=3\r\n";
        assert_eq!(
            detect(ini.as_bytes(), Some(Path::new("a.ini"))),
            Format::Ini
        );
    }

    #[test]
    fn hive_is_refused_with_a_pointer_to_the_right_command() {
        let e = read(b"regf\x00\x00\x00\x00", None, None, &ReadOptions::default()).unwrap_err();
        assert!(e.contains("regx hive"), "{e}");
    }
}
