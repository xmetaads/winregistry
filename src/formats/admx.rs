//! ADMX / ADML — Group Policy administrative templates.
//!
//! An ADMX is a **schema**, not data: it declares which registry values a policy
//! controls, not what an administrator chose. That distinction drives the whole
//! design here.
//!
//! What is concrete and therefore emitted:
//!   * `<enabledValue>` / `<disabledValue>` on the policy's own `valueName`
//!   * the ADMX default when neither is declared — enabling writes `REG_DWORD 1`,
//!     disabling writes `REG_DWORD 0`
//!   * `<enabledList>` / `<disabledList>` entries, which carry literal values
//!
//! What is **not** emitted, only reported: `<elements>` — `text`, `decimal`,
//! `boolean`, `enum`, `list`, `multiText`. Those hold whatever the administrator
//! typed into the Group Policy editor, and inventing a value for them would put
//! fabricated data into the registry. `regx inspect` lists them so you can see
//! exactly which value names a policy owns.
//!
//! `class` decides the hive: `Machine` → HKLM, `User` → HKCU, `Both` → emitted
//! twice, once per hive, because that is literally what Windows does.
//!
//! An accompanying `.adml` in a language folder (`en-US\Foo.adml`) resolves the
//! `$(string.Id)` display names. It is found automatically next to the ADMX.

use crate::model::*;
use crate::xml::Node;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Enabled,
    Disabled,
}

impl State {
    pub fn parse(s: &str) -> Option<State> {
        match s.trim().to_ascii_lowercase().as_str() {
            "enabled" | "enable" | "on" => Some(State::Enabled),
            "disabled" | "disable" | "off" => Some(State::Disabled),
            _ => None,
        }
    }
}

pub fn read(
    bytes: &[u8],
    path: Option<&Path>,
    state: State,
    only: Option<&str>,
) -> Result<(Vec<KeyBlock>, Vec<String>), String> {
    let (text, _) = crate::encoding::decode(bytes);
    let root = crate::xml::parse(&text)?;
    if !root.name.eq_ignore_ascii_case("policyDefinitions") {
        return Err(format!(
            "not an ADMX file: the root element is <{}>, expected <policyDefinitions>",
            root.name
        ));
    }

    let strings = path.map(load_adml).unwrap_or_default();
    let mut notes = Vec::new();
    if !strings.is_empty() {
        notes.push(format!("{} display string(s) resolved from the ADML", strings.len()));
    }

    let policies: Vec<&Node> = root
        .kid("policies")
        .map(|p| p.kids("policy").collect())
        .unwrap_or_default();

    if policies.is_empty() {
        return Err("this ADMX declares no <policy> elements".into());
    }

    let mut blocks: Vec<KeyBlock> = Vec::new();
    let mut matched = 0usize;
    let mut skipped_elements = 0usize;

    for p in &policies {
        let name = p.attr("name").unwrap_or("(unnamed)");
        if let Some(want) = only {
            if !name.eq_ignore_ascii_case(want) {
                continue;
            }
        }
        matched += 1;

        let Some(key) = p.attr("key") else {
            notes.push(format!("policy {name}: no key attribute, skipped"));
            continue;
        };

        let hives = match p.attr("class").unwrap_or("Machine").to_ascii_lowercase().as_str() {
            "user" => vec![Hive::Hkcu],
            "both" => vec![Hive::Hklm, Hive::Hkcu],
            _ => vec![Hive::Hklm],
        };

        let display = p
            .attr("displayName")
            .map(|d| resolve(d, &strings))
            .unwrap_or_else(|| name.to_string());

        for hive in hives {
            let path = RegPath { hive, sub: key.trim_matches('\\').to_string() };
            let mut entries: Vec<ValueEntry> = Vec::new();

            if let Some(vn) = p.attr("valueName") {
                let data = match state {
                    State::Enabled => value_of(p.kid("enabledValue"))
                        // The documented default when the ADMX omits it.
                        .unwrap_or(RegData::Dword(1)),
                    State::Disabled => value_of(p.kid("disabledValue"))
                        .unwrap_or(RegData::Dword(0)),
                };
                entries.push(ValueEntry {
                    name: crate::formats::value_name(vn),
                    data,
                    line: 0,
                });
            }

            // enabledList / disabledList carry literal values, so they are safe
            // to emit; each item may override the key.
            let list_tag = match state {
                State::Enabled => "enabledList",
                State::Disabled => "disabledList",
            };
            if let Some(list) = p.kid(list_tag) {
                let default_key = list.attr("defaultKey").unwrap_or(key);
                for item in list.kids("item") {
                    let Some(vn) = item.attr("valueName") else { continue };
                    let item_key = item.attr("key").unwrap_or(default_key);
                    let data = value_of(item.kid("value")).unwrap_or(RegData::Dword(1));
                    push(
                        &mut blocks,
                        RegPath { hive, sub: item_key.trim_matches('\\').to_string() },
                        ValueEntry { name: crate::formats::value_name(vn), data, line: 0 },
                    );
                }
            }

            if !entries.is_empty() {
                for e in entries {
                    push(&mut blocks, path.clone(), e);
                }
            } else if p.kid("elements").is_none() && p.kid(list_tag).is_none() {
                // Nothing concrete at all: still record that the key is involved.
                block_for(&mut blocks, path.clone());
            }
        }

        // Report the parts that need an administrator's input.
        if let Some(elements) = p.kid("elements") {
            let mut described = Vec::new();
            for el in &elements.children {
                let vn = el.attr("valueName").unwrap_or("(per-item)");
                let ekey = el.attr("key").unwrap_or(key);
                described.push(format!("{}:{vn} under {ekey}", el.name));
                skipped_elements += 1;
            }
            if !described.is_empty() {
                notes.push(format!(
                    "policy {display:?} has {} element(s) whose data an administrator supplies; \
                     not emitted: {}",
                    described.len(),
                    described.join(", ")
                ));
            }
        }
    }

    if matched == 0 {
        return Err(match only {
            Some(w) => format!("no policy named {w:?} in this ADMX"),
            None => "no usable policy found".into(),
        });
    }

    notes.insert(
        0,
        format!(
            "{matched} of {} policy definition(s), rendered in the {} state",
            policies.len(),
            match state {
                State::Enabled => "enabled",
                State::Disabled => "disabled",
            }
        ),
    );
    if skipped_elements > 0 {
        notes.push(format!(
            "{skipped_elements} element value(s) omitted — an ADMX declares which values a policy \
             owns, not what was configured. Read the real settings from a Registry.pol instead."
        ));
    }
    Ok((blocks, notes))
}

/// `<decimal value="1"/>`, `<longDecimal value="..."/>`, `<string>x</string>`,
/// `<delete/>`.
fn value_of(node: Option<&Node>) -> Option<RegData> {
    let n = node?;
    for child in &n.children {
        match child.name.to_ascii_lowercase().as_str() {
            "decimal" => {
                let v: u32 = child.attr("value")?.trim().parse().ok()?;
                return Some(RegData::Dword(v));
            }
            "longdecimal" => {
                let v: u64 = child.attr("value")?.trim().parse().ok()?;
                return Some(RegData::Hex { ty: REG_QWORD, bytes: v.to_le_bytes().to_vec() });
            }
            "string" => return Some(RegData::Sz(child.text.clone())),
            "delete" => return Some(RegData::Delete),
            _ => {}
        }
    }
    None
}

/// Resolve `$(string.Id)` against the ADML string table.
fn resolve(raw: &str, strings: &BTreeMap<String, String>) -> String {
    let Some(inner) = raw.strip_prefix("$(").and_then(|s| s.strip_suffix(')')) else {
        return raw.to_string();
    };
    let id = inner.strip_prefix("string.").unwrap_or(inner);
    strings.get(id).cloned().unwrap_or_else(|| raw.to_string())
}

/// Find and read the ADML beside the ADMX. Windows keeps them in language
/// folders, so `Acme.admx` pairs with `en-US\Acme.adml`. A missing ADML is not
/// an error — it only costs display names.
fn load_adml(admx: &Path) -> BTreeMap<String, String> {
    let Some(dir) = admx.parent() else { return BTreeMap::new() };
    let stem = admx.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();

    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    // Prefer the machine's own language, then English, then anything present.
    for lang in ["en-US", "en-GB"] {
        candidates.push(dir.join(lang).join(format!("{stem}.adml")));
    }
    candidates.push(dir.join(format!("{stem}.adml")));
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if e.path().is_dir() {
                candidates.push(e.path().join(format!("{stem}.adml")));
            }
        }
    }

    for c in candidates {
        let Ok(bytes) = std::fs::read(&c) else { continue };
        let (text, _) = crate::encoding::decode(&bytes);
        let Ok(root) = crate::xml::parse(&text) else { continue };
        let mut out = BTreeMap::new();
        for table in root.descendants("stringTable") {
            for s in table.kids("string") {
                if let Some(id) = s.attr("id") {
                    out.insert(id.to_string(), s.text.clone());
                }
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    BTreeMap::new()
}

fn block_for<'a>(blocks: &'a mut Vec<KeyBlock>, path: RegPath) -> &'a mut KeyBlock {
    let fold = path.fold();
    if let Some(i) = blocks.iter().position(|b| b.path.fold() == fold) {
        return &mut blocks[i];
    }
    blocks.push(KeyBlock { path, delete: false, values: Vec::new(), line: 0 });
    blocks.last_mut().unwrap()
}

fn push(blocks: &mut Vec<KeyBlock>, path: RegPath, entry: ValueEntry) {
    block_for(blocks, path).values.push(entry);
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADMX: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions revision="1.0" schemaVersion="1.0">
  <policies>
    <policy name="AcmeEnable" class="Machine" displayName="$(string.AcmeEnable)"
            key="Software\Policies\Acme\Client" valueName="Enabled">
      <enabledValue><decimal value="1"/></enabledValue>
      <disabledValue><decimal value="0"/></disabledValue>
      <elements>
        <text id="ServerUrl" valueName="ServerUrl"/>
        <decimal id="MaxRetries" valueName="MaxRetries"/>
      </elements>
    </policy>
    <policy name="AcmeBoth" class="Both"
            key="Software\Policies\Acme\Shared" valueName="Shared"/>
    <policy name="AcmeList" class="User" key="Software\Policies\Acme\L">
      <enabledList defaultKey="Software\Policies\Acme\L">
        <item valueName="A"><value><decimal value="7"/></value></item>
        <item valueName="B" key="Software\Policies\Acme\Other">
          <value><string>text</string></value>
        </item>
      </enabledList>
    </policy>
  </policies>
</policyDefinitions>"#;

    #[test]
    fn emits_enabled_and_disabled_values() {
        let (b, _) = read(ADMX.as_bytes(), None, State::Enabled, Some("AcmeEnable")).unwrap();
        assert_eq!(b[0].path.hive, Hive::Hklm);
        assert_eq!(b[0].values[0].data, RegData::Dword(1));

        let (b, _) = read(ADMX.as_bytes(), None, State::Disabled, Some("AcmeEnable")).unwrap();
        assert_eq!(b[0].values[0].data, RegData::Dword(0));
    }

    #[test]
    fn elements_are_reported_never_fabricated() {
        let (b, notes) = read(ADMX.as_bytes(), None, State::Enabled, Some("AcmeEnable")).unwrap();
        let names: Vec<String> = b[0].values.iter().map(|v| v.name.to_string()).collect();
        assert_eq!(names, vec!["Enabled"], "element values must not be invented");
        assert!(notes.iter().any(|n| n.contains("ServerUrl")), "{notes:?}");
    }

    #[test]
    fn class_both_emits_into_both_hives() {
        let (b, _) = read(ADMX.as_bytes(), None, State::Enabled, Some("AcmeBoth")).unwrap();
        let hives: Vec<Hive> = b.iter().map(|x| x.path.hive).collect();
        assert!(hives.contains(&Hive::Hklm) && hives.contains(&Hive::Hkcu), "{hives:?}");
    }

    #[test]
    fn missing_enabled_value_uses_the_documented_default() {
        let (b, _) = read(ADMX.as_bytes(), None, State::Enabled, Some("AcmeBoth")).unwrap();
        assert_eq!(b[0].values[0].data, RegData::Dword(1));
    }

    #[test]
    fn enabled_list_items_may_override_the_key() {
        let (b, _) = read(ADMX.as_bytes(), None, State::Enabled, Some("AcmeList")).unwrap();
        let other = b.iter().find(|x| x.path.sub.ends_with("Other")).unwrap();
        assert_eq!(other.values[0].data, RegData::Sz("text".into()));
        let main = b.iter().find(|x| x.path.sub.ends_with("\\L")).unwrap();
        assert_eq!(main.values[0].data, RegData::Dword(7));
    }

    #[test]
    fn rejects_a_non_admx_root_and_unknown_policy() {
        assert!(read(b"<foo/>", None, State::Enabled, None).is_err());
        assert!(read(ADMX.as_bytes(), None, State::Enabled, Some("Nope")).is_err());
    }
}
