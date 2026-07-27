//! Group Policy Preferences `Registry.xml`.
//!
//! The other half of Group Policy. Where an ADMX declares a *schema* and a
//! `Registry.pol` carries the *policy* branch, GPP writes anywhere in the
//! registry and — crucially — its writes are **not** reverted when the GPO stops
//! applying unless the item says so. That makes reading them worthwhile: a
//! GPP item is often the reason a setting keeps coming back.
//!
//! ```xml
//! <RegistrySettings clsid="{A3CCFC41-...}">
//!   <Registry clsid="{9CD4B2F4-...}" name="Server" status="Server">
//!     <Properties action="U" hive="HKEY_CURRENT_USER" key="Software\Acme"
//!                 name="Server" type="REG_SZ" value="acme.test"/>
//!   </Registry>
//!   <Collection name="Group"> ... </Collection>
//! </RegistrySettings>
//! ```
//!
//! `action` is `C`reate, `R`eplace, `U`pdate or `D`elete. C/R/U all end in a
//! written value, so they map to a set; only D deletes. A `D` with no `name`
//! deletes the whole key.

use crate::model::*;
use crate::xml::Node;

pub fn read(bytes: &[u8]) -> Result<(Vec<KeyBlock>, Vec<String>), String> {
    let (text, _) = crate::encoding::decode(bytes);
    let root = crate::xml::parse(&text)?;

    // The file may be rooted at RegistrySettings, or at a Collection, or be a
    // fragment lifted out of a GPO; accept any of them.
    let items = root.descendants("Registry");
    if items.is_empty() {
        return Err(format!(
            "no <Registry> elements found (root is <{}>); this does not look like a \
             Group Policy Preferences Registry.xml",
            root.name
        ));
    }

    let mut blocks: Vec<KeyBlock> = Vec::new();
    let mut notes = Vec::new();
    let mut deletes = 0usize;
    let mut disabled = 0usize;

    for item in items {
        // A disabled item is present in the file but not applied.
        if item.attr("disabled").map(|d| d == "1").unwrap_or(false) {
            disabled += 1;
            continue;
        }
        let Some(props) = item.kid("Properties") else {
            notes.push(format!(
                "item {:?} has no <Properties>, skipped",
                item.attr("name").unwrap_or("(unnamed)")
            ));
            continue;
        };

        let hive = match props.attr("hive") {
            Some(h) => match Hive::parse(h) {
                Some(h) => h,
                None => {
                    notes.push(format!("unknown hive {h:?}, item skipped"));
                    continue;
                }
            },
            None => {
                notes.push("item has no hive attribute, skipped".into());
                continue;
            }
        };

        let key = props
            .attr("key")
            .unwrap_or("")
            .trim_matches('\\')
            .to_string();
        let path = RegPath { hive, sub: key };
        let action = props.attr("action").unwrap_or("U").to_ascii_uppercase();
        let name = props.attr("name").unwrap_or("");

        if action == "D" {
            deletes += 1;
            if name.is_empty() {
                block_for(&mut blocks, path).delete = true;
            } else {
                push(
                    &mut blocks,
                    path,
                    ValueEntry {
                        name: crate::formats::value_name(name),
                        data: RegData::Delete,
                        line: 0,
                    },
                );
            }
            continue;
        }

        if !matches!(action.as_str(), "C" | "R" | "U") {
            notes.push(format!("unknown action {action:?}, item skipped"));
            continue;
        }

        let ty = props.attr("type").unwrap_or("REG_SZ");
        let data = match decode_value(props, ty) {
            Ok(d) => d,
            Err(e) => {
                notes.push(format!(
                    "{}\\{}: {e}",
                    path,
                    if name.is_empty() { "(Default)" } else { name }
                ));
                continue;
            }
        };

        push(
            &mut blocks,
            path,
            ValueEntry {
                name: crate::formats::value_name(name),
                data,
                line: 0,
            },
        );
    }

    let total: usize = blocks.iter().map(|b| b.values.len()).sum();
    notes.insert(
        0,
        format!(
            "{total} value(s) across {} key(s), {deletes} delete action(s)",
            blocks.len()
        ),
    );
    if disabled > 0 {
        notes.push(format!(
            "{disabled} item(s) marked disabled=\"1\" were skipped"
        ));
    }
    notes.push(
        "GPP writes persist after the GPO stops applying unless the item is set to \
         remove-when-out-of-scope — that is often why a setting reappears"
            .into(),
    );
    Ok((blocks, notes))
}

fn decode_value(props: &Node, ty: &str) -> Result<RegData, String> {
    let upper = ty.trim().to_ascii_uppercase();

    // REG_MULTI_SZ carries its entries as <Values><Value>..</Value></Values>
    // rather than in the value attribute.
    if upper == "REG_MULTI_SZ" {
        if let Some(values) = props.kid("Values") {
            let parts: Vec<String> = values.kids("Value").map(|v| v.text.clone()).collect();
            return crate::engine::parse_typed("REG_MULTI_SZ", &parts.join("\\0"));
        }
    }

    let raw = props.attr("value").unwrap_or("");

    match upper.as_str() {
        // GPP writes DWORD/QWORD as decimal here regardless of displayDecimal,
        // which only controls how the editor shows it.
        "REG_DWORD" | "REG_QWORD" => crate::engine::parse_typed(&upper, raw),
        "REG_BINARY" => crate::engine::parse_typed("REG_BINARY", raw),
        "REG_SZ" | "REG_EXPAND_SZ" | "REG_MULTI_SZ" | "REG_NONE" => {
            crate::engine::parse_typed(&upper, raw)
        }
        other => Err(format!("unsupported type {other:?}")),
    }
}

fn block_for(blocks: &mut Vec<KeyBlock>, path: RegPath) -> &mut KeyBlock {
    let fold = path.fold();
    if let Some(i) = blocks.iter().position(|b| b.path.fold() == fold) {
        return &mut blocks[i];
    }
    blocks.push(KeyBlock {
        path,
        delete: false,
        values: Vec::new(),
        line: 0,
    });
    blocks.last_mut().unwrap()
}

fn push(blocks: &mut Vec<KeyBlock>, path: RegPath, entry: ValueEntry) {
    block_for(blocks, path).values.push(entry);
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}">
  <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="Server">
    <Properties action="U" hive="HKEY_CURRENT_USER" key="Software\Acme"
                name="Server" type="REG_SZ" value="acme.test"/>
  </Registry>
  <Registry name="Port">
    <Properties action="C" hive="HKEY_CURRENT_USER" key="Software\Acme"
                name="Port" type="REG_DWORD" value="8080" displayDecimal="1"/>
  </Registry>
  <Registry name="Recent">
    <Properties action="R" hive="HKEY_CURRENT_USER" key="Software\Acme"
                name="Recent" type="REG_MULTI_SZ">
      <Values><Value>a.txt</Value><Value>b.txt</Value></Values>
    </Properties>
  </Registry>
  <Collection name="Group">
    <Registry name="Legacy">
      <Properties action="D" hive="HKEY_CURRENT_USER" key="Software\Acme" name="Legacy"/>
    </Registry>
    <Registry name="OldKey">
      <Properties action="D" hive="HKEY_CURRENT_USER" key="Software\AcmeOld" name=""/>
    </Registry>
  </Collection>
  <Registry name="Off" disabled="1">
    <Properties action="U" hive="HKEY_CURRENT_USER" key="Software\Acme"
                name="Ignored" type="REG_SZ" value="no"/>
  </Registry>
</RegistrySettings>"#;

    fn val(b: &[KeyBlock], key: &str, name: &str) -> RegData {
        b.iter()
            .find(|x| x.path.sub == key)
            .unwrap()
            .values
            .iter()
            .find(|v| matches!(&v.name, ValueName::Named(n) if n == name))
            .unwrap()
            .data
            .clone()
    }

    #[test]
    fn reads_create_replace_update_as_writes() {
        let (b, _) = read(XML.as_bytes()).unwrap();
        assert_eq!(
            val(&b, "Software\\Acme", "Server"),
            RegData::Sz("acme.test".into())
        );
        assert_eq!(val(&b, "Software\\Acme", "Port"), RegData::Dword(8080));
        assert_eq!(
            val(&b, "Software\\Acme", "Recent").type_id(),
            Some(REG_MULTI_SZ)
        );
    }

    #[test]
    fn multi_sz_comes_from_child_value_elements() {
        let (b, _) = read(XML.as_bytes()).unwrap();
        let RegData::Hex { bytes, .. } = val(&b, "Software\\Acme", "Recent") else {
            panic!()
        };
        assert_eq!(
            crate::model::utf16_from_bytes(&bytes),
            vec!["a.txt", "b.txt"]
        );
    }

    #[test]
    fn delete_action_distinguishes_value_from_key() {
        let (b, _) = read(XML.as_bytes()).unwrap();
        assert_eq!(val(&b, "Software\\Acme", "Legacy"), RegData::Delete);
        let old = b
            .iter()
            .find(|x| x.path.sub == "Software\\AcmeOld")
            .unwrap();
        assert!(old.delete, "action=D with an empty name deletes the key");
    }

    #[test]
    fn items_inside_a_collection_are_found() {
        let (b, _) = read(XML.as_bytes()).unwrap();
        assert!(b.iter().any(|x| x.path.sub == "Software\\AcmeOld"));
    }

    #[test]
    fn disabled_items_are_skipped_and_counted() {
        let (b, notes) = read(XML.as_bytes()).unwrap();
        let acme = b.iter().find(|x| x.path.sub == "Software\\Acme").unwrap();
        assert!(!acme.values.iter().any(|v| v.name.to_string() == "Ignored"));
        assert!(notes.iter().any(|n| n.contains("disabled")), "{notes:?}");
    }

    #[test]
    fn a_file_without_registry_items_is_rejected() {
        assert!(read(br#"<Groups clsid="{x}"><User name="a"/></Groups>"#).is_err());
    }
}
