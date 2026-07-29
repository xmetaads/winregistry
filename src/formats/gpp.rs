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
//! `action` is `C`reate, `R`eplace, `U`pdate or `D`elete. R/U value writes and
//! D deletes map exactly. C is conditional on absence, item-level targeting is
//! conditional on the client environment, and `removePolicy="1"` requires a
//! future undo when scope changes. These become fidelity losses so a caller
//! cannot flatten them into unconditional, permanent writes.

use super::OrderedBlocks;
use crate::model::*;
use crate::xml::Node;

pub fn read(bytes: &[u8]) -> Result<super::ReaderResult, String> {
    let (text, _) = crate::encoding::decode_strict(bytes)?;
    let root = crate::xml::parse(&text)?;

    // The file may be rooted at RegistrySettings, at a Collection, or be one
    // Registry fragment. Walk only the protocol's container grammar rather
    // than finding Registry-looking elements under arbitrary XML wrappers.
    if !matches!(
        root.name.to_ascii_lowercase().as_str(),
        "registrysettings" | "collection" | "registry"
    ) {
        return Err(format!(
            "unexpected GPP root <{}>; expected <RegistrySettings>, <Collection>, or <Registry>",
            root.name
        ));
    }
    if root.name.eq_ignore_ascii_case("RegistrySettings") && root.attr("disabled") == Some("1") {
        return Ok((
            Vec::new(),
            vec![
                "the entire GPP Registry preference type is disabled=\"1\"; no items apply".into(),
            ],
            Vec::new(),
        ));
    }
    let mut items = Vec::new();
    let mut structural_losses = Vec::new();
    collect_items(&root, &mut items, &mut structural_losses);
    if items.is_empty() {
        return Err(format!(
            "no <Registry> elements found (root is <{}>); this does not look like a \
             Group Policy Preferences Registry.xml",
            root.name
        ));
    }

    let mut blocks = OrderedBlocks::new();
    let mut notes = Vec::new();
    let mut losses = structural_losses;
    let mut deletes = 0usize;

    if root.name.eq_ignore_ascii_case("RegistrySettings") {
        if let Some(value) = root.attr("disabled") {
            match value {
                "1" => unreachable!("disabled RegistrySettings returned before item collection"),
                "0" => {}
                _ => losses.push(format!(
                    "invalid disabled attribute {value:?} on <{}>",
                    root.name
                )),
            }
        }
    }

    for item in items {
        // MS-GPPREF places `disabled` on the outer RegistrySettings element,
        // not on an individual Registry instruction.
        if let Some(value) = item.attr("disabled") {
            losses.push(format!(
                "item {:?} has non-schema disabled attribute {value:?}",
                item.attr("name").unwrap_or("(unnamed)")
            ));
            continue;
        }
        let mut invalid_common_attribute = false;
        for attribute in ["removePolicy", "userContext", "bypassErrors"] {
            if let Some(value) = item.attr(attribute) {
                if !matches!(value, "0" | "1") {
                    losses.push(format!(
                        "item {:?} has invalid {attribute} attribute {value:?}",
                        item.attr("name").unwrap_or("(unnamed)")
                    ));
                    invalid_common_attribute = true;
                }
            }
        }
        if invalid_common_attribute {
            continue;
        }
        if item.attr("removePolicy") == Some("1") {
            losses.push(format!(
                "item {:?} uses removePolicy=\"1\", which requires undoing the preference \
                 after the GPO leaves scope",
                item.attr("name").unwrap_or("(unnamed)")
            ));
            continue;
        }
        if item.kid("Filters").is_some() {
            losses.push(format!(
                "item {:?} uses environment-dependent item-level targeting",
                item.attr("name").unwrap_or("(unnamed)")
            ));
            continue;
        }
        let Some(props) = item.kid("Properties") else {
            losses.push(format!(
                "item {:?} has no <Properties>",
                item.attr("name").unwrap_or("(unnamed)")
            ));
            continue;
        };

        let hive = match props.attr("hive") {
            Some(h) => match Hive::parse(h) {
                Some(h) => h,
                None => {
                    losses.push(format!("unknown hive {h:?}"));
                    continue;
                }
            },
            None => {
                losses.push("item has no hive attribute".into());
                continue;
            }
        };

        let Some(key) = props.attr("key").filter(|key| !key.is_empty()) else {
            losses.push("item has no key attribute".into());
            continue;
        };
        let key = key.trim_matches('\\').to_string();
        let path = RegPath { hive, sub: key };
        let action = props.attr("action").unwrap_or("U").to_ascii_uppercase();
        let name = props.attr("name").unwrap_or("");
        let default = match props.attr("default") {
            None | Some("0") => false,
            Some("1") => true,
            Some(value) => {
                losses.push(format!("{path}: invalid default attribute {value:?}"));
                continue;
            }
        };
        if default && !name.is_empty() {
            losses.push(format!(
                "{path}: both default=\"1\" and named value {name:?} are set"
            ));
            continue;
        }
        if props.attr("bitfield") == Some("1") || props.kid("SubProp").is_some() {
            losses.push(format!(
                "{}\\{}: bitfield update depends on the current DWORD and masks",
                path,
                if default {
                    "(Default)"
                } else if name.is_empty() {
                    "(key)"
                } else {
                    name
                }
            ));
            continue;
        }
        let is_value = default || !name.is_empty();
        let value_name = if default {
            ValueName::Default
        } else {
            crate::formats::value_name(name)
        };

        if action == "D" {
            deletes += 1;
            if is_value {
                blocks.push(
                    path,
                    ValueEntry {
                        name: value_name,
                        data: RegData::Delete,
                        line: 0,
                    },
                    0,
                );
            } else {
                blocks.block_for(path, 0).delete = true;
            }
            continue;
        }

        if !matches!(action.as_str(), "C" | "R" | "U") {
            losses.push(format!("unknown action {action:?}"));
            continue;
        }

        if !is_value {
            if props.attr("type").is_some_and(|value| !value.is_empty())
                || props.attr("value").is_some_and(|value| !value.is_empty())
                || props.kid("Values").is_some()
            {
                losses.push(format!(
                    "{path}: key-only action carries value type or data"
                ));
                continue;
            }
            if action == "R" {
                losses.push(format!(
                    "{path}: Replace on a key deletes every value and subkey before recreating it"
                ));
            } else {
                // Create and Update are both an idempotent key creation when
                // the preference item does not target a value.
                blocks.block_for(path, 0);
            }
            continue;
        }

        if action == "C" {
            losses.push(format!(
                "{}\\{}: Create writes only when the target is absent",
                path,
                if default { "(Default)" } else { name }
            ));
            continue;
        }

        let Some(ty) = props.attr("type").filter(|ty| !ty.is_empty()) else {
            losses.push(format!(
                "{}\\{}: value action has no type",
                path,
                if default { "(Default)" } else { name }
            ));
            continue;
        };
        let data = match decode_value(props, ty) {
            Ok(d) => d,
            Err(e) => {
                losses.push(format!(
                    "{}\\{}: {e}",
                    path,
                    if default { "(Default)" } else { name }
                ));
                continue;
            }
        };

        blocks.push(
            path,
            ValueEntry {
                name: value_name,
                data,
                line: 0,
            },
            0,
        );
    }

    let total = blocks.value_count();
    notes.insert(
        0,
        format!(
            "{total} value(s) across {} key(s), {deletes} delete action(s)",
            blocks.len()
        ),
    );
    notes.push(
        "GPP writes persist after the GPO stops applying unless the item is set to \
         remove-when-out-of-scope — that is often why a setting reappears"
            .into(),
    );
    Ok((blocks.into_vec(), notes, losses))
}

fn collect_items<'a>(
    node: &'a Node,
    items: &mut Vec<&'a Node>,
    structural_losses: &mut Vec<String>,
) {
    if node.name.eq_ignore_ascii_case("Registry") {
        items.push(node);
        return;
    }

    for child in &node.children {
        if child.name.eq_ignore_ascii_case("Registry") {
            items.push(child);
        } else if child.name.eq_ignore_ascii_case("Collection") {
            collect_items(child, items, structural_losses);
        } else {
            structural_losses.push(format!(
                "unexpected <{}> inside <{}>; only <Registry> and <Collection> are valid here",
                child.name, node.name
            ));
        }
    }
}

fn decode_value(props: &Node, ty: &str) -> Result<RegData, String> {
    let upper = ty.trim().to_ascii_uppercase();

    // REG_MULTI_SZ carries its entries as <Values><Value>..</Value></Values>
    // rather than in the value attribute.
    if upper == "REG_MULTI_SZ" {
        if let Some(values) = props.kid("Values") {
            let parts: Vec<String> = values.kids("Value").map(|v| v.text.clone()).collect();
            return crate::value::parse_typed("REG_MULTI_SZ", &parts.join("\\0"));
        }
    }

    let raw = props.attr("value").unwrap_or("");

    match upper.as_str() {
        // GPP writes DWORD/QWORD as decimal here regardless of displayDecimal,
        // which only controls how the editor shows it.
        "REG_DWORD" | "REG_QWORD" => crate::value::parse_typed(&upper, raw),
        "REG_BINARY" => crate::value::parse_typed("REG_BINARY", raw),
        "REG_SZ" | "REG_EXPAND_SZ" | "REG_MULTI_SZ" | "REG_NONE" => {
            crate::value::parse_typed(&upper, raw)
        }
        other => Err(format!("unsupported type {other:?}")),
    }
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
        let (b, _, losses) = read(XML.as_bytes()).unwrap();
        assert_eq!(
            val(&b, "Software\\Acme", "Server"),
            RegData::Sz("acme.test".into())
        );
        assert!(!b.iter().any(|block| block
            .values
            .iter()
            .any(|value| matches!(&value.name, ValueName::Named(name) if name == "Port"))));
        assert!(losses.iter().any(|loss| loss.contains("Create writes")));
        assert_eq!(
            val(&b, "Software\\Acme", "Recent").type_id(),
            Some(REG_MULTI_SZ)
        );
    }

    #[test]
    fn multi_sz_comes_from_child_value_elements() {
        let (b, _, _) = read(XML.as_bytes()).unwrap();
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
        let (b, _, _) = read(XML.as_bytes()).unwrap();
        assert_eq!(val(&b, "Software\\Acme", "Legacy"), RegData::Delete);
        let old = b
            .iter()
            .find(|x| x.path.sub == "Software\\AcmeOld")
            .unwrap();
        assert!(old.delete, "action=D with an empty name deletes the key");
    }

    #[test]
    fn items_inside_a_collection_are_found() {
        let (b, _, _) = read(XML.as_bytes()).unwrap();
        assert!(b.iter().any(|x| x.path.sub == "Software\\AcmeOld"));
    }

    #[test]
    fn disabled_preference_type_is_skipped_and_counted() {
        let xml = r#"<RegistrySettings disabled="1">
          <Registry name="Ignored"><Properties action="U" hive="HKCU"
            key="Software\Acme" name="Ignored" type="REG_DWORD" value="1"/></Registry>
        </RegistrySettings>"#;
        let (blocks, notes, losses) = read(xml.as_bytes()).unwrap();
        assert!(blocks.is_empty());
        assert!(losses.is_empty());
        assert!(notes.iter().any(|n| n.contains("entire")), "{notes:?}");

        let item_fragment = r#"<Registry name="NotOuter" disabled="1">
          <Properties action="U" hive="HKCU" key="Software\Acme"
            name="Ignored" type="REG_DWORD" value="1"/>
        </Registry>"#;
        let (blocks, _, losses) = read(item_fragment.as_bytes()).unwrap();
        assert!(blocks.is_empty());
        assert_eq!(losses.len(), 1);
        assert!(losses[0].contains("non-schema disabled"), "{losses:?}");
    }

    #[test]
    fn item_level_targeting_is_never_applied_unconditionally() {
        let xml = r#"<RegistrySettings>
          <Registry name="Targeted">
            <Properties action="U" hive="HKCU" key="Software\Acme"
                        name="Targeted" type="REG_DWORD" value="1"/>
            <Filters><FilterGroup name="Example"/></Filters>
          </Registry>
          <Registry name="Masked">
            <Properties action="U" hive="HKCU" key="Software\Acme"
                        name="Masked" type="REG_DWORD" value="1" bitfield="1">
              <SubProp id="One" value="1" mask="1"/>
            </Properties>
          </Registry>
          <Registry name="RemoveLater" removePolicy="1">
            <Properties action="U" hive="HKCU" key="Software\Acme"
                        name="RemoveLater" type="REG_DWORD" value="1"/>
          </Registry>
          <Registry name="BadContext" userContext="maybe">
            <Properties action="U" hive="HKCU" key="Software\Acme"
                        name="BadContext" type="REG_DWORD" value="1"/>
          </Registry>
          <Registry name="NonSchemaDisabled" disabled="1">
            <Properties action="U" hive="HKCU" key="Software\Acme"
                        name="NonSchemaDisabled" type="REG_DWORD" value="1"/>
          </Registry>
        </RegistrySettings>"#;
        let (blocks, _, losses) = read(xml.as_bytes()).unwrap();
        assert!(blocks.is_empty());
        assert_eq!(losses.len(), 5);
        assert!(losses
            .iter()
            .any(|loss| loss.contains("item-level targeting")));
        assert!(losses.iter().any(|loss| loss.contains("bitfield update")));
        assert!(losses.iter().any(|loss| loss.contains("removePolicy")));
        assert!(losses
            .iter()
            .any(|loss| loss.contains("invalid userContext")));
        assert!(losses
            .iter()
            .any(|loss| loss.contains("non-schema disabled")));
    }

    #[test]
    fn key_actions_and_default_values_are_distinguished_by_protocol_attributes() {
        let xml = r#"<RegistrySettings>
          <Registry name="CreateKey"><Properties action="C" hive="HKCU"
            key="Software\Acme\Created" name="" type="" value=""/></Registry>
          <Registry name="UpdateKey"><Properties action="U" hive="HKCU"
            key="Software\Acme\Updated" name="" type="" value=""/></Registry>
          <Registry name="ReplaceKey"><Properties action="R" hive="HKCU"
            key="Software\Acme\Replaced" name="" type="" value=""/></Registry>
          <Registry name="Default"><Properties action="U" hive="HKCU"
            key="Software\Acme" name="" default="1" type="REG_SZ" value="text"/></Registry>
          <Registry name="DeleteDefault"><Properties action="D" hive="HKCU"
            key="Software\Acme" name="" default="1"/></Registry>
        </RegistrySettings>"#;
        let (blocks, _, losses) = read(xml.as_bytes()).unwrap();
        assert!(blocks.iter().any(|block| {
            block.path.sub.ends_with("\\Created") && !block.delete && block.values.is_empty()
        }));
        assert!(blocks.iter().any(|block| {
            block.path.sub.ends_with("\\Updated") && !block.delete && block.values.is_empty()
        }));
        assert!(!blocks
            .iter()
            .any(|block| block.path.sub.ends_with("\\Replaced")));
        let acme = blocks
            .iter()
            .find(|block| block.path.sub == "Software\\Acme")
            .unwrap();
        assert!(!acme.delete);
        assert_eq!(acme.values.len(), 2);
        assert!(acme
            .values
            .iter()
            .all(|value| value.name == ValueName::Default));
        assert!(losses.iter().any(|loss| loss.contains("Replace on a key")));
    }

    #[test]
    fn a_file_without_registry_items_is_rejected() {
        assert!(read(br#"<Groups clsid="{x}"><User name="a"/></Groups>"#).is_err());

        let error = read(
            br#"<SomethingElse><Registry><Properties action="U" hive="HKCU"
              key="Software\Acme" name="X" type="REG_DWORD" value="1"/>
            </Registry></SomethingElse>"#,
        )
        .unwrap_err();
        assert!(error.contains("unexpected GPP root"), "{error}");
    }
}
