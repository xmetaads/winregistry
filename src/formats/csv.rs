//! CSV / TSV input — bulk edits that started life in a spreadsheet.
//!
//! ```text
//! key,name,type,data
//! HKCU\Software\Acme,Server,REG_SZ,acme.test
//! HKCU\Software\Acme,Port,REG_DWORD,8080
//! HKCU\Software\Acme,Legacy,,                 <- empty type+data deletes the value
//! HKCU\Software\Old,,,DELETE_KEY              <- deletes the key
//! ```
//!
//! Columns are matched by header name, in any order, case-insensitively, so a
//! sheet exported from Excel works without rearranging it. Quoting follows
//! RFC 4180: `""` inside a quoted field is a literal quote.

use crate::model::*;

pub fn read(bytes: &[u8]) -> Result<(Vec<KeyBlock>, Vec<String>), String> {
    let (text, _) = crate::encoding::decode(bytes);
    let rows = parse(&text);
    let mut rows = rows.into_iter();

    let (header_line, header) = rows.next().ok_or("the file is empty")?;
    let cols: Vec<String> = header
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();

    let find = |names: &[&str]| cols.iter().position(|c| names.contains(&c.as_str()));
    let c_key = find(&["key", "path", "subkey"]).ok_or_else(|| {
        format!("line {header_line}: no 'key' column in the header row {header:?}")
    })?;
    let c_name = find(&["name", "value", "valuename"]);
    let c_type = find(&["type", "regtype"]);
    let c_data = find(&["data", "value data", "valuedata", "content"]);

    if c_data.is_none() && c_type.is_none() {
        return Err(format!(
            "line {header_line}: the header needs at least a 'data' or 'type' column, found {header:?}"
        ));
    }

    let mut blocks: Vec<KeyBlock> = Vec::new();
    let mut notes = vec![format!(
        "columns: key={}, name={:?}, type={:?}, data={:?}",
        c_key, c_name, c_type, c_data
    )];
    let mut count = 0usize;

    for (line, row) in rows {
        if row.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        let cell = |i: Option<usize>| i.and_then(|i| row.get(i)).map(|s| s.trim()).unwrap_or("");

        let path = row.get(c_key).map(|s| s.trim()).unwrap_or("");
        if path.is_empty() {
            notes.push(format!("line {line}: empty key, row skipped"));
            continue;
        }
        let mut block = crate::formats::block(path, line)?;

        let name = cell(c_name);
        let ty = cell(c_type);
        let data = cell(c_data);

        // A whole-key delete: no value name, and the data says so.
        if name.is_empty() && data.eq_ignore_ascii_case("DELETE_KEY") {
            block.delete = true;
            merge(&mut blocks, block);
            count += 1;
            continue;
        }

        let value = if ty.is_empty() && data.is_empty() {
            RegData::Delete
        } else {
            let ty = if ty.is_empty() { "REG_SZ" } else { ty };
            crate::engine::parse_typed(ty, data).map_err(|e| format!("line {line}: {e}"))?
        };

        block.values.push(ValueEntry {
            name: crate::formats::value_name(name),
            data: value,
            line,
        });
        merge(&mut blocks, block);
        count += 1;
    }

    notes.push(format!("{count} row(s) read"));
    Ok((blocks, notes))
}

fn merge(blocks: &mut Vec<KeyBlock>, incoming: KeyBlock) {
    let fold = incoming.path.fold();
    match blocks.iter_mut().find(|b| b.path.fold() == fold) {
        Some(existing) => {
            if incoming.delete {
                existing.delete = true;
                existing.values.clear();
            } else {
                existing.values.extend(incoming.values);
            }
        }
        None => blocks.push(incoming),
    }
}

/// RFC 4180 rows, with the physical line number each row starts on.
/// The delimiter is auto-detected from the header: tab if present, else comma.
fn parse(text: &str) -> Vec<(usize, Vec<String>)> {
    let delim = {
        let first = text.lines().next().unwrap_or("");
        if first.contains('\t') && !first.contains(',') {
            '\t'
        } else {
            ','
        }
    };

    let mut rows = Vec::new();
    let mut field = String::new();
    let mut row: Vec<String> = Vec::new();
    let mut quoted = false;
    let mut line = 1usize;
    let mut row_start = 1usize;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            '\r' if !quoted => {}
            '\n' if !quoted => {
                line += 1;
                row.push(std::mem::take(&mut field));
                if !(row.len() == 1 && row[0].trim().is_empty()) {
                    rows.push((row_start, std::mem::take(&mut row)));
                } else {
                    row.clear();
                }
                row_start = line;
            }
            '\n' => {
                line += 1;
                field.push('\n');
            }
            c if c == delim && !quoted => row.push(std::mem::take(&mut field)),
            c => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push((row_start, row));
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_typed_rows() {
        let src = "key,name,type,data\n\
                   HKCU\\Software\\Acme,Server,REG_SZ,acme.test\n\
                   HKCU\\Software\\Acme,Port,REG_DWORD,8080\n";
        let (blocks, _) = read(src.as_bytes()).unwrap();
        assert_eq!(blocks.len(), 1, "same key collapses into one block");
        assert_eq!(blocks[0].values[0].data, RegData::Sz("acme.test".into()));
        assert_eq!(blocks[0].values[1].data, RegData::Dword(8080));
    }

    #[test]
    fn column_order_and_case_do_not_matter() {
        let src = "Data,TYPE,Key,Name\nacme.test,REG_SZ,HKCU\\Software\\Acme,Server\n";
        let (blocks, _) = read(src.as_bytes()).unwrap();
        assert_eq!(blocks[0].values[0].data, RegData::Sz("acme.test".into()));
    }

    #[test]
    fn empty_type_and_data_deletes_the_value() {
        let src = "key,name,type,data\nHKCU\\Software\\Acme,Legacy,,\n";
        let (blocks, _) = read(src.as_bytes()).unwrap();
        assert_eq!(blocks[0].values[0].data, RegData::Delete);
    }

    #[test]
    fn delete_key_sentinel() {
        let src = "key,name,type,data\nHKCU\\Software\\Old,,,DELETE_KEY\n";
        let (blocks, _) = read(src.as_bytes()).unwrap();
        assert!(blocks[0].delete);
    }

    #[test]
    fn quoted_fields_keep_commas_and_newlines() {
        let src = "key,name,type,data\n\
                   \"HKCU\\Software\\A,B\",\"Odd\"\"Name\",REG_SZ,\"x,y\"\n";
        let (blocks, _) = read(src.as_bytes()).unwrap();
        assert_eq!(blocks[0].path.sub, "Software\\A,B");
        assert_eq!(
            blocks[0].values[0].name,
            ValueName::Named("Odd\"Name".into())
        );
        assert_eq!(blocks[0].values[0].data, RegData::Sz("x,y".into()));
    }

    #[test]
    fn tabs_are_detected() {
        let src = "key\tname\ttype\tdata\nHKCU\\Software\\Acme\tServer\tREG_SZ\tacme.test\n";
        let (blocks, _) = read(src.as_bytes()).unwrap();
        assert_eq!(blocks[0].values[0].data, RegData::Sz("acme.test".into()));
    }

    #[test]
    fn a_header_without_a_key_column_is_an_error() {
        assert!(read(b"a,b,c\n1,2,3\n").is_err());
    }
}
