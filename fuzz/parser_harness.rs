#[path = "../src/coalesce.rs"]
mod coalesce;
#[path = "../src/encoding.rs"]
mod encoding;
#[path = "../src/formats/mod.rs"]
mod formats;
#[path = "../src/model.rs"]
mod model;
#[path = "../src/parser.rs"]
mod parser;
#[path = "../src/value.rs"]
mod value;
#[path = "../src/xml.rs"]
mod xml;

use formats::{Format, ReadOptions};

pub fn reg_bytes(data: &[u8]) {
    let outcome = parser::parse_bytes(data);
    let _ = outcome.has_errors();
}

pub fn xml_bytes(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let _ = xml::parse(&text);
}

pub fn all_formats(data: &[u8]) {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    let format = match selector % 8 {
        0 => Format::Reg,
        1 => Format::Pol,
        2 => Format::Json,
        3 => Format::Csv,
        4 => Format::Inf,
        5 => Format::Ini,
        6 => Format::Admx,
        _ => Format::Gpp,
    };

    // Keep arbitrary bytes useful for the PReg state machine. Without a valid
    // fixed header, almost every mutation would stop at byte zero and provide
    // no coverage of record boundaries, lengths, or directives.
    let owned;
    let input = if format == Format::Pol && !payload.starts_with(b"PReg") {
        owned = [b"PReg".as_slice(), &1u32.to_le_bytes(), payload].concat();
        owned.as_slice()
    } else {
        payload
    };
    let _ = formats::read(input, None, Some(format), &ReadOptions::default());
}
