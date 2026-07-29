#![no_main]
#![allow(dead_code)]

include!("../parser_harness.rs");

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    xml_bytes(data);
});
