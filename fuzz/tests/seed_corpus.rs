#![allow(dead_code)]

include!("../parser_harness.rs");

use std::path::Path;

fn feed_dir(path: &Path, mut feed: impl FnMut(&[u8])) {
    for entry in std::fs::read_dir(path).expect("read seed directory") {
        let entry = entry.expect("read seed entry");
        if entry.file_type().expect("seed file type").is_file() {
            let bytes = std::fs::read(entry.path()).expect("read seed");
            feed(&bytes);
        }
    }
}

#[test]
fn every_checked_in_seed_reaches_its_parser_without_panicking() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    feed_dir(&root.join("reg_bytes"), reg_bytes);
    feed_dir(&root.join("xml_bytes"), xml_bytes);
    feed_dir(&root.join("all_formats"), all_formats);
}

#[test]
fn deterministic_mutation_smoke_does_not_panic() {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;

    for case in 0..10_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let len = ((state as usize) ^ case) % 2_049;
        let mut bytes = vec![0_u8; len];

        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }

        reg_bytes(&bytes);
        xml_bytes(&bytes);
        all_formats(&bytes);
    }
}
