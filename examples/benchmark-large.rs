//! Reproducible end-to-end benchmarks for the large inputs called out in the
//! project audit: text registry data, Registry.pol, and a deep application
//! hive. The shipped executable is measured as a child process, so parser,
//! model, writer, and OS API costs are all included.
//!
//! Usage:
//!   cargo build --release
//!   cargo run --release --example benchmark-large -- target/release/regx.exe 5000

use std::fs::File;
use std::io::{BufWriter, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Measurement {
    name: &'static str,
    elapsed: Duration,
    input_bytes: u64,
    items: usize,
    peak_working_set: Option<u64>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let regx = PathBuf::from(
        args.next()
            .unwrap_or_else(|| "target/release/regx.exe".into()),
    );
    let scale: usize = args
        .next()
        .map(|value| value.to_string_lossy().parse())
        .transpose()?
        .unwrap_or(5_000);
    if scale < 100 {
        return Err("scale must be at least 100".into());
    }
    if args.next().is_some() {
        return Err("usage: benchmark-large [REGX_EXE] [SCALE]".into());
    }
    if !regx.is_file() {
        return Err(format!("{} does not exist; build regx first", regx.display()).into());
    }
    let warmup = Command::new(&regx).arg("--version").output()?;
    if !warmup.status.success() {
        return Err("regx warm-up failed".into());
    }

    let root = PathBuf::from("target").join("benchmark-large");
    std::fs::create_dir_all(&root)?;
    let reg = root.join("large.reg");
    let pol = root.join("Registry.pol");
    let hive_script = root.join("deep-hive.txt");
    let hive = root.join("deep.hive");
    let reg_out = root.join("large.out.reg");
    let pol_out = root.join("policy.out.reg");

    write_reg(&reg, scale)?;
    write_pol(&pol, scale)?;
    write_hive_script(&hive_script, scale)?;
    if hive.exists() {
        std::fs::remove_file(&hive)?;
    }

    let measurements = vec![
        measure(
            "large .reg convert",
            &regx,
            &[
                "convert".into(),
                reg.as_os_str().into(),
                "--redirect".into(),
                "off".into(),
                "-o".into(),
                reg_out.as_os_str().into(),
            ],
            reg.metadata()?.len(),
            scale,
        )?,
        measure(
            "large Registry.pol convert",
            &regx,
            &[
                "convert".into(),
                pol.as_os_str().into(),
                "--redirect".into(),
                "off".into(),
                "-o".into(),
                pol_out.as_os_str().into(),
            ],
            pol.metadata()?.len(),
            scale,
        )?,
        measure(
            "deep hive create/write",
            &regx,
            &[
                "hive".into(),
                hive.as_os_str().into(),
                "--create".into(),
                "exec".into(),
                "--script".into(),
                hive_script.as_os_str().into(),
            ],
            hive_script.metadata()?.len(),
            scale + scale.min(240),
        )?,
        measure(
            "deep hive recursive query",
            &regx,
            &[
                "hive".into(),
                hive.as_os_str().into(),
                "query".into(),
                "".into(),
                "-r".into(),
            ],
            hive.metadata()?.len(),
            scale + scale.min(240),
        )?,
    ];

    println!("regx large-data benchmark (scale={scale})");
    println!(
        "{:<28} {:>10} {:>12} {:>12} {:>12} {:>12}",
        "workload", "time", "input", "throughput", "items/s", "peak WS"
    );
    for item in measurements {
        let seconds = item.elapsed.as_secs_f64().max(f64::EPSILON);
        let mib = item.input_bytes as f64 / 1_048_576.0;
        let peak = item
            .peak_working_set
            .map(|bytes| format!("{:.1} MiB", bytes as f64 / 1_048_576.0))
            .unwrap_or_else(|| "n/a".into());
        println!(
            "{:<28} {:>8.3} s {:>9.2} MiB {:>9.2} MiB/s {:>12.0} {:>12}",
            item.name,
            seconds,
            mib,
            mib / seconds,
            item.items as f64 / seconds,
            peak
        );
    }
    Ok(())
}

fn write_reg(path: &Path, scale: usize) -> std::io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    writeln!(out, "Windows Registry Editor Version 5.00\r")?;
    for index in 0..scale {
        writeln!(
            out,
            "\r\n[HKEY_CURRENT_USER\\Software\\regx-benchmark\\K{index:06}]\r"
        )?;
        writeln!(
            out,
            "\"Text\"=\"payload-{index:06}-abcdefghijklmnopqrstuvwxyz\"\r"
        )?;
        writeln!(out, "\"Number\"=dword:{index:08x}\r")?;
        writeln!(
            out,
            "\"Binary\"=hex:00,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f\r"
        )?;
    }
    out.flush()
}

fn utf16z(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn write_pol(path: &Path, scale: usize) -> std::io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    out.write_all(b"PReg")?;
    out.write_all(&1u32.to_le_bytes())?;
    for index in 0..scale {
        let key = utf16z(&format!("Software\\Policies\\regx-benchmark\\K{index:06}"));
        let name = utf16z("Enabled");
        let data = (index as u32).to_le_bytes();
        out.write_all(&('[' as u16).to_le_bytes())?;
        out.write_all(&key)?;
        out.write_all(&(';' as u16).to_le_bytes())?;
        out.write_all(&name)?;
        out.write_all(&(';' as u16).to_le_bytes())?;
        out.write_all(&4u32.to_le_bytes())?; // REG_DWORD
        out.write_all(&(';' as u16).to_le_bytes())?;
        out.write_all(&(data.len() as u32).to_le_bytes())?;
        out.write_all(&(';' as u16).to_le_bytes())?;
        out.write_all(&data)?;
        out.write_all(&(']' as u16).to_le_bytes())?;
    }
    out.flush()
}

fn write_hive_script(path: &Path, scale: usize) -> std::io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    let depth = scale.min(240);
    let mut deep = String::from("Software\\regx-benchmark\\deep");
    for index in 0..depth {
        deep.push_str(&format!("\\L{index:03}"));
        writeln!(out, "set {deep} -v Depth -t REG_DWORD -d {index}")?;
    }
    for index in 0..scale {
        writeln!(
            out,
            "set Software\\regx-benchmark\\wide\\K{index:06} -v Value -d payload-{index:06}"
        )?;
    }
    out.flush()
}

fn measure(
    name: &'static str,
    program: &Path,
    args: &[std::ffi::OsString],
    input_bytes: u64,
    items: usize,
) -> Result<Measurement, Box<dyn std::error::Error>> {
    let started = Instant::now();
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stderr = child.stderr.take().expect("stderr was piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stderr.read_to_end(&mut bytes);
        (result, bytes)
    });
    let mut peak = None;
    let status = loop {
        peak = peak.max(peak_working_set(child.id()));
        if let Some(status) = child.try_wait()? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let (read_result, stderr) = stderr_reader
        .join()
        .map_err(|_| format!("{name}: stderr reader panicked"))?;
    read_result?;
    if !status.success() {
        return Err(format!(
            "{name} failed with {status}: {}",
            String::from_utf8_lossy(&stderr)
        )
        .into());
    }
    Ok(Measurement {
        name,
        elapsed: started.elapsed(),
        input_bytes,
        items,
        peak_working_set: peak,
    })
}

#[cfg(windows)]
fn peak_working_set(pid: u32) -> Option<u64> {
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const PROCESS_VM_READ: u32 = 0x0010;
    #[repr(C)]
    struct Counters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
        fn CloseHandle(handle: isize) -> i32;
    }
    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetProcessMemoryInfo(handle: isize, counters: *mut Counters, cb: u32) -> i32;
    }
    let handle =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if handle == 0 {
        return None;
    }
    let mut counters: Counters = unsafe { std::mem::zeroed() };
    counters.cb = std::mem::size_of::<Counters>() as u32;
    let ok = unsafe { GetProcessMemoryInfo(handle, &mut counters, counters.cb) };
    unsafe {
        CloseHandle(handle);
    }
    (ok != 0).then_some(counters.peak_working_set_size as u64)
}

#[cfg(not(windows))]
fn peak_working_set(_pid: u32) -> Option<u64> {
    None
}
