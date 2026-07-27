mod audit;
mod cli;
mod coalesce;
mod diff;
mod discover;
mod encoding;
mod engine;
mod fix;
mod formats;
mod hive;
mod model;
mod parser;
mod redirect;
mod selfcheck;
mod sha256;
mod undo;
mod winreg;
mod writer;
mod xml;

use anyhow::{anyhow, Context};
use clap::Parser as _;
use cli::{
    exit, Cli, Command, GlobalOpts, HiveOp, LogLevel, MinConfidence, OnRefuse, OutputFormat,
    RedirectMode, RedirectOpts,
};
use engine::Roots;
use model::*;
use parser::{ParseOutcome, Severity};
use redirect::{Confidence, Policy};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use winreg::View;

/// An input file that could not be read as registry data.
///
/// Carried through `anyhow` so `main` can recover the documented exit code.
/// Without this, every reader failure collapsed into the generic IO path and a
/// malformed `.reg` reported 7 instead of the 3 the contract promises — the
/// integration suite exists to catch exactly that.
#[derive(Debug)]
struct InputError {
    source: String,
    message: String,
    code: i32,
}

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.source, self.message)
    }
}

impl std::error::Error for InputError {}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = match run(&cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("regx: {e:#}");
            e.downcast_ref::<InputError>()
                .map(|i| i.code)
                .unwrap_or(exit::IO)
        }
    };
    ExitCode::from(code as u8)
}

fn run(cli: &Cli) -> anyhow::Result<i32> {
    if cli.self_check {
        let code = cmd_self_check(&cli.global);
        if cli.command.is_none() {
            return Ok(code);
        }
    }
    let Some(command) = &cli.command else {
        return Err(anyhow!(
            "no command given. Try `regx --help`, or `regx --self-check`."
        ));
    };

    match command {
        Command::Validate {
            files,
            strict,
            fix,
            out,
            backup,
        } => cmd_validate(cli, files, *strict, *fix, out.as_deref(), *backup),
        Command::Convert {
            file,
            out,
            input,
            redirect,
            reg4,
        } => cmd_convert(cli, file, out.as_deref(), input, redirect, *reg4),
        Command::Merge { files, out } => cmd_merge(cli, files, out.as_deref()),
        Command::Import {
            files,
            input,
            redirect,
            backup,
            no_backup,
        } => cmd_import(
            cli,
            ImportJob {
                files,
                input,
                redirect,
                backup: backup.as_deref(),
                no_backup: *no_backup,
                prune: false,
            },
        ),
        Command::Sync {
            file,
            input,
            redirect,
            prune,
        } => cmd_import(
            cli,
            ImportJob {
                files: std::slice::from_ref(file),
                input,
                redirect,
                backup: None,
                no_backup: false,
                prune: *prune,
            },
        ),
        Command::Formats => cmd_formats(cli),
        Command::Audit { file, verbose } => cmd_audit(cli, file, *verbose),
        Command::Inspect { files, input } => cmd_inspect(cli, files, input),
        Command::Discover {
            target,
            policy,
            registry_pointer,
            verbose,
            strict,
        } => cmd_discover(
            cli,
            target.as_deref(),
            *policy,
            *registry_pointer,
            *verbose,
            *strict,
        ),
        Command::Export {
            key,
            out,
            recursive,
            reg4,
        } => cmd_export(cli, key, out.as_deref(), *recursive, *reg4),
        Command::Query {
            key,
            value,
            recursive,
        } => cmd_query(cli, key, value.as_deref(), *recursive),
        Command::Set {
            key,
            value,
            r#type,
            data,
            redirect,
        } => cmd_set(cli, key, value, r#type, data, redirect),
        Command::Delete {
            key,
            value,
            recursive,
        } => cmd_delete(cli, key, value.as_deref(), *recursive),
        Command::Probe { key } => cmd_probe(cli, key),
        Command::Hive {
            file,
            op,
            create,
            exclusive,
        } => cmd_hive(cli, file, op, *create, *exclusive),
        Command::Diff {
            a,
            b,
            input,
            out,
            exit_code,
        } => cmd_diff(cli, a, b, input, out.as_deref(), *exit_code),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn view_of(g: &GlobalOpts) -> View {
    match g.view {
        cli::View::Native | cli::View::Both => View::Native,
        cli::View::Bits32 => View::Bits32,
        cli::View::Bits64 => View::Bits64,
    }
}

fn read_reg(path: &Path) -> anyhow::Result<ParseOutcome> {
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(parser::parse_bytes(&bytes))
}

fn read_options(o: &cli::InputOpts) -> anyhow::Result<formats::ReadOptions> {
    let mut opts = formats::ReadOptions::default();
    if let Some(h) = &o.pol_root {
        opts.pol_root = Hive::parse(h)
            .ok_or_else(|| anyhow!("--pol-root {h:?} is not a hive name (try HKLM or HKCU)"))?;
    }
    opts.inf_section = o.inf_section.clone();
    opts.admx_state = formats::admx::State::parse(&o.admx_state).ok_or_else(|| {
        anyhow!(
            "--admx-state {:?} is not 'enabled' or 'disabled'",
            o.admx_state
        )
    })?;
    opts.admx_policy = o.admx_policy.clone();
    Ok(opts)
}

/// Read any supported format, reporting what was detected and anything the
/// reader had to decide on its own.
fn read_any(cli: &Cli, path: &Path, o: &cli::InputOpts) -> anyhow::Result<formats::ReadOutcome> {
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;

    let forced =
        match &o.from {
            Some(name) => Some(formats::Format::parse_name(name).ok_or_else(|| {
                anyhow!("--from {name:?} is not a known format; run `regx formats`")
            })?),
            None => None,
        };

    let outcome = formats::read(&bytes, Some(path), forced, &read_options(o)?).map_err(|e| {
        anyhow!(InputError {
            source: path.display().to_string(),
            message: e,
            // Every reader failure means "this input could not be parsed as
            // registry data", which is exit code 3 by the documented contract.
            code: exit::PARSE,
        })
    })?;

    if cli.global.log_level >= LogLevel::Info {
        eprintln!(
            "regx: {} read as {}{}",
            path.display(),
            outcome.format,
            if forced.is_some() {
                " (forced)"
            } else {
                " (detected)"
            }
        );
        for n in &outcome.notes {
            eprintln!("  note: {n}");
        }
    }
    Ok(outcome)
}

fn report_diagnostics(path: &Path, outcome: &ParseOutcome, level: LogLevel) {
    for d in &outcome.diagnostics {
        let tag = match d.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        if d.severity == Severity::Warning && level < LogLevel::Warn {
            continue;
        }
        eprintln!("{}:{}: {tag}: {}", path.display(), d.line, d.message);
    }
}

fn write_reg(
    path: &Path,
    file: &RegFile,
    root_as: Option<&str>,
    banner: &[String],
) -> anyhow::Result<()> {
    let text = writer::to_string_rooted(file, root_as, banner);
    let bytes = match file.format {
        RegFormat::V5 => encoding::encode_utf16le_bom(&text),
        RegFormat::V4 => text.into_bytes(),
    };
    std::fs::write(path, bytes).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

/// Map a Win32 registry failure onto the documented exit codes so a pipeline can
/// tell "no such key" apart from "you are not allowed".
fn reg_exit(e: &winreg::Error) -> i32 {
    if e.is_not_found() {
        exit::NOT_FOUND
    } else if e.is_access_denied() {
        exit::ACCESS_DENIED
    } else {
        exit::IO
    }
}

/// Open the audit log if one was requested.
///
/// Failing to open it aborts the command rather than proceeding unlogged: an
/// operator who asked for an audit trail has to be able to rely on getting one,
/// and silently continuing would be the worst outcome of the three.
fn open_audit(cli: &Cli, command: &str) -> anyhow::Result<Option<audit::Logger>> {
    let Some(path) = &cli.global.audit_log else {
        return Ok(None);
    };
    let logger = audit::Logger::open(path, cli.global.audit_redact, command)
        .with_context(|| format!("cannot open the audit log {}", path.display()))?;
    if cli.global.log_level >= LogLevel::Info {
        eprintln!(
            "regx: audit log -> {}{}",
            path.display(),
            if cli.global.audit_redact {
                " (values redacted to digests)"
            } else {
                ""
            }
        );
    }
    Ok(Some(logger))
}

/// The command line as recorded in the audit log.
fn command_line() -> String {
    std::env::args().collect::<Vec<_>>().join(" ")
}

fn parse_key(s: &str) -> anyhow::Result<RegPath> {
    RegPath::parse(s).ok_or_else(|| {
        anyhow!("{s:?} does not start with a known root (HKLM, HKCU, HKCR, HKU, HKCC)")
    })
}

fn confirm(g: &GlobalOpts, prompt: &str) -> bool {
    if g.yes || g.dry_run {
        return true;
    }
    eprint!("{prompt} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "YES")
}

// ---------------------------------------------------------------------------
// Redirection
// ---------------------------------------------------------------------------

struct RedirectOutcome {
    skipped: usize,
    refused: usize,
}

fn apply_redirect(file: &mut RegFile, opts: &RedirectOpts, level: LogLevel) -> RedirectOutcome {
    let policy = match opts.redirect {
        RedirectMode::Off => Policy::Off,
        RedirectMode::ClassesOnly => Policy::ClassesOnly,
        RedirectMode::Auto | RedirectMode::Force => Policy::Auto,
    };
    let floor = match (opts.redirect, opts.min_confidence) {
        (RedirectMode::Force, _) | (_, MinConfidence::Low) => Confidence::Low,
        (_, MinConfidence::Medium) => Confidence::Medium,
        (_, MinConfidence::High) => Confidence::High,
    };

    let mut kept = Vec::new();
    let mut out = RedirectOutcome {
        skipped: 0,
        refused: 0,
    };

    for mut key in std::mem::take(&mut file.keys) {
        let m = redirect::map(&key.path, policy);
        match m.to {
            Some(dest) if m.confidence >= floor => {
                if level >= LogLevel::Info {
                    eprintln!(
                        "  redirect [{}] {} -> {}  ({})",
                        m.confidence.label(),
                        key.path,
                        dest,
                        m.reason
                    );
                }
                key.path = dest;
                kept.push(key);
            }
            Some(dest) => {
                out.skipped += 1;
                eprintln!(
                    "  skip [{}] {} -> {}  ({}); lower --min-confidence to include",
                    m.confidence.label(),
                    key.path,
                    dest,
                    m.reason
                );
            }
            None if m.confidence == Confidence::Refuse => {
                out.refused += 1;
                eprintln!("  refuse {}  ({})", key.path, m.reason);
            }
            None => kept.push(key),
        }
    }

    // Redirection routinely collapses distinct sources onto one destination
    // (SOFTWARE\X and SOFTWARE\WOW6432Node\X), so coalescing is mandatory here,
    // not cosmetic.
    let (merged, report) = coalesce::coalesce(kept);
    for c in &report.conflicts {
        eprintln!(
            "  conflict {}\\{}: line {} {:?} overridden by line {} {:?}",
            c.path, c.value, c.first_line, c.old, c.last_line, c.new
        );
    }
    if report.blocks_merged > 0 && level >= LogLevel::Info {
        eprintln!(
            "  merged {} duplicate key block(s), {} value conflict(s)",
            report.blocks_merged,
            report.conflicts.len()
        );
    }
    file.keys = merged;
    out
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

fn cmd_validate(
    cli: &Cli,
    files: &[PathBuf],
    strict: bool,
    do_fix: bool,
    out: Option<&Path>,
    keep_backup: bool,
) -> anyhow::Result<i32> {
    if do_fix && out.is_some() && files.len() > 1 {
        return Err(anyhow!("--out takes a single input file"));
    }
    let mut worst = exit::OK;

    for path in files {
        let bytes =
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let (text, _) = {
            let o = encoding::decode(&bytes);
            (o.0, o.1)
        };
        let outcome = parser::parse_bytes(&bytes);
        let f = &outcome.file;

        println!(
            "{}: {} / {} - {} key block(s), {} value(s)",
            path.display(),
            f.format.header(),
            f.encoding,
            f.keys.len(),
            f.keys.iter().map(|k| k.values.len()).sum::<usize>(),
        );
        report_diagnostics(path, &outcome, LogLevel::Debug);

        if outcome.has_errors() {
            // A file with syntax errors is not safely repairable: we would be
            // guessing at the author's intent, not fixing a known defect.
            eprintln!(
                "{}: syntax errors present; --fix only repairs structurally valid files",
                path.display()
            );
            worst = exit::PARSE;
            continue;
        }

        if !do_fix {
            if strict && !outcome.diagnostics.is_empty() && worst == exit::OK {
                worst = exit::PARSE;
            }
            continue;
        }

        let mut file = outcome.file;
        let raw_fixes = fix::scan_raw(&text);
        let report = fix::repair(&mut file);
        let total = raw_fixes.len() + report.fixes.len();

        for x in raw_fixes.iter().chain(report.fixes.iter()) {
            println!(
                "  fix{} line {}: {}",
                if x.class == fix::Class::Lossy {
                    " (lossy)"
                } else {
                    ""
                },
                x.line,
                x.what
            );
        }
        for (line, why) in &report.unfixable {
            println!("  not fixed, line {line}: {why}");
        }

        if total == 0 {
            println!("  nothing to repair");
            if !report.unfixable.is_empty() {
                worst = exit::PARSE;
            }
            continue;
        }

        let dest = out.unwrap_or(path.as_path());
        if cli.global.dry_run {
            println!("  --dry-run: {} repair(s) not written", total);
            continue;
        }
        if keep_backup && dest == path.as_path() {
            let bak = path.with_extension(format!(
                "{}.bak",
                path.extension()
                    .map(|e| e.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ));
            std::fs::copy(path, &bak)
                .with_context(|| format!("cannot write backup {}", bak.display()))?;
            println!("  backup: {}", bak.display());
        }
        write_reg(dest, &file, None, &[])?;
        println!(
            "  wrote {} ({} repair(s), {} lossy)",
            dest.display(),
            total,
            report.lossy_count()
        );
        if !report.unfixable.is_empty() {
            worst = exit::PARTIAL;
        }
    }

    Ok(worst)
}

// ---------------------------------------------------------------------------
// convert / merge
// ---------------------------------------------------------------------------

fn cmd_convert(
    cli: &Cli,
    input: &Path,
    out: Option<&Path>,
    iopts: &cli::InputOpts,
    ropts: &RedirectOpts,
    reg4: bool,
) -> anyhow::Result<i32> {
    let mut file = read_any(cli, input, iopts)?.file;
    file.format = if reg4 { RegFormat::V4 } else { RegFormat::V5 };
    let r = apply_redirect(&mut file, ropts, cli.global.log_level);

    if r.refused > 0 && ropts.on_refuse == OnRefuse::Fail {
        eprintln!(
            "regx: {} key(s) could not be redirected (--on-refuse fail)",
            r.refused
        );
        return Ok(exit::REDIRECT_REFUSED);
    }

    match out {
        Some(p) if !cli.global.dry_run => {
            write_reg(p, &file, None, &[])?;
            eprintln!(
                "regx: wrote {} ({} key block(s), {} skipped, {} refused)",
                p.display(),
                file.keys.len(),
                r.skipped,
                r.refused
            );
        }
        _ => print!("{}", writer::to_string(&file)),
    }
    Ok(if r.skipped > 0 {
        exit::PARTIAL
    } else {
        exit::OK
    })
}

fn cmd_merge(cli: &Cli, files: &[PathBuf], out: Option<&Path>) -> anyhow::Result<i32> {
    let mut all = Vec::new();
    let mut format = RegFormat::V5;
    for p in files {
        let outcome = read_reg(p)?;
        report_diagnostics(p, &outcome, cli.global.log_level);
        if outcome.has_errors() {
            return Ok(exit::PARSE);
        }
        if outcome.file.format == RegFormat::V4 && all.is_empty() {
            format = RegFormat::V4;
        }
        all.extend(outcome.file.keys);
    }

    let (keys, report) = coalesce::coalesce(all);
    for c in &report.conflicts {
        eprintln!(
            "  conflict {}\\{}: {:?} overridden by {:?}",
            c.path, c.value, c.old, c.new
        );
    }
    let file = RegFile {
        format,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys,
    };
    eprintln!(
        "regx: merged {} file(s) -> {} key block(s), {} conflict(s)",
        files.len(),
        file.keys.len(),
        report.conflicts.len()
    );

    match out {
        Some(p) if !cli.global.dry_run => write_reg(p, &file, None, &[])?,
        _ => print!("{}", writer::to_string(&file)),
    }
    Ok(exit::OK)
}

// ---------------------------------------------------------------------------
// import / sync
// ---------------------------------------------------------------------------

/// Everything `import` and `sync` need. They differ only in `prune` and in
/// whether an undo snapshot path was given, so they share one implementation;
/// grouping the arguments keeps that shared function readable.
struct ImportJob<'a> {
    files: &'a [PathBuf],
    input: &'a cli::InputOpts,
    redirect: &'a RedirectOpts,
    backup: Option<&'a Path>,
    no_backup: bool,
    prune: bool,
}

fn cmd_import(cli: &Cli, job: ImportJob<'_>) -> anyhow::Result<i32> {
    let ImportJob {
        files,
        input: iopts,
        redirect: ropts,
        backup,
        no_backup,
        prune,
    } = job;

    let mut all = Vec::new();
    for p in files {
        all.extend(read_any(cli, p, iopts)?.file.keys);
    }
    let mut file = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys: all,
    };

    let r = apply_redirect(&mut file, ropts, cli.global.log_level);
    if r.refused > 0 && ropts.on_refuse == OnRefuse::Fail {
        return Ok(exit::REDIRECT_REFUSED);
    }
    if file.keys.is_empty() {
        eprintln!("regx: nothing left to apply");
        return Ok(if r.refused > 0 {
            exit::REDIRECT_REFUSED
        } else {
            exit::OK
        });
    }

    let roots = Roots::live();
    let view = view_of(&cli.global);

    if prune {
        file.keys = add_prune_deletes(&roots, &file.keys, view);
    }

    // Undo snapshot before anything is written.
    if !no_backup && !cli.global.dry_run {
        let dest = backup
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| undo::default_path(&files[0]));
        let snap = undo::snapshot(&roots, &file, view);
        let banner = vec![
            format!("regx undo snapshot for: {}", files[0].display()),
            format!(
                "{} value(s) captured, {} key(s) to remove on rollback",
                snap.restored_values,
                snap.new_keys.len()
            ),
            "Apply this file to revert the import.".to_string(),
        ];
        write_reg(&dest, &snap.file, None, &banner)?;
        eprintln!("regx: undo snapshot -> {}", dest.display());
        if !snap.is_complete() {
            eprintln!(
                "regx: WARNING - {} key(s) could not be read; the undo file is INCOMPLETE:",
                snap.unreadable.len()
            );
            for (p, e) in snap.unreadable.iter().take(10) {
                eprintln!("    {p}: {e}");
            }
        }
    }

    let n = file.keys.len();
    if !confirm(
        &cli.global,
        &format!("Apply {n} key block(s) to the live registry?"),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }

    let mut logger = open_audit(cli, &command_line())?;
    let rep = engine::apply_audited(&roots, &file, view, cli.global.dry_run, logger.as_mut());
    print_apply(cli, &rep);

    Ok(if !rep.failures.is_empty() {
        if rep.touched() > 0 {
            exit::PARTIAL
        } else {
            exit::ACCESS_DENIED
        }
    } else if r.skipped > 0 {
        exit::PARTIAL
    } else {
        exit::OK
    })
}

/// For `--prune`: any live value under a declared key that the file does not
/// mention becomes an explicit `"name"=-` delete, making the apply idempotent.
fn add_prune_deletes(roots: &Roots, keys: &[KeyBlock], view: View) -> Vec<KeyBlock> {
    let mut out = Vec::with_capacity(keys.len());
    for block in keys {
        let mut block = block.clone();
        if !block.delete {
            if let Ok((live, _)) = engine::export(roots, &block.path, view, false) {
                if let Some(live) = live.first() {
                    for lv in &live.values {
                        let declared = block.values.iter().any(|v| {
                            model::fold_str(engine::value_api_name(&v.name))
                                == model::fold_str(engine::value_api_name(&lv.name))
                        });
                        if !declared {
                            block.values.push(ValueEntry {
                                name: lv.name.clone(),
                                data: RegData::Delete,
                                line: 0,
                            });
                        }
                    }
                }
            }
        }
        out.push(block);
    }
    out
}

fn print_apply(cli: &Cli, rep: &engine::ApplyReport) {
    let prefix = if cli.global.dry_run { "would " } else { "" };
    eprintln!(
        "regx: {prefix}create {} key(s), {prefix}delete {} key(s), {prefix}set {} value(s), {prefix}delete {} value(s)",
        rep.keys_created, rep.keys_deleted, rep.values_set, rep.values_deleted
    );
    for (what, why) in &rep.failures {
        eprintln!("  failed {what}: {why}");
    }
}

// ---------------------------------------------------------------------------
// export / query / set / delete / probe
// ---------------------------------------------------------------------------

fn cmd_export(
    cli: &Cli,
    key: &str,
    out: Option<&Path>,
    recursive: bool,
    reg4: bool,
) -> anyhow::Result<i32> {
    let path = parse_key(key)?;
    let roots = Roots::live();
    let (keys, report) = match engine::export(&roots, &path, view_of(&cli.global), recursive) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("regx: {e}");
            return Ok(reg_exit(&e));
        }
    };

    let file = RegFile {
        format: if reg4 { RegFormat::V4 } else { RegFormat::V5 },
        encoding: encoding::SourceEncoding::Utf16Le,
        keys,
    };

    for (p, e) in &report.skipped {
        eprintln!("  skipped {p}: {e}");
    }
    match out {
        Some(p) if !cli.global.dry_run => {
            write_reg(p, &file, None, &[])?;
            eprintln!(
                "regx: exported {} key(s), {} value(s) -> {}{}",
                report.keys,
                report.values,
                p.display(),
                if report.skipped.is_empty() {
                    String::new()
                } else {
                    format!(" ({} subkey(s) skipped)", report.skipped.len())
                }
            );
        }
        _ => print!("{}", writer::to_string(&file)),
    }
    Ok(if report.skipped.is_empty() {
        exit::OK
    } else {
        exit::PARTIAL
    })
}

fn cmd_query(cli: &Cli, key: &str, value: Option<&str>, recursive: bool) -> anyhow::Result<i32> {
    let path = parse_key(key)?;
    let roots = Roots::live();
    print_query(cli, &roots, &path, value, recursive, None)
}

fn print_query(
    cli: &Cli,
    roots: &Roots,
    path: &RegPath,
    value: Option<&str>,
    recursive: bool,
    root_label: Option<&str>,
) -> anyhow::Result<i32> {
    let (keys, report) = match engine::export(roots, path, view_of(&cli.global), recursive) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("regx: {e}");
            return Ok(reg_exit(&e));
        }
    };

    let label = |p: &RegPath| match root_label {
        None => p.to_string(),
        Some(r) if p.sub.is_empty() => r.to_string(),
        Some(r) => format!("{r}\\{}", p.sub),
    };

    if cli.global.output == OutputFormat::Json {
        println!("{}", json_of(&keys, &label));
        return Ok(exit::OK);
    }

    for block in &keys {
        println!("{}", label(&block.path));
        for v in &block.values {
            if let Some(want) = value {
                if model::fold_str(engine::value_api_name(&v.name)) != model::fold_str(want) {
                    continue;
                }
            }
            println!(
                "    {:<28} {:<14} {}",
                v.name.to_string(),
                v.data.type_name(),
                v.data.preview()
            );
        }
    }
    for (p, e) in &report.skipped {
        eprintln!("  skipped {p}: {e}");
    }
    Ok(if report.skipped.is_empty() {
        exit::OK
    } else {
        exit::PARTIAL
    })
}

fn json_of(keys: &[KeyBlock], label: &dyn Fn(&RegPath) -> String) -> String {
    let mut s = String::from("[\n");
    for (i, b) in keys.iter().enumerate() {
        s.push_str(&format!(
            "  {{\"key\": {}, \"values\": [",
            jstr(&label(&b.path))
        ));
        for (j, v) in b.values.iter().enumerate() {
            if j > 0 {
                s.push_str(", ");
            }
            s.push_str(&format!(
                "{{\"name\": {}, \"type\": {}, \"data\": {}}}",
                jstr(&v.name.to_string()),
                jstr(v.data.type_name()),
                jstr(&v.data.preview())
            ));
        }
        s.push_str("]}");
        if i + 1 < keys.len() {
            s.push(',');
        }
        s.push('\n');
    }
    s.push(']');
    s
}

fn jstr(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn cmd_set(
    cli: &Cli,
    key: &str,
    value: &str,
    ty: &str,
    data: &str,
    ropts: &RedirectOpts,
) -> anyhow::Result<i32> {
    let path = parse_key(key)?;
    let parsed = engine::parse_typed(ty, data).map_err(|e| anyhow!(e))?;
    let mut file = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys: vec![KeyBlock {
            path,
            delete: false,
            values: vec![ValueEntry {
                name: if value.is_empty() {
                    ValueName::Default
                } else {
                    ValueName::Named(value.to_string())
                },
                data: parsed,
                line: 0,
            }],
            line: 0,
        }],
    };
    apply_redirect(&mut file, ropts, cli.global.log_level);
    if file.keys.is_empty() {
        return Ok(exit::REDIRECT_REFUSED);
    }

    let roots = Roots::live();
    let mut logger = open_audit(cli, &command_line())?;
    let rep = engine::apply_audited(
        &roots,
        &file,
        view_of(&cli.global),
        cli.global.dry_run,
        logger.as_mut(),
    );
    print_apply(cli, &rep);
    Ok(if rep.failures.is_empty() {
        exit::OK
    } else {
        exit::ACCESS_DENIED
    })
}

fn cmd_delete(cli: &Cli, key: &str, value: Option<&str>, recursive: bool) -> anyhow::Result<i32> {
    let path = parse_key(key)?;
    let block = match value {
        Some(name) => KeyBlock {
            path: path.clone(),
            delete: false,
            values: vec![ValueEntry {
                name: if name.is_empty() {
                    ValueName::Default
                } else {
                    ValueName::Named(name.to_string())
                },
                data: RegData::Delete,
                line: 0,
            }],
            line: 0,
        },
        None => {
            if !recursive {
                return Err(anyhow!(
                    "deleting a key removes its subkeys; pass -r to confirm, or -v NAME for one value"
                ));
            }
            KeyBlock {
                path: path.clone(),
                delete: true,
                values: vec![],
                line: 0,
            }
        }
    };

    if !confirm(&cli.global, &format!("Delete {path}?")) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }

    let file = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys: vec![block],
    };
    let roots = Roots::live();
    let mut logger = open_audit(cli, &command_line())?;
    let rep = engine::apply_audited(
        &roots,
        &file,
        view_of(&cli.global),
        cli.global.dry_run,
        logger.as_mut(),
    );
    print_apply(cli, &rep);
    Ok(if rep.failures.is_empty() {
        exit::OK
    } else {
        exit::ACCESS_DENIED
    })
}

fn cmd_probe(cli: &Cli, key: &str) -> anyhow::Result<i32> {
    let path = parse_key(key)?;
    let roots = Roots::live();
    let r = engine::probe(&roots, &path, view_of(&cli.global));

    if cli.global.output == OutputFormat::Json {
        println!(
            "{{\"path\": {}, \"exists\": {}, \"readable\": {}, \"writable\": {}, \"creatable\": {}, \"detail\": {}}}",
            jstr(&r.path), r.exists, r.readable, r.writable, r.creatable, jstr(&r.detail)
        );
    } else {
        println!("{}", r.path);
        println!("  exists    {}", r.exists);
        println!("  readable  {}", r.readable);
        println!("  writable  {}", r.writable);
        println!("  creatable {}", r.creatable);
        if !r.detail.is_empty() {
            println!("  detail    {}", r.detail);
        }
    }
    Ok(if r.writable || r.creatable {
        exit::OK
    } else {
        exit::ACCESS_DENIED
    })
}

// ---------------------------------------------------------------------------
// hive
// ---------------------------------------------------------------------------

fn cmd_hive(
    cli: &Cli,
    file: &Path,
    op: &HiveOp,
    create: bool,
    exclusive: bool,
) -> anyhow::Result<i32> {
    if let HiveOp::Info = op {
        let i = hive::info(file);
        println!("{}", i.path.display());
        println!("  size        {} bytes", i.size);
        println!(
            "  hive header {}",
            if i.signature_ok {
                "regf (valid)"
            } else {
                "MISSING"
            }
        );
        println!("  mountable   read={} write={}", i.readable, i.writable);
        if !i.detail.is_empty() {
            println!("  detail      {}", i.detail);
        }
        if !i.root_subkeys.is_empty() {
            println!("  root keys   {}", i.root_subkeys.join(", "));
        }
        return Ok(if i.readable { exit::OK } else { exit::IO });
    }

    let writable = op_needs_write(op) && !cli.global.dry_run;
    let session = hive::open(file, writable, create, exclusive).map_err(|e| anyhow!("{e}"))?;
    if session.created {
        eprintln!("regx: created a new hive file at {}", file.display());
    }
    eprintln!(
        "regx: mounted {} via RegLoadAppKey ({}), no elevation used",
        file.display(),
        if writable { "read/write" } else { "read-only" }
    );

    let ops: Vec<String> = match op {
        HiveOp::Exec { cmd, script, .. } => {
            let mut v = cmd.clone();
            if let Some(s) = script {
                let text = std::fs::read_to_string(s)
                    .with_context(|| format!("cannot read {}", s.display()))?;
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                        continue;
                    }
                    v.push(line.to_string());
                }
            }
            v
        }
        _ => Vec::new(),
    };

    let keep_going = matches!(
        op,
        HiveOp::Exec {
            keep_going: true,
            ..
        }
    );
    let mut worst = exit::OK;

    if ops.is_empty() && matches!(op, HiveOp::Exec { .. }) {
        return Err(anyhow!(
            "`hive exec` needs at least one -c OP or --script FILE"
        ));
    }

    if ops.is_empty() {
        worst = run_hive_op(cli, &session, op)?;
    } else {
        for (i, line) in ops.iter().enumerate() {
            let argv = split_argv(line);
            if argv.is_empty() {
                continue;
            }
            let parsed = cli::HiveOpLine::try_parse_from(argv);
            let sub = match parsed {
                Ok(s) => s.op,
                Err(e) => {
                    eprintln!("regx: op {} ({line:?}): {e}", i + 1);
                    worst = exit::USAGE;
                    if keep_going {
                        continue;
                    }
                    break;
                }
            };
            eprintln!("regx: [{}/{}] {line}", i + 1, ops.len());
            match run_hive_op(cli, &session, &sub) {
                Ok(c) if c != exit::OK => {
                    worst = c;
                    if !keep_going {
                        break;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("regx: op {} failed: {e:#}", i + 1);
                    worst = exit::IO;
                    if !keep_going {
                        break;
                    }
                }
            }
        }
    }

    if writable {
        session.flush().map_err(|e| anyhow!("{e}"))?;
    }
    eprintln!("regx: unmounted {}", file.display());
    Ok(worst)
}

fn op_needs_write(op: &HiveOp) -> bool {
    match op {
        HiveOp::Set { .. } | HiveOp::Delete { .. } | HiveOp::Import { .. } => true,
        HiveOp::Exec { cmd, script, .. } => {
            let mut text = cmd.join(" ");
            if let Some(s) = script {
                if let Ok(extra) = std::fs::read_to_string(s) {
                    text.push(' ');
                    text.push_str(&extra);
                }
            }
            // Conservative: any mention of a mutating verb opens read/write.
            ["set", "delete", "import"]
                .iter()
                .any(|v| text.split_whitespace().any(|w| w == *v))
        }
        _ => false,
    }
}

/// A hive-relative path becomes a `RegPath` whose hive component is ignored.
fn hive_path(sub: &str) -> RegPath {
    RegPath {
        hive: Hive::Hkcu,
        sub: sub.trim_matches('\\').to_string(),
    }
}

fn run_hive_op(cli: &Cli, s: &hive::Session, op: &HiveOp) -> anyhow::Result<i32> {
    let view = View::Native; // A mounted hive has no WOW64 split.
    match op {
        HiveOp::Info | HiveOp::Exec { .. } => Ok(exit::OK),

        HiveOp::Ls { subkey, recursive } => {
            let (keys, rep) = match engine::export(&s.roots, &hive_path(subkey), view, *recursive) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("regx: {e}");
                    return Ok(reg_exit(&e));
                }
            };
            for b in &keys {
                println!(
                    "{}",
                    if b.path.sub.is_empty() {
                        "\\"
                    } else {
                        &b.path.sub
                    }
                );
            }
            for (p, e) in &rep.skipped {
                eprintln!("  skipped {p}: {e}");
            }
            Ok(exit::OK)
        }

        HiveOp::Query {
            subkey,
            value,
            recursive,
        } => print_query(
            cli,
            &s.roots,
            &hive_path(subkey),
            value.as_deref(),
            *recursive,
            Some("<hive>"),
        ),

        HiveOp::Set {
            subkey,
            value,
            r#type,
            data,
        } => {
            let parsed = engine::parse_typed(r#type, data).map_err(|e| anyhow!(e))?;
            let file = RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: vec![KeyBlock {
                    path: hive_path(subkey),
                    delete: false,
                    values: vec![ValueEntry {
                        name: if value.is_empty() {
                            ValueName::Default
                        } else {
                            ValueName::Named(value.clone())
                        },
                        data: parsed,
                        line: 0,
                    }],
                    line: 0,
                }],
            };
            let rep = engine::apply(&s.roots, &file, view, cli.global.dry_run);
            print_apply(cli, &rep);
            Ok(if rep.failures.is_empty() {
                exit::OK
            } else {
                exit::ACCESS_DENIED
            })
        }

        HiveOp::Delete {
            subkey,
            value,
            recursive,
        } => {
            let block = match value {
                Some(name) => KeyBlock {
                    path: hive_path(subkey),
                    delete: false,
                    values: vec![ValueEntry {
                        name: if name.is_empty() {
                            ValueName::Default
                        } else {
                            ValueName::Named(name.clone())
                        },
                        data: RegData::Delete,
                        line: 0,
                    }],
                    line: 0,
                },
                None => {
                    if !recursive {
                        return Err(anyhow!("pass -r to delete a subkey and its children"));
                    }
                    KeyBlock {
                        path: hive_path(subkey),
                        delete: true,
                        values: vec![],
                        line: 0,
                    }
                }
            };
            let file = RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: vec![block],
            };
            let rep = engine::apply(&s.roots, &file, view, cli.global.dry_run);
            print_apply(cli, &rep);
            Ok(if rep.failures.is_empty() {
                exit::OK
            } else {
                exit::ACCESS_DENIED
            })
        }

        HiveOp::Import { input, strip_root } => {
            let outcome = read_reg(input)?;
            report_diagnostics(input, &outcome, cli.global.log_level);
            if outcome.has_errors() {
                return Ok(exit::PARSE);
            }
            let mut file = outcome.file;
            // Strip the mount-point prefix the .reg file was exported under, so
            // `HKEY_USERS\OFFLINE\Software\X` lands on `Software\X` in the hive.
            if let Some(prefix) = strip_root {
                let want = model::fold_str(prefix.trim_matches('\\'));
                for k in &mut file.keys {
                    let full = model::fold_str(&k.path.to_string());
                    if let Some(rest) = full.strip_prefix(&want) {
                        let n = k.path.to_string().len() - rest.len();
                        k.path.sub = k.path.to_string()[n..].trim_matches('\\').to_string();
                    }
                }
            }
            let (keys, _) = coalesce::coalesce(std::mem::take(&mut file.keys));
            file.keys = keys;
            let rep = engine::apply(&s.roots, &file, view, cli.global.dry_run);
            print_apply(cli, &rep);
            Ok(if rep.failures.is_empty() {
                exit::OK
            } else {
                exit::PARTIAL
            })
        }

        HiveOp::Export {
            subkey,
            out,
            root_as,
        } => {
            let (keys, rep) = match engine::export(&s.roots, &hive_path(subkey), view, true) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("regx: {e}");
                    return Ok(reg_exit(&e));
                }
            };
            let file = RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys,
            };
            for (p, e) in &rep.skipped {
                eprintln!("  skipped {p}: {e}");
            }
            match out {
                Some(p) if !cli.global.dry_run => {
                    let banner = vec![
                        format!("exported from offline hive {}", s.path.display()),
                        format!("re-rooted under {root_as}"),
                    ];
                    write_reg(p, &file, Some(root_as), &banner)?;
                    eprintln!(
                        "regx: exported {} key(s), {} value(s) -> {}",
                        rep.keys,
                        rep.values,
                        p.display()
                    );
                }
                _ => print!("{}", writer::to_string_rooted(&file, Some(root_as), &[])),
            }
            Ok(exit::OK)
        }
    }
}

/// Minimal argv splitter for `hive exec` operation strings: double quotes group,
/// `\"` escapes a quote. Deliberately not a shell - no globbing, no variables.
fn split_argv(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if in_quotes && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

// ---------------------------------------------------------------------------
// formats / inspect
// ---------------------------------------------------------------------------

const FORMAT_TABLE: &[(&str, &str, &str)] = &[
    (
        "reg",
        ".reg",
        "regedit's own text format, UTF-16 or ANSI REGEDIT4",
    ),
    (
        "pol",
        "Registry.pol",
        "Group Policy PReg binary; **del./**DeleteValues directives honoured",
    ),
    (
        "admx",
        ".admx + .adml",
        "policy template; concrete enabled/disabled values, elements reported",
    ),
    (
        "gpp",
        "Registry.xml",
        "Group Policy Preferences; actions C/R/U/D, Collections traversed",
    ),
    (
        "inf",
        ".inf",
        "[AddReg]/[DelReg] sections, with [Strings] token substitution",
    ),
    (
        "json",
        ".json",
        "compact {path: {name: value}} or explicit {\"keys\": [...]}",
    ),
    (
        "csv",
        ".csv / .tsv",
        "header row naming key, name, type, data in any order",
    ),
    (
        "ini",
        ".ini / .cfg",
        "[HKEY_...] sections, optional :type suffix on each name",
    ),
    (
        "hive",
        "NTUSER.DAT",
        "not read here - use `regx hive <FILE>`",
    ),
];

fn cmd_audit(cli: &Cli, file: &Path, verbose: bool) -> anyhow::Result<i32> {
    let v = audit::verify(file)
        .with_context(|| format!("cannot read the audit log {}", file.display()))?;

    if cli.global.output == OutputFormat::Json {
        let broken: Vec<String> = v
            .broken
            .iter()
            .map(|(line, why)| format!("    {{\"line\": {line}, \"problem\": {}}}", jstr(why)))
            .collect();
        println!(
            "{{\n  \"file\": {},\n  \"records\": {},\n  \"sessions\": {},\n  \"intact\": {},\n  \"broken\": [\n{}\n  ]\n}}",
            jstr(&file.display().to_string()),
            v.records,
            v.sessions,
            v.is_intact(),
            broken.join(",\n")
        );
        return Ok(if v.is_intact() {
            exit::OK
        } else {
            exit::PARTIAL
        });
    }

    println!("{}", file.display());
    println!("  records   {}", v.records);
    println!("  sessions  {}", v.sessions);
    if let Ok(d) = audit::file_digest(file) {
        println!("  sha256    {d}");
    }

    if v.is_intact() {
        println!("\n  Chain intact: no record has been altered or removed.");
    } else {
        println!("\n  CHAIN BROKEN at {} point(s):", v.broken.len());
        for (line, why) in &v.broken {
            println!("    line {line}: {why}");
        }
        println!(
            "\n  A break means the file was changed after it was written. The records\n\
             \x20 before the first break are still trustworthy; those after it are not."
        );
    }

    if verbose {
        let text = std::fs::read_to_string(file)?;
        println!();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            println!("  {:>4}  {}", i + 1, line);
        }
    }

    Ok(if v.is_intact() {
        exit::OK
    } else {
        exit::PARTIAL
    })
}

fn cmd_formats(cli: &Cli) -> anyhow::Result<i32> {
    if cli.global.output == OutputFormat::Json {
        let items: Vec<String> = FORMAT_TABLE
            .iter()
            .map(|(n, ext, d)| {
                format!(
                    "  {{\"format\": {}, \"typical\": {}, \"notes\": {}}}",
                    jstr(n),
                    jstr(ext),
                    jstr(d)
                )
            })
            .collect();
        println!("[\n{}\n]", items.join(",\n"));
        return Ok(exit::OK);
    }

    println!("Input formats (detected from content first, extension second):\n");
    for (name, ext, desc) in FORMAT_TABLE {
        println!("  {name:<6} {ext:<14} {desc}");
    }
    println!(
        "\nForce one with --from <FORMAT> on import, convert, sync or inspect.\n\
         A Registry.pol carries no hive of its own: it is inferred from a Machine\\ or\n\
         User\\ path component, or set with --pol-root."
    );
    Ok(exit::OK)
}

/// One side of a `diff`: a file in any supported format, or a live key.
///
/// A string that parses as a registry path is treated as live. That is
/// unambiguous in practice — `HKCU\...` is not a legal relative file name — and
/// it means the same argument position accepts either kind.
fn diff_side(cli: &Cli, spec: &str, iopts: &cli::InputOpts) -> anyhow::Result<Vec<KeyBlock>> {
    if let Some(path) = RegPath::parse(spec) {
        let roots = Roots::live();
        let (blocks, report) = engine::export(&roots, &path, view_of(&cli.global), true)
            .map_err(|e| anyhow!("{spec}: {e}"))?;
        for (p, e) in &report.skipped {
            eprintln!("  skipped {p}: {e}");
        }
        if !report.skipped.is_empty() {
            eprintln!(
                "regx: {} subkey(s) of {spec} were unreadable; the comparison is incomplete",
                report.skipped.len()
            );
        }
        return Ok(blocks);
    }

    let file = Path::new(spec);
    if !file.exists() {
        return Err(anyhow!(
            "{spec:?} is neither an existing file nor a registry path starting with a known root"
        ));
    }
    Ok(read_any(cli, file, iopts)?.file.keys)
}

fn cmd_diff(
    cli: &Cli,
    a: &str,
    b: &str,
    iopts: &cli::InputOpts,
    out: Option<&Path>,
    exit_code: bool,
) -> anyhow::Result<i32> {
    let left = diff_side(cli, a, iopts)?;
    let right = diff_side(cli, b, iopts)?;
    let d = diff::compare(&left, &right);
    let (added, modified, removed) = d.counts();

    if cli.global.output == OutputFormat::Json {
        let mut items: Vec<String> = d
            .keys
            .iter()
            .map(|k| {
                format!(
                    "    {{\"kind\": \"key\", \"change\": {}, \"path\": {}}}",
                    jstr(&format!("{:?}", k.change).to_lowercase()),
                    jstr(&k.path.to_string())
                )
            })
            .collect();
        items.extend(d.values.iter().map(|v| {
            format!(
                "    {{\"kind\": \"value\", \"change\": {}, \"path\": {}, \"name\": {}, \
                 \"left\": {}, \"right\": {}}}",
                jstr(&format!("{:?}", v.change).to_lowercase()),
                jstr(&v.path.to_string()),
                jstr(&v.name.to_string()),
                v.left
                    .as_ref()
                    .map(|x| jstr(&x.preview()))
                    .unwrap_or_else(|| "null".into()),
                v.right
                    .as_ref()
                    .map(|x| jstr(&x.preview()))
                    .unwrap_or_else(|| "null".into()),
            )
        }));
        println!(
            "{{\n  \"a\": {},\n  \"b\": {},\n  \"added\": {added}, \"modified\": {modified}, \
             \"removed\": {removed},\n  \"changes\": [\n{}\n  ]\n}}",
            jstr(a),
            jstr(b),
            items.join(",\n")
        );
    } else if d.is_empty() {
        println!("No differences.");
    } else {
        println!("--- {a}\n+++ {b}\n");
        for k in &d.keys {
            println!("{} [{}]", k.change.sigil(), k.path);
        }
        for v in &d.values {
            match v.change {
                diff::Change::Modified => {
                    println!("{} {}\\{}", v.change.sigil(), v.path, v.name);
                    println!(
                        "    - {}",
                        v.left.as_ref().map(|x| x.preview()).unwrap_or_default()
                    );
                    println!(
                        "    + {}",
                        v.right.as_ref().map(|x| x.preview()).unwrap_or_default()
                    );
                }
                _ => {
                    let shown = v.right.as_ref().or(v.left.as_ref());
                    println!(
                        "{} {}\\{} = {}",
                        v.change.sigil(),
                        v.path,
                        v.name,
                        shown.map(|x| x.preview()).unwrap_or_default()
                    );
                }
            }
        }
        println!("\n{added} added, {modified} modified, {removed} removed");
    }

    if let Some(p) = out {
        if cli.global.dry_run {
            eprintln!("regx: --dry-run, patch not written");
        } else {
            let patch = d.to_patch();
            let banner = vec![
                format!("regx diff patch: applying this to {a} produces {b}"),
                format!("{added} added, {modified} modified, {removed} removed"),
            ];
            write_reg(p, &patch, None, &banner)?;
            eprintln!(
                "regx: patch -> {} ({} key block(s))",
                p.display(),
                patch.keys.len()
            );
        }
    }

    Ok(if exit_code && !d.is_empty() {
        exit::PARTIAL
    } else {
        exit::OK
    })
}

fn cmd_discover(
    cli: &Cli,
    target: Option<&Path>,
    policy: bool,
    registry_pointer: bool,
    verbose: bool,
    strict: bool,
) -> anyhow::Result<i32> {
    let target = match target {
        Some(t) => t.to_path_buf(),
        None => std::env::current_dir().context("cannot read the current directory")?,
    };

    let opts = discover::Options {
        policy,
        registry_pointer,
        verbose,
    };
    let r = discover::discover(&target, &opts).map_err(|e| anyhow!(e))?;

    if cli.global.output == OutputFormat::Json {
        let items: Vec<String> = r
            .found
            .iter()
            .map(|f| {
                let risks: Vec<String> = f.risks.iter().map(|x| jstr(&format!("{x:?}"))).collect();
                format!(
                    "    {{\"path\": {}, \"origin\": {}, \"rank\": {}, \"format\": {}, \
                     \"size\": {}, \"risks\": [{}]}}",
                    jstr(&f.path.display().to_string()),
                    jstr(&f.origin.label()),
                    f.origin.rank(),
                    match f.format {
                        Some(fmt) => jstr(fmt.name()),
                        None => "null".into(),
                    },
                    f.size,
                    risks.join(", ")
                )
            })
            .collect();
        println!(
            "{{\n  \"anchor\": {},\n  \"stem\": {},\n  \"found\": [\n{}\n  ]\n}}",
            jstr(&r.anchor.display().to_string()),
            jstr(&r.stem),
            items.join(",\n")
        );
        return Ok(if strict && r.risky() > 0 {
            exit::PARTIAL
        } else {
            exit::OK
        });
    }

    if let Some(exe) = &r.exe {
        println!("executable  {}", exe.display());
    }
    println!("anchor      {}", r.anchor.display());
    println!("stem        {}", r.stem);
    for n in &r.notes {
        println!("note        {n}");
    }

    if r.found.is_empty() {
        println!("\nNo companion files found.");
    } else {
        println!("\n{} companion file(s), in search order:\n", r.found.len());
        for f in &r.found {
            println!(
                "  [{}] {:<22} {}",
                f.origin.rank(),
                f.origin.label(),
                f.path.display()
            );
            println!(
                "      {:<10} {} bytes",
                f.format.map(|x| x.name()).unwrap_or("unknown"),
                f.size
            );
            for risk in &f.risks {
                println!("      RISK   {:?}: {}", risk, risk.explain());
            }
        }
    }

    if verbose && !r.searched.is_empty() {
        println!("\nProbed and absent ({}):", r.searched.len());
        for p in &r.searched {
            println!("  {}", p.display());
        }
    }

    let risky = r.risky();
    if risky > 0 {
        println!(
            "\n{risky} of {} hit(s) carry a risk. Read them with `regx inspect`, and \
             confirm the application really uses that rung before trusting it.",
            r.found.len()
        );
    }

    Ok(if strict && risky > 0 {
        exit::PARTIAL
    } else {
        exit::OK
    })
}

fn cmd_inspect(cli: &Cli, files: &[PathBuf], iopts: &cli::InputOpts) -> anyhow::Result<i32> {
    let mut worst = exit::OK;

    for path in files {
        let outcome = match read_any(cli, path, iopts) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("regx: {e:#}");
                worst = exit::PARSE;
                continue;
            }
        };

        let values: usize = outcome.file.keys.iter().map(|k| k.values.len()).sum();
        let deletes = outcome.file.keys.iter().filter(|k| k.delete).count();
        let mut hives: Vec<&str> = outcome
            .file
            .keys
            .iter()
            .map(|k| k.path.hive.long_name())
            .collect();
        hives.sort_unstable();
        hives.dedup();

        if cli.global.output == OutputFormat::Json {
            println!(
                "{{\"file\": {}, \"format\": {}, \"keys\": {}, \"values\": {}, \
                 \"keyDeletes\": {}, \"hives\": [{}], \"notes\": [{}]}}",
                jstr(&path.display().to_string()),
                jstr(outcome.format.name()),
                outcome.file.keys.len(),
                values,
                deletes,
                hives.iter().map(|h| jstr(h)).collect::<Vec<_>>().join(", "),
                outcome
                    .notes
                    .iter()
                    .map(|n| jstr(n))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            continue;
        }

        println!("{}", path.display());
        println!("  format      {}", outcome.format);
        println!(
            "  key blocks  {} ({deletes} whole-key delete(s))",
            outcome.file.keys.len()
        );
        println!("  values      {values}");
        println!("  hives       {}", hives.join(", "));
        for n in &outcome.notes {
            println!("  note        {n}");
        }

        // Show where each key would land if it were redirected, without writing.
        let refused = outcome
            .file
            .keys
            .iter()
            .filter(|k| redirect::map(&k.path, Policy::Auto).confidence == Confidence::Refuse)
            .count();
        if refused > 0 {
            println!("  {refused} key(s) have no per-user equivalent; `regx convert` shows which");
            worst = exit::PARTIAL;
        }
    }

    Ok(worst)
}

// ---------------------------------------------------------------------------
// self-check
// ---------------------------------------------------------------------------

fn cmd_self_check(g: &GlobalOpts) -> i32 {
    let findings = selfcheck::run();

    if g.output == OutputFormat::Json {
        let mut s = String::from("[\n");
        for (i, f) in findings.iter().enumerate() {
            s.push_str(&format!(
                "  {{\"area\": {}, \"verdict\": {}, \"detail\": {}}}{}\n",
                jstr(f.area),
                jstr(match f.verdict {
                    selfcheck::Verdict::Ok => "ok",
                    selfcheck::Verdict::Note => "note",
                    selfcheck::Verdict::Warn => "warn",
                }),
                jstr(&f.detail),
                if i + 1 < findings.len() { "," } else { "" }
            ));
        }
        s.push(']');
        println!("{s}");
    } else {
        println!("regx self-check");
        for f in &findings {
            let tag = match f.verdict {
                selfcheck::Verdict::Ok => "ok  ",
                selfcheck::Verdict::Note => "note",
                selfcheck::Verdict::Warn => "WARN",
            };
            println!("  [{tag}] {:<16} {}", f.area, f.detail);
        }
    }

    let warns = findings
        .iter()
        .filter(|f| f.verdict == selfcheck::Verdict::Warn)
        .count();
    if warns > 0 {
        exit::PARTIAL
    } else {
        exit::OK
    }
}
