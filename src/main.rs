mod audit;
mod batch;
mod cli;
mod coalesce;
mod copy_plan;
mod diff;
mod discover;
mod encoding;
mod engine;
mod file_io;
mod fingerprint;
mod fix;
mod formats;
mod hive;
mod ipc;
mod model;
mod parser;
mod policy;
mod redirect;
mod saved_plan;
mod search;
mod selfcheck;
mod sha256;
mod shell;
mod shortcut;
mod shortcut_manifest;
mod signature;
mod undo;
mod value;
mod winreg;
mod writer;
mod xml;

use anyhow::{anyhow, Context};
use clap::{CommandFactory as _, Parser as _};
use cli::{
    exit, Cli, Command, CompletionShell, DataFormat, GlobalOpts, HiveOp, LnkOp, LogLevel,
    MinConfidence, OnRefuse, OutputFormat, RedirectMode, RedirectOpts, ShortcutStyle,
};
use engine::Roots;
use model::*;
use parser::{ParseOutcome, Severity};
use redirect::{Confidence, Policy};
use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use winreg::View;

const MAX_REGISTRY_INPUT_BYTES: u64 = 64 * 1024 * 1024;

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

#[derive(Debug)]
struct ExitError {
    message: String,
    code: i32,
}

impl std::fmt::Display for ExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ExitError {}

fn usage(message: impl Into<String>) -> anyhow::Error {
    coded(exit::USAGE, message)
}

fn access_denied(message: impl Into<String>) -> anyhow::Error {
    coded(exit::ACCESS_DENIED, message)
}

fn coded(code: i32, message: impl Into<String>) -> anyhow::Error {
    anyhow!(ExitError {
        message: message.into(),
        code,
    })
}

fn main() -> ExitCode {
    let args = normalize_lnk_output_args(std::env::args_os());
    let args = match resolve_shell_cli_args(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("regx: {error}");
            return ExitCode::from(exit::USAGE as u8);
        }
    };
    let cli = Cli::parse_from(args);
    let code = match run(&cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("regx: {e:#}");
            if let Some(error) = e.downcast_ref::<ExitError>() {
                error.code
            } else {
                e.downcast_ref::<InputError>()
                    .map(|i| i.code)
                    .unwrap_or(exit::IO)
            }
        }
    };
    ExitCode::from(code as u8)
}

fn resolve_shell_cli_args(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Vec<std::ffi::OsString>, String> {
    args.into_iter()
        .map(|argument| {
            let Some(text) = argument.to_str() else {
                return Ok(argument);
            };
            if text
                .as_bytes()
                .windows(6)
                .any(|window| window.eq_ignore_ascii_case(b"shell:"))
            {
                shell::resolve_text(text).map(std::ffi::OsString::from)
            } else {
                Ok(argument)
            }
        })
        .collect()
}

/// Preserve the long-established global `--output json|text` while also
/// supporting the requested `lnk create --output FILE` spelling. Clap cannot
/// attach the same long option to a global and a nested argument, so only a
/// non-format value in the `lnk create` context is rewritten to the internal
/// unambiguous option name.
fn normalize_lnk_output_args(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Vec<std::ffi::OsString> {
    let args = args.into_iter().collect::<Vec<_>>();
    let mut output = Vec::with_capacity(args.len());
    let mut saw_lnk = false;
    let mut saw_create = false;
    let mut index = 0_usize;
    while index < args.len() {
        let text = args[index].to_string_lossy();
        if text.eq_ignore_ascii_case("lnk") {
            saw_lnk = true;
        } else if saw_lnk && text.eq_ignore_ascii_case("create") {
            saw_create = true;
        }

        if saw_create && text == "--output" {
            if let Some(value) = args.get(index + 1) {
                let value_text = value.to_string_lossy();
                if !matches!(value_text.as_ref(), "json" | "text") {
                    output.push("--shortcut-output".into());
                    output.push(value.clone());
                    index += 2;
                    continue;
                }
            }
        } else if saw_create {
            if let Some(value) = text.strip_prefix("--output=") {
                if !matches!(value, "json" | "text") {
                    output.push(format!("--shortcut-output={value}").into());
                    index += 1;
                    continue;
                }
            }
        }
        output.push(args[index].clone());
        index += 1;
    }
    output
}

fn run(cli: &Cli) -> anyhow::Result<i32> {
    if cli.global.output == OutputFormat::Json {
        if cli.self_check && cli.command.is_some() {
            eprintln!(
                "regx: `--self-check --output json` cannot be combined with a command because \
                 stdout must contain exactly one JSON document"
            );
            return Ok(exit::USAGE);
        }
        if let Some(command) = &cli.command {
            if let Some(guidance) = json_output_conflict(command) {
                eprintln!(
                    "regx: this command produces a data/script stream rather than a status \
                     document; {guidance}"
                );
                return Ok(exit::USAGE);
            }
        }
    }

    if !cli.self_check {
        if let Some(Command::Completions { shell }) = &cli.command {
            return cmd_completions(*shell);
        }
    }

    // Read before anything else so every enforcement point sees the same
    // policy, and so a machine with none configured pays for one key open.
    let policy = policy::Policy::load();

    if cli.self_check {
        let code = cmd_self_check(&cli.global, &policy);
        if cli.command.is_none() {
            return Ok(code);
        }
    }
    if let Some(Command::Completions { shell }) = &cli.command {
        return cmd_completions(*shell);
    }
    let Some(command) = &cli.command else {
        eprintln!("regx: no command given. Try `regx --help`, or `regx --self-check`.");
        return Ok(exit::USAGE);
    };
    match command {
        Command::Lnk { op } => cmd_lnk(cli, &policy, op),
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
            to,
            conflicts,
            reg4,
        } => cmd_convert(
            cli,
            &policy,
            ConvertJob {
                input: file,
                out: out.as_deref(),
                input_options: input,
                redirect,
                to: *to,
                conflicts: *conflicts,
                reg4: *reg4,
            },
        ),
        Command::Merge {
            files,
            input,
            out,
            to,
            conflicts,
            reg4,
        } => cmd_merge(cli, files, input, out.as_deref(), *to, *conflicts, *reg4),
        Command::Import {
            files,
            input,
            redirect,
            values,
            conflicts,
            backup,
            no_backup,
        } => cmd_import(
            cli,
            &policy,
            ImportJob {
                files,
                input,
                redirect,
                values: Some(values),
                backup: backup.as_deref(),
                no_backup: *no_backup,
                prune: false,
                prune_keys: false,
                conflicts: *conflicts,
            },
        ),
        Command::Undo { file, backup } => cmd_undo(cli, &policy, file, backup.as_deref()),
        Command::Sync {
            file,
            input,
            redirect,
            conflicts,
            prune,
            prune_keys,
            backup,
            no_backup,
        } => cmd_import(
            cli,
            &policy,
            ImportJob {
                files: std::slice::from_ref(file),
                input,
                redirect,
                values: None,
                backup: backup.as_deref(),
                no_backup: *no_backup,
                prune: *prune,
                prune_keys: *prune_keys,
                conflicts: *conflicts,
            },
        ),
        Command::Formats => cmd_formats(cli),
        Command::Completions { .. } => unreachable!("handled before policy loading"),
        Command::Audit {
            file,
            chain,
            rotate_to,
            write_anchor,
            verify_anchor,
            anchor_key,
            verbose,
        } => cmd_audit(
            cli,
            AuditJob {
                file,
                chain,
                rotate_to: rotate_to.as_deref(),
                write_anchor: write_anchor.as_deref(),
                verify_anchor: verify_anchor.as_deref(),
                anchor_key: anchor_key.as_deref(),
                verbose: *verbose,
            },
        ),
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
            computer,
            out,
            to,
            root_as,
            recursive,
            no_recursive,
            reg4,
            keys,
            values,
        } => cmd_export(
            cli,
            key,
            computer.as_deref(),
            out.as_deref(),
            ExportOptions {
                format: ExportFormatOptions {
                    to: *to,
                    reg4: *reg4,
                },
                root_as: root_as.as_deref(),
                recursive: *recursive && !*no_recursive,
                keys,
                values,
            },
        ),
        Command::Query {
            key,
            computer,
            value,
            recursive,
        } => cmd_query(cli, key, computer.as_deref(), value.as_deref(), *recursive),
        Command::Ls {
            key,
            computer,
            recursive,
            keys,
            limit,
        } => cmd_ls(
            cli,
            key,
            computer.as_deref(),
            *recursive,
            keys,
            *limit as usize,
        ),
        Command::Stats {
            source,
            computer,
            root_as,
            keys,
            values,
            input,
        } => cmd_stats(
            cli,
            source,
            computer.as_deref(),
            root_as.as_deref(),
            keys,
            values,
            input,
        ),
        Command::Fingerprint {
            source,
            computer,
            root_as,
            expect,
            expect_32,
            expect_64,
            keys,
            values,
            input,
        } => cmd_fingerprint(
            cli,
            FingerprintJob {
                source,
                computer: computer.as_deref(),
                root_as: root_as.as_deref(),
                expect: expect.as_deref(),
                expect_32: expect_32.as_deref(),
                expect_64: expect_64.as_deref(),
                key_filters: keys,
                value_filters: values,
                input,
            },
        ),
        Command::Set {
            key,
            value,
            r#type,
            data,
            redirect,
            backup,
        } => cmd_set(
            cli,
            &policy,
            SetJob {
                key,
                value,
                ty: r#type,
                data,
                redirect,
                backup: backup.as_deref(),
            },
        ),
        Command::Delete {
            key,
            value,
            recursive,
            backup,
        } => cmd_delete(
            cli,
            &policy,
            key,
            value.as_deref(),
            *recursive,
            backup.as_deref(),
        ),
        Command::Probe { key, computer } => cmd_probe(cli, key, computer.as_deref()),
        Command::Permissions {
            key,
            computer,
            compare,
            compare_computer,
            exit_code,
        } => cmd_permissions(
            cli,
            key,
            computer.as_deref(),
            compare.as_deref(),
            compare_computer.as_deref(),
            *exit_code,
        ),
        Command::Search {
            source,
            query,
            computer,
            mode,
            case_sensitive,
            input,
            field,
            include,
            exclude,
            values,
            limit,
        } => cmd_search(
            cli,
            SearchJob {
                source,
                query,
                computer: computer.as_deref(),
                mode: *mode,
                case_sensitive: *case_sensitive,
                input,
                fields: field,
                include,
                exclude,
                values,
                limit: *limit as usize,
            },
        ),
        Command::Watch {
            key,
            no_recursive,
            count,
            timeout,
        } => cmd_watch(cli, key, !*no_recursive, *count, *timeout),
        Command::Plan {
            files,
            input,
            redirect,
            conflicts,
            prune,
            prune_keys,
            save,
        } => cmd_plan(
            cli,
            &policy,
            PlanJob {
                files,
                input,
                redirect,
                prune: *prune,
                prune_keys: *prune_keys,
                save: save.as_deref(),
                conflicts: *conflicts,
            },
        ),
        Command::ApplyPlan { plan, backup } => {
            cmd_apply_plan(cli, &policy, plan, backup.as_deref())
        }
        Command::Batch {
            manifest,
            redirect,
            conflicts,
            backup,
        } => cmd_batch(
            cli,
            &policy,
            manifest,
            redirect,
            *conflicts,
            backup.as_deref(),
        ),
        Command::Copy {
            source,
            source_computer,
            dest,
            overwrite,
            backup,
            save_plan,
        } => cmd_copy_move(
            cli,
            &policy,
            CopyMoveJob {
                source,
                source_computer: source_computer.as_deref(),
                dest,
                overwrite: *overwrite,
                backup: backup.as_deref(),
                save_plan: save_plan.as_deref(),
                remove_source: false,
            },
        ),
        Command::Move {
            source,
            dest,
            overwrite,
            backup,
            save_plan,
        } => cmd_copy_move(
            cli,
            &policy,
            CopyMoveJob {
                source,
                source_computer: None,
                dest,
                overwrite: *overwrite,
                backup: backup.as_deref(),
                save_plan: save_plan.as_deref(),
                remove_source: true,
            },
        ),
        Command::CopyValue {
            source,
            source_value,
            source_computer,
            dest,
            dest_value,
            overwrite,
            backup,
            save_plan,
        } => cmd_copy_move_value(
            cli,
            &policy,
            ValueCopyMoveJob {
                source,
                source_value,
                source_computer: source_computer.as_deref(),
                dest,
                dest_value: dest_value.as_deref(),
                overwrite: *overwrite,
                backup: backup.as_deref(),
                save_plan: save_plan.as_deref(),
                remove_source: false,
            },
        ),
        Command::MoveValue {
            source,
            source_value,
            dest,
            dest_value,
            overwrite,
            backup,
            save_plan,
        } => cmd_copy_move_value(
            cli,
            &policy,
            ValueCopyMoveJob {
                source,
                source_value,
                source_computer: None,
                dest,
                dest_value: dest_value.as_deref(),
                overwrite: *overwrite,
                backup: backup.as_deref(),
                save_plan: save_plan.as_deref(),
                remove_source: true,
            },
        ),
        Command::ApplyCopyPlan { plan, backup } => {
            cmd_apply_copy_plan(cli, &policy, plan, backup.as_deref())
        }
        Command::Backup {
            key,
            computer,
            file,
        } => cmd_backup(cli, &policy, key, computer.as_deref(), file),
        Command::Restore {
            file,
            dest,
            overwrite,
            backup,
        } => cmd_restore(cli, &policy, file, dest, *overwrite, backup.as_deref()),
        Command::Hive {
            file,
            op,
            create,
            exclusive,
        } => {
            if policy.disable_hive {
                return Err(access_denied(
                    "the offline hive engine is disabled by administrative policy \
                     (HKLM\\SOFTWARE\\Policies\\regx, DisableHive)",
                ));
            }
            cmd_hive(cli, &policy, file, op, *create, *exclusive)
        }
        Command::Diff {
            a,
            computer_a,
            b,
            computer_b,
            map_a,
            map_b,
            input,
            out,
            to,
            exit_code,
            include,
            exclude,
            values,
            summary_only,
        } => cmd_diff(
            cli,
            DiffJob {
                a,
                computer_a: computer_a.as_deref(),
                b,
                computer_b: computer_b.as_deref(),
                map_a: map_a.as_deref(),
                map_b: map_b.as_deref(),
                input,
                out: out.as_deref(),
                to: *to,
                exit_code: *exit_code,
                include,
                exclude,
                values,
                summary_only: *summary_only,
            },
        ),
    }
}

/// Commands in this list intentionally own stdout as a non-status data stream.
///
/// Silently accepting the global JSON flag used to produce plain text for these
/// commands. Refusing the ambiguous combination keeps `--output json` a reliable
/// machine contract while preserving the dedicated data-format switches.
fn json_output_conflict(command: &Command) -> Option<&'static str> {
    match command {
        Command::Convert { .. } => Some("use `convert --to json` for registry-data JSON"),
        Command::Merge { .. } => Some("use `merge --to json` for registry-data JSON"),
        Command::Completions { .. } => {
            Some("completion scripts are shell source and cannot be encoded as JSON")
        }
        Command::Hive {
            op: HiveOp::Exec { .. },
            ..
        } => Some(
            "`hive exec` can contain several operations; invoke each operation separately for JSON",
        ),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn view_of(g: &GlobalOpts) -> View {
    match g.view {
        cli::View::Native => View::Native,
        cli::View::Bits32 => View::Bits32,
        cli::View::Bits64 => View::Bits64,
        cli::View::Both => unreachable!("--view both must be handled before view_of"),
    }
}

fn is_stdin(path: &Path) -> bool {
    path.as_os_str() == "-"
}

fn is_stream_input(path: &Path) -> bool {
    is_stdin(path) || ipc::is_named_pipe(path)
}

fn input_label(path: &Path) -> String {
    if is_stdin(path) {
        "<stdin>".to_string()
    } else if ipc::is_named_pipe(path) {
        ipc::label(path)
    } else {
        path.display().to_string()
    }
}

/// Read a named file, standard input, or a one-shot Windows named pipe.
///
/// Callers that accept more than one input first use `ensure_single_stdin` so
/// the stream is never consumed once and then silently seen as empty.
fn read_input_bytes(path: &Path) -> anyhow::Result<Vec<u8>> {
    if is_stdin(path) {
        read_bounded(std::io::stdin().lock(), MAX_REGISTRY_INPUT_BYTES, "<stdin>")
    } else if ipc::is_named_pipe(path) {
        ipc::read(path, MAX_REGISTRY_INPUT_BYTES).map_err(|error| anyhow!(error))
    } else {
        file_io::read_limited(path, MAX_REGISTRY_INPUT_BYTES, "registry-data input")
            .map_err(|error| anyhow!(error))
    }
}

fn read_bounded(
    reader: impl std::io::Read,
    max_bytes: u64,
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {label}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(anyhow!(
            "registry-data input exceeds the {max_bytes}-byte size limit: {label}"
        ));
    }
    Ok(bytes)
}

fn ensure_single_stdin<'a>(paths: impl IntoIterator<Item = &'a Path>) -> anyhow::Result<()> {
    if paths.into_iter().filter(|p| is_stdin(p)).count() > 1 {
        return Err(usage(
            "standard input (`-`) can only be used once in a command",
        ));
    }
    Ok(())
}

fn read_reg(path: &Path) -> anyhow::Result<ParseOutcome> {
    let bytes = read_input_bytes(path)?;
    Ok(parser::parse_bytes(&bytes))
}

fn read_options(o: &cli::InputOpts) -> anyhow::Result<formats::ReadOptions> {
    let mut opts = formats::ReadOptions::default();
    if let Some(h) = &o.pol_root {
        opts.pol_root = Hive::parse(h).ok_or_else(|| {
            usage(format!(
                "--pol-root {h:?} is not a hive name (try HKLM or HKCU)"
            ))
        })?;
    }
    opts.inf_section = o.inf_section.clone();
    opts.inf_language = o
        .inf_language
        .as_deref()
        .map(|language| {
            if language.len() != 4 || !language.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(usage(format!(
                    "--inf-language {language:?} is not a four-hex-digit Windows LANGID"
                )));
            }
            u16::from_str_radix(language, 16).map_err(|_| {
                usage(format!(
                    "--inf-language {language:?} is not a four-hex-digit Windows LANGID"
                ))
            })
        })
        .transpose()?;
    opts.admx_state = formats::admx::State::parse(&o.admx_state).ok_or_else(|| {
        usage(format!(
            "--admx-state {:?} is not 'enabled' or 'disabled'",
            o.admx_state
        ))
    })?;
    opts.admx_policy = o.admx_policy.clone();
    Ok(opts)
}

/// Read any supported format, reporting what was detected and anything the
/// reader had to decide on its own.
fn read_any(cli: &Cli, path: &Path, o: &cli::InputOpts) -> anyhow::Result<formats::ReadOutcome> {
    let bytes = read_input_bytes(path)?;

    let forced = match &o.from {
        Some(name) => Some(formats::Format::parse_name(name).ok_or_else(|| {
            usage(format!(
                "--from {name:?} is not a known format; run `regx formats`"
            ))
        })?),
        None => None,
    };

    // Streams have no trustworthy extension to use as a tie-breaker; content
    // detection still handles every distinctive format, and --from resolves
    // ambiguous text.
    let hint = if is_stream_input(path) {
        None
    } else {
        Some(path)
    };
    let outcome = formats::read(&bytes, hint, forced, &read_options(o)?).map_err(|e| {
        anyhow!(InputError {
            source: input_label(path),
            message: e,
            // Every reader failure means "this input could not be parsed as
            // registry data", which is exit code 3 by the documented contract.
            code: exit::PARSE,
        })
    })?;

    if cli.global.log_level >= LogLevel::Info {
        eprintln!(
            "regx: {} read as {}{}",
            input_label(path),
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
        for loss in &outcome.losses {
            eprintln!("  loss: {loss}");
        }
    }
    Ok(outcome)
}

fn require_lossless_input(
    outcome: formats::ReadOutcome,
    source: &Path,
    operation: &str,
) -> anyhow::Result<formats::ReadOutcome> {
    if outcome.losses.is_empty() {
        return Ok(outcome);
    }
    Err(anyhow!(InputError {
        source: input_label(source),
        message: format!(
            "{operation} requires an exact registry-data model, but the input contains:\n  {}",
            outcome.losses.join("\n  ")
        ),
        code: exit::PARSE,
    }))
}

fn require_allowed_conflicts(
    outcome: &formats::ReadOutcome,
    source: &Path,
    policy: cli::MergeConflictPolicy,
    operation: &str,
) -> anyhow::Result<()> {
    if policy == cli::MergeConflictPolicy::LastWins || outcome.conflicts.is_empty() {
        return Ok(());
    }
    let details = outcome
        .conflicts
        .iter()
        .map(|conflict| {
            format!(
                "{}\\{}: {:?} overridden by {:?}",
                conflict.path, conflict.value, conflict.old, conflict.new
            )
        })
        .collect::<Vec<_>>()
        .join("\n  ");
    Err(anyhow!(InputError {
        source: input_label(source),
        message: format!(
            "{operation} refused {} semantic conflict(s) inside this input:\n  {details}",
            outcome.conflicts.len()
        ),
        code: exit::PARSE,
    }))
}

fn require_coalesce_conflicts(
    report: &coalesce::CoalesceReport,
    policy: cli::MergeConflictPolicy,
    operation: &str,
) -> anyhow::Result<()> {
    for conflict in &report.conflicts {
        eprintln!(
            "  conflict {}\\{}: {:?} overridden by {:?}",
            conflict.path, conflict.value, conflict.old, conflict.new
        );
    }
    if policy == cli::MergeConflictPolicy::LastWins || report.conflicts.is_empty() {
        return Ok(());
    }
    Err(coded(
        exit::PARSE,
        format!(
            "{operation} refused {} semantic conflict(s); reconcile the input \
             or use --conflicts last-wins",
            report.conflicts.len()
        ),
    ))
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
    writer::validate_reg_names(file).map_err(|error| anyhow!(error))?;
    let text = writer::to_string_rooted(file, root_as, banner);
    let bytes = match file.format {
        RegFormat::V5 => encoding::encode_utf16le_bom(&text),
        RegFormat::V4 => encoding::encode_ansi(&text).map_err(|error| anyhow!(error))?,
    };
    file_io::atomic_write(path, &bytes)
        .with_context(|| format!("cannot write {}", path.display()))?;
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
fn open_audit(
    cli: &Cli,
    policy: &policy::Policy,
    command: &str,
) -> anyhow::Result<Option<audit::Logger>> {
    // Policy wins where it is stricter: an administrator's log path is used
    // when the caller supplied none, and redaction can be turned on but never
    // off. A flag may add restriction, never remove it.
    let path = match (&policy.audit_log, &cli.global.audit_log) {
        (Some(required), _) => required,
        (None, Some(asked)) => asked,
        (None, None) => return Ok(None),
    };
    let redact = cli.global.audit_redact || policy.audit_redact;
    let logger = audit::Logger::open(path, redact, command)
        .with_context(|| format!("cannot open the audit log {}", path.display()))?;
    if cli.global.log_level >= LogLevel::Info {
        eprintln!(
            "regx: audit log -> {}{}{}",
            path.display(),
            if policy.audit_log.is_some() {
                " (required by policy)"
            } else {
                ""
            },
            if redact {
                " (values redacted to digests)"
            } else {
                ""
            }
        );
    }
    Ok(Some(logger))
}

/// Refuse the whole operation if policy denies any key it would touch.
///
/// Failing rather than dropping the offending block: a partial apply that
/// silently omitted what an administrator forbade would leave the operator
/// believing the file went in whole.
fn enforce_denies(policy: &policy::Policy, file: &RegFile) -> anyhow::Result<()> {
    for block in &file.keys {
        if let Some(rule) = policy.denies(&block.path) {
            return Err(access_denied(format!(
                "{} is denied by administrative policy (rule: {rule}). Nothing was written.",
                block.path
            )));
        }
    }
    Ok(())
}

/// The command line as recorded in the audit log.
fn command_line() -> String {
    std::env::args().collect::<Vec<_>>().join(" ")
}

fn parse_key(s: &str) -> anyhow::Result<RegPath> {
    RegPath::parse(s).ok_or_else(|| {
        usage(format!(
            "{s:?} does not start with a known root (HKLM, HKCU, HKCR, HKU, HKCC)"
        ))
    })
}

fn roots_for_read(computer: Option<&str>, path: &RegPath) -> anyhow::Result<Roots> {
    let Some(computer) = computer else {
        return Ok(Roots::live());
    };
    let computer = computer.trim();
    let bare = computer.trim_start_matches('\\');
    if bare.is_empty()
        || bare.chars().any(char::is_control)
        || bare.contains(['\\', '/'])
        || bare.chars().any(char::is_whitespace)
    {
        return Err(usage("--computer must name a Windows computer"));
    }
    if !matches!(path.hive, Hive::Hklm | Hive::Hku) {
        return Err(usage(format!(
            "remote registry reads support only HKLM and HKU; {} is not accepted by RegConnectRegistryW",
            path.hive.long_name()
        )));
    }
    Roots::remote(computer, path.hive).map_err(|error| {
        coded(
            reg_exit(&error),
            format!("remote registry \\\\{bare}: {error}"),
        )
    })
}

fn confirm(g: &GlobalOpts, policy: &policy::Policy, prompt: &str) -> bool {
    // A dry run is not a write, so it is never gated.
    if g.dry_run {
        return true;
    }
    // -y is a convenience an administrator can take away.
    if g.yes {
        if !policy.require_confirm {
            return true;
        }
        eprintln!("regx: policy requires confirmation; -y does not apply");
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
// Windows Shell Known Folders and native shortcuts
// ---------------------------------------------------------------------------

fn cmd_lnk(cli: &Cli, policy: &policy::Policy, op: &LnkOp) -> anyhow::Result<i32> {
    match op {
        LnkOp::Create {
            target,
            output,
            workdir,
            args,
            description,
            icon,
            style,
        } => {
            let (icon_path, icon_index) = match icon {
                Some(spec) => {
                    let (path, index) = shortcut::parse_icon_spec(spec).map_err(usage)?;
                    (Some(path), index)
                }
                None => (None, 0),
            };
            let requested = shortcut::CreateOptions {
                target: target.clone(),
                output: output.clone(),
                working_directory: workdir.clone(),
                arguments: args.clone(),
                description: description.clone(),
                icon_path,
                icon_index,
                style: cli_shortcut_style(*style),
            };
            cmd_lnk_create(cli, policy, &requested)
        }
        LnkOp::Inspect { file } => {
            let info = shortcut::inspect(file).map_err(|error| anyhow!(error))?;
            print_link_info(cli, "inspect", &info, false, false, None);
            Ok(exit::OK)
        }
        LnkOp::Delete { file } => cmd_lnk_delete(cli, policy, file),
        LnkOp::Apply { file } => cmd_lnk_apply(cli, policy, file),
    }
}

fn cli_shortcut_style(style: ShortcutStyle) -> shortcut::ShowStyle {
    match style {
        ShortcutStyle::Normal => shortcut::ShowStyle::Normal,
        ShortcutStyle::Hidden => shortcut::ShowStyle::Hidden,
        ShortcutStyle::Minimized => shortcut::ShowStyle::Minimized,
    }
}

fn cmd_lnk_create(
    cli: &Cli,
    policy: &policy::Policy,
    requested: &shortcut::CreateOptions,
) -> anyhow::Result<i32> {
    let options = shortcut::resolve_options(requested).map_err(usage)?;
    shortcut::validate(&options).map_err(usage)?;
    let existed = options.output.exists();
    let before = existed
        .then(|| audit::file_digest(&options.output))
        .transpose()
        .with_context(|| format!("cannot hash existing shortcut {}", options.output.display()))?;
    if !confirm(
        &cli.global,
        policy,
        &format!(
            "{} native shortcut {} -> {}?",
            if existed { "Replace" } else { "Create" },
            options.output.display(),
            options.target.display()
        ),
    ) {
        return Err(access_denied("shortcut creation was not confirmed"));
    }
    let mut logger = open_audit(cli, policy, &command_line())?;
    if cli.global.dry_run {
        if let Some(log) = logger.as_mut() {
            log.record_artifact(audit::ArtifactEvent {
                op: audit::ArtifactOp::ShortcutCreate,
                path: &options.output,
                before_sha256: before.as_deref(),
                after_sha256: None,
                outcome: audit::Outcome::Simulated,
                detail: Some("dry-run"),
            });
        }
        let info = planned_link_info(&options);
        print_link_info(cli, "create", &info, true, existed, before.as_deref());
        return Ok(exit::OK);
    }

    let info = shortcut::create(&options, existed).map_err(|error| anyhow!(error))?;
    let after = audit::file_digest(&options.output)
        .with_context(|| format!("cannot hash shortcut {}", options.output.display()))?;
    if let Some(log) = logger.as_mut() {
        log.record_artifact(audit::ArtifactEvent {
            op: audit::ArtifactOp::ShortcutCreate,
            path: &options.output,
            before_sha256: before.as_deref(),
            after_sha256: Some(&after),
            outcome: audit::Outcome::Applied,
            detail: None,
        });
    }
    print_link_info(cli, "create", &info, false, existed, Some(&after));
    Ok(exit::OK)
}

fn cmd_lnk_delete(cli: &Cli, policy: &policy::Policy, file: &Path) -> anyhow::Result<i32> {
    let info = shortcut::inspect(file).map_err(|error| anyhow!(error))?;
    let before = audit::file_digest(&info.file)
        .with_context(|| format!("cannot hash shortcut {}", info.file.display()))?;
    if !confirm(
        &cli.global,
        policy,
        &format!("Delete native shortcut {}?", info.file.display()),
    ) {
        return Err(access_denied("shortcut deletion was not confirmed"));
    }
    let mut logger = open_audit(cli, policy, &command_line())?;
    if !cli.global.dry_run {
        shortcut::delete(&info.file).map_err(|error| anyhow!(error))?;
    }
    if let Some(log) = logger.as_mut() {
        log.record_artifact(audit::ArtifactEvent {
            op: audit::ArtifactOp::ShortcutDelete,
            path: &info.file,
            before_sha256: Some(&before),
            after_sha256: None,
            outcome: if cli.global.dry_run {
                audit::Outcome::Simulated
            } else {
                audit::Outcome::Applied
            },
            detail: cli.global.dry_run.then_some("dry-run"),
        });
    }
    print_link_info(
        cli,
        "delete",
        &info,
        cli.global.dry_run,
        true,
        Some(&before),
    );
    Ok(exit::OK)
}

fn cmd_lnk_apply(cli: &Cli, policy: &policy::Policy, source: &Path) -> anyhow::Result<i32> {
    if is_stream_input(source) && !cli.global.dry_run && (!cli.global.yes || policy.require_confirm)
    {
        return Err(usage(
            "applying a shortcut manifest from stdin or a named pipe requires -y (and cannot be used when policy requires interactive confirmation)",
        ));
    }
    let bytes = read_input_bytes(source)?;
    let text = decode_shortcut_manifest(&bytes)
        .map_err(|error| usage(format!("{}: {error}", input_label(source))))?;
    let manifest = shortcut_manifest::parse(&text).map_err(usage)?;
    let mut prepared = Vec::with_capacity(manifest.actions.len());
    let mut destinations = std::collections::BTreeSet::new();
    for action in manifest.actions {
        let action = match action {
            shortcut_manifest::Action::Create(options) => {
                let options = shortcut::resolve_options(&options).map_err(usage)?;
                shortcut::validate(&options).map_err(usage)?;
                PreparedShortcutAction::Create(options)
            }
            shortcut_manifest::Action::Delete(path) => {
                let info = shortcut::inspect(&path).map_err(|error| anyhow!(error))?;
                PreparedShortcutAction::Delete(info.file)
            }
        };
        let destination = action.path();
        let identity = destination
            .as_os_str()
            .to_string_lossy()
            .to_ascii_lowercase();
        if !destinations.insert(identity) {
            return Err(usage(format!(
                "shortcut manifest changes {} more than once; split dependent changes into separate invocations",
                destination.display()
            )));
        }
        prepared.push(action);
    }

    let snapshots = prepared
        .iter()
        .map(|action| {
            let path = action.path();
            if path.exists() {
                std::fs::read(path)
                    .map(Some)
                    .with_context(|| format!("cannot snapshot shortcut {}", path.display()))
            } else {
                Ok(None)
            }
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if !confirm(
        &cli.global,
        policy,
        &format!("Apply {} native shortcut action(s)?", prepared.len()),
    ) {
        return Err(access_denied("shortcut manifest was not confirmed"));
    }
    let mut logger = open_audit(cli, policy, &command_line())?;
    if cli.global.dry_run {
        print_manifest_result(cli, &prepared, true, false);
        for (action, before) in prepared.iter().zip(&snapshots) {
            record_shortcut_action(
                logger.as_mut(),
                action,
                before.as_ref().map(|bytes| sha256::hash_hex(bytes)),
                None,
                audit::Outcome::Simulated,
                Some("dry-run"),
            );
        }
        return Ok(exit::OK);
    }

    for (index, action) in prepared.iter().enumerate() {
        let result = apply_shortcut_action(action);
        if let Err(error) = result {
            let mut rollback_failed = Vec::new();
            for prior in (0..index).rev() {
                if let Err(rollback_error) =
                    restore_shortcut_snapshot(prepared[prior].path(), snapshots[prior].as_deref())
                {
                    rollback_failed.push(rollback_error);
                }
            }
            print_manifest_result(cli, &prepared, false, true);
            let suffix = if rollback_failed.is_empty() {
                "all earlier shortcut actions were rolled back".to_string()
            } else {
                format!("rollback failures: {}", rollback_failed.join("; "))
            };
            return Err(anyhow!(
                "shortcut action {} failed: {error}; {suffix}",
                index + 1
            ));
        }
        let before = snapshots[index]
            .as_ref()
            .map(|bytes| sha256::hash_hex(bytes));
        let after = action
            .path()
            .exists()
            .then(|| audit::file_digest(action.path()))
            .transpose()
            .with_context(|| format!("cannot hash shortcut {}", action.path().display()))?;
        record_shortcut_action(
            logger.as_mut(),
            action,
            before,
            after,
            audit::Outcome::Applied,
            None,
        );
    }
    print_manifest_result(cli, &prepared, false, false);
    Ok(exit::OK)
}

fn decode_shortcut_manifest(bytes: &[u8]) -> Result<String, String> {
    if bytes.starts_with(&[0xff, 0xfe])
        || bytes.starts_with(&[0xfe, 0xff])
        || bytes.starts_with(&[0xef, 0xbb, 0xbf])
    {
        return encoding::decode_strict(bytes).map(|(text, _)| text);
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|error| format!("shortcut manifest is not valid UTF-8: {error}"))
}

enum PreparedShortcutAction {
    Create(shortcut::CreateOptions),
    Delete(PathBuf),
}

impl PreparedShortcutAction {
    fn path(&self) -> &Path {
        match self {
            Self::Create(options) => &options.output,
            Self::Delete(path) => path,
        }
    }

    fn operation(&self) -> &'static str {
        match self {
            Self::Create(_) => "create",
            Self::Delete(_) => "delete",
        }
    }
}

fn apply_shortcut_action(action: &PreparedShortcutAction) -> Result<(), String> {
    match action {
        PreparedShortcutAction::Create(options) => {
            shortcut::create(options, options.output.exists()).map(|_| ())
        }
        PreparedShortcutAction::Delete(path) => shortcut::delete(path).map(|_| ()),
    }
}

fn restore_shortcut_snapshot(path: &Path, bytes: Option<&[u8]>) -> Result<(), String> {
    match bytes {
        Some(bytes) => file_io::atomic_write(path, bytes)
            .map_err(|error| format!("cannot restore {}: {error}", path.display())),
        None if path.exists() => std::fs::remove_file(path)
            .map_err(|error| format!("cannot remove {} during rollback: {error}", path.display())),
        None => Ok(()),
    }
}

fn record_shortcut_action(
    logger: Option<&mut audit::Logger>,
    action: &PreparedShortcutAction,
    before: Option<String>,
    after: Option<String>,
    outcome: audit::Outcome,
    detail: Option<&str>,
) {
    let Some(logger) = logger else { return };
    logger.record_artifact(audit::ArtifactEvent {
        op: match action {
            PreparedShortcutAction::Create(_) => audit::ArtifactOp::ShortcutCreate,
            PreparedShortcutAction::Delete(_) => audit::ArtifactOp::ShortcutDelete,
        },
        path: action.path(),
        before_sha256: before.as_deref(),
        after_sha256: after.as_deref(),
        outcome,
        detail,
    });
}

fn planned_link_info(options: &shortcut::CreateOptions) -> shortcut::LinkInfo {
    shortcut::LinkInfo {
        file: options.output.clone(),
        target: options.target.clone(),
        working_directory: options.working_directory.clone(),
        arguments: options.arguments.clone().unwrap_or_default(),
        description: options.description.clone().unwrap_or_default(),
        icon_path: options.icon_path.clone(),
        icon_index: options.icon_index,
        style: options.style,
    }
}

fn print_link_info(
    cli: &Cli,
    action: &str,
    info: &shortcut::LinkInfo,
    dry_run: bool,
    replaced: bool,
    sha256: Option<&str>,
) {
    if cli.global.output == OutputFormat::Json {
        println!(
            "{{\"schemaVersion\":1,\"command\":\"lnk\",\"action\":{},\"dryRun\":{},\"replaced\":{},\"file\":{},\"target\":{},\"arguments\":{},\"workingDirectory\":{},\"description\":{},\"iconPath\":{},\"iconIndex\":{},\"style\":{},\"sha256\":{}}}",
            jstr(action),
            dry_run,
            replaced,
            jstr(&info.file.display().to_string()),
            jstr(&info.target.display().to_string()),
            jstr(&info.arguments),
            info.working_directory
                .as_ref()
                .map(|path| jstr(&path.display().to_string()))
                .unwrap_or_else(|| "null".into()),
            jstr(&info.description),
            info.icon_path
                .as_ref()
                .map(|path| jstr(&path.display().to_string()))
                .unwrap_or_else(|| "null".into()),
            info.icon_index,
            jstr(info.style.as_str()),
            sha256.map(jstr).unwrap_or_else(|| "null".into())
        );
    } else {
        println!(
            "{} {} -> {}{}",
            if dry_run { "Would" } else { "Shortcut" },
            action,
            info.file.display(),
            if action != "delete" {
                format!(" (target: {})", info.target.display())
            } else {
                String::new()
            }
        );
    }
}

fn print_manifest_result(
    cli: &Cli,
    actions: &[PreparedShortcutAction],
    dry_run: bool,
    failed: bool,
) {
    if cli.global.output == OutputFormat::Json {
        let items = actions
            .iter()
            .map(|action| {
                format!(
                    "{{\"operation\":{},\"path\":{}}}",
                    jstr(action.operation()),
                    jstr(&action.path().display().to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{{\"schemaVersion\":1,\"command\":\"lnk.apply\",\"dryRun\":{},\"failed\":{},\"actions\":[{}]}}",
            dry_run, failed, items
        );
    } else {
        println!(
            "{} {} shortcut action(s){}",
            if dry_run { "Would apply" } else { "Applied" },
            actions.len(),
            if failed {
                " (failed and rolled back)"
            } else {
                ""
            }
        );
        for action in actions {
            println!("  {} {}", action.operation(), action.path().display());
        }
    }
}

// ---------------------------------------------------------------------------
// Redirection
// ---------------------------------------------------------------------------

struct RedirectOutcome {
    skipped: usize,
    refused: usize,
    conflicts: usize,
}

fn apply_redirect(
    file: &mut RegFile,
    opts: &RedirectOpts,
    admin: &policy::Policy,
    level: LogLevel,
) -> RedirectOutcome {
    let policy = match opts.redirect {
        RedirectMode::Off => Policy::Off,
        RedirectMode::ClassesOnly => Policy::ClassesOnly,
        RedirectMode::Auto | RedirectMode::Force => Policy::Auto,
    };
    let mut floor = match (opts.redirect, opts.min_confidence) {
        (RedirectMode::Force, _) | (_, MinConfidence::Low) => Confidence::Low,
        (_, MinConfidence::Medium) => Confidence::Medium,
        (_, MinConfidence::High) => Confidence::High,
    };

    // Policy raises the floor and never lowers it: --min-confidence low cannot
    // undo an administrator's requirement, while --min-confidence high still
    // works on top of it.
    if let Some(required) = admin.min_confidence.as_deref() {
        let want = match required {
            "high" => Some(Confidence::High),
            "medium" => Some(Confidence::Medium),
            "low" => Some(Confidence::Low),
            _ => None,
        };
        if let Some(w) = want {
            if w > floor {
                if level >= LogLevel::Info {
                    eprintln!("  policy raises the redirection floor to {}", w.label());
                }
                floor = w;
            }
        }
    }

    let mut kept = Vec::new();
    let mut out = RedirectOutcome {
        skipped: 0,
        refused: 0,
        conflicts: 0,
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
            "  merged {} duplicate key block(s), {} semantic conflict(s)",
            report.blocks_merged,
            report.conflicts.len()
        );
    }
    out.conflicts = report.conflicts.len();
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
    if do_fix && files.len() != 1 {
        return Err(usage(
            "`validate --fix` accepts exactly one input so repairs cannot be partially applied",
        ));
    }
    ensure_single_stdin(files.iter().map(PathBuf::as_path))?;
    if do_fix && files.iter().any(|p| is_stream_input(p)) && out.is_none() {
        return Err(usage(
            "`validate` stream input with `--fix` requires --out because a stream cannot be rewritten",
        ));
    }
    if keep_backup && files.iter().any(|p| is_stream_input(p)) {
        return Err(usage(
            "`validate --backup` is not meaningful for stream input",
        ));
    }
    let mut worst = exit::OK;
    let mut json_reports = Vec::new();

    for path in files {
        let bytes = read_input_bytes(path)?;
        let (text, _) = {
            let o = encoding::decode(&bytes);
            (o.0, o.1)
        };
        let outcome = parser::parse_bytes(&bytes);
        let f = &outcome.file;

        let value_count = f.keys.iter().map(|k| k.values.len()).sum::<usize>();
        if cli.global.output != OutputFormat::Json {
            println!(
                "{}: {} / {} - {} key block(s), {} value(s)",
                input_label(path),
                f.format.header(),
                f.encoding,
                f.keys.len(),
                value_count,
            );
            report_diagnostics(path, &outcome, LogLevel::Debug);
        }

        if outcome.has_errors() {
            // A file with syntax errors is not safely repairable: we would be
            // guessing at the author's intent, not fixing a known defect.
            if cli.global.output == OutputFormat::Json {
                json_reports.push(validation_json(
                    path,
                    &outcome,
                    (false, cli.global.dry_run),
                    &[],
                    &[],
                    None,
                    [None, None],
                ));
            } else {
                eprintln!(
                    "{}: syntax errors present; --fix only repairs structurally valid files",
                    path.display()
                );
            }
            worst = exit::PARSE;
            continue;
        }

        if !do_fix {
            if cli.global.output == OutputFormat::Json {
                json_reports.push(validation_json(
                    path,
                    &outcome,
                    (false, cli.global.dry_run),
                    &[],
                    &[],
                    None,
                    [None, None],
                ));
            }
            if strict && !outcome.diagnostics.is_empty() && worst == exit::OK {
                worst = exit::PARSE;
            }
            continue;
        }

        let mut file = outcome.file.clone();
        let raw_fixes = fix::scan_raw(&text);
        let report = fix::repair(&mut file);
        let total = raw_fixes.len() + report.fixes.len();

        if cli.global.output != OutputFormat::Json {
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
        }

        if total == 0 {
            if cli.global.output == OutputFormat::Json {
                json_reports.push(validation_json(
                    path,
                    &outcome,
                    (false, cli.global.dry_run),
                    &[],
                    &report.unfixable,
                    Some(&file),
                    [None, None],
                ));
            } else {
                println!("  nothing to repair");
            }
            if !report.unfixable.is_empty() {
                worst = exit::PARSE;
            }
            continue;
        }

        let dest = out.unwrap_or(path.as_path());
        if cli.global.dry_run {
            if cli.global.output == OutputFormat::Json {
                let fixes = raw_fixes
                    .iter()
                    .chain(report.fixes.iter())
                    .collect::<Vec<_>>();
                json_reports.push(validation_json(
                    path,
                    &outcome,
                    (false, true),
                    &fixes,
                    &report.unfixable,
                    Some(&file),
                    [None, None],
                ));
            } else {
                println!("  --dry-run: {} repair(s) not written", total);
            }
            continue;
        }
        let backup_artifact = if keep_backup && dest == path.as_path() {
            let bak = path.with_extension(format!(
                "{}.bak",
                path.extension()
                    .map(|e| e.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ));
            std::fs::copy(path, &bak)
                .with_context(|| format!("cannot write backup {}", bak.display()))?;
            let (bytes, sha256) = sha256::hash_file(&bak)
                .with_context(|| format!("cannot checksum backup {}", bak.display()))?;
            if cli.global.output != OutputFormat::Json {
                println!("  backup: {}", bak.display());
            }
            Some((bak, bytes, sha256))
        } else {
            None
        };
        write_reg(dest, &file, None, &[])?;
        let (artifact_bytes, artifact_sha256) = sha256::hash_file(dest)
            .with_context(|| format!("cannot checksum repaired file {}", dest.display()))?;
        if cli.global.output == OutputFormat::Json {
            let fixes = raw_fixes
                .iter()
                .chain(report.fixes.iter())
                .collect::<Vec<_>>();
            json_reports.push(validation_json(
                path,
                &outcome,
                (true, false),
                &fixes,
                &report.unfixable,
                Some(&file),
                [
                    Some((dest, artifact_bytes, artifact_sha256.as_str())),
                    backup_artifact
                        .as_ref()
                        .map(|(path, bytes, sha256)| (path.as_path(), *bytes, sha256.as_str())),
                ],
            ));
        } else {
            println!(
                "  wrote {} ({} repair(s), {} lossy)",
                dest.display(),
                total,
                report.lossy_count()
            );
        }
        if !report.unfixable.is_empty() {
            worst = exit::PARTIAL;
        }
    }

    if cli.global.output == OutputFormat::Json {
        println!("[{}]", json_reports.join(","));
    }

    Ok(worst)
}

fn validation_json(
    path: &Path,
    outcome: &ParseOutcome,
    state: (bool, bool),
    fixes: &[&fix::Fix],
    unfixable: &[(usize, String)],
    repaired_data: Option<&RegFile>,
    artifacts: [Option<(&Path, u64, &str)>; 2],
) -> String {
    let (written, dry_run) = state;
    let [artifact, backup_artifact] = artifacts;
    let diagnostics = outcome
        .diagnostics
        .iter()
        .map(|diagnostic| {
            format!(
                "{{\"line\":{},\"severity\":{},\"message\":{}}}",
                diagnostic.line,
                jstr(match diagnostic.severity {
                    Severity::Warning => "warning",
                    Severity::Error => "error",
                }),
                jstr(&diagnostic.message)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let fixes = fixes
        .iter()
        .map(|fix| {
            format!(
                "{{\"line\":{},\"class\":{},\"message\":{}}}",
                fix.line,
                jstr(match fix.class {
                    fix::Class::Safe => "safe",
                    fix::Class::Lossy => "lossy",
                }),
                jstr(&fix.what)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let unfixable = unfixable
        .iter()
        .map(|(line, message)| format!("{{\"line\":{},\"message\":{}}}", line, jstr(message)))
        .collect::<Vec<_>>()
        .join(",");
    let repaired_data = repaired_data
        .map(writer::to_json)
        .unwrap_or_else(|| "null".into());
    let (output, bytes, sha256) = match artifact {
        Some((path, bytes, sha256)) => (
            jstr(&path.display().to_string()),
            bytes.to_string(),
            jstr(sha256),
        ),
        None => ("null".into(), "null".into(), "null".into()),
    };
    let (backup, backup_bytes, backup_sha256) = match backup_artifact {
        Some((path, bytes, sha256)) => (
            jstr(&path.display().to_string()),
            bytes.to_string(),
            jstr(sha256),
        ),
        None => ("null".into(), "null".into(), "null".into()),
    };
    format!(
        "{{\"file\":{},\"valid\":{},\"written\":{},\"dryRun\":{},\"keys\":{},\
         \"values\":{},\"diagnostics\":[{}],\"fixes\":[{}],\"unfixable\":[{}],\
         \"repairedData\":{},\"output\":{},\"bytes\":{},\"sha256\":{},\
         \"backup\":{},\"backupBytes\":{},\"backupSha256\":{}}}",
        jstr(&input_label(path)),
        !outcome.has_errors(),
        written,
        dry_run,
        outcome.file.keys.len(),
        outcome
            .file
            .keys
            .iter()
            .map(|key| key.values.len())
            .sum::<usize>(),
        diagnostics,
        fixes,
        unfixable,
        repaired_data,
        output,
        bytes,
        sha256,
        backup,
        backup_bytes,
        backup_sha256
    )
}

// ---------------------------------------------------------------------------
// convert / merge
// ---------------------------------------------------------------------------

struct ConvertJob<'a> {
    input: &'a Path,
    out: Option<&'a Path>,
    input_options: &'a cli::InputOpts,
    redirect: &'a RedirectOpts,
    to: DataFormat,
    conflicts: cli::MergeConflictPolicy,
    reg4: bool,
}

fn cmd_convert(cli: &Cli, policy: &policy::Policy, job: ConvertJob<'_>) -> anyhow::Result<i32> {
    let ConvertJob {
        input,
        out,
        input_options: iopts,
        redirect: ropts,
        to,
        conflicts,
        reg4,
    } = job;
    if reg4 && to != DataFormat::Reg {
        return Err(usage("--reg4 can only be used with --to reg"));
    }
    let outcome = require_lossless_input(read_any(cli, input, iopts)?, input, "convert")?;
    require_allowed_conflicts(&outcome, input, conflicts, "convert")?;
    let mut file = outcome.file;
    file.format = if reg4 { RegFormat::V4 } else { RegFormat::V5 };
    let r = apply_redirect(&mut file, ropts, policy, cli.global.log_level);
    if conflicts == cli::MergeConflictPolicy::Error && r.conflicts > 0 {
        return Err(coded(
            exit::PARSE,
            format!(
                "convert refused {} semantic conflict(s) after redirection; \
                 reconcile the input or use --conflicts last-wins",
                r.conflicts
            ),
        ));
    }

    if r.refused > 0 && ropts.on_refuse == OnRefuse::Fail {
        eprintln!(
            "regx: {} key(s) could not be redirected (--on-refuse fail)",
            r.refused
        );
        return Ok(exit::REDIRECT_REFUSED);
    }

    if to == DataFormat::Pol {
        let (bytes, root) = formats::pol::write(&file).map_err(|error| anyhow!(error))?;
        match out {
            Some(path) if !cli.global.dry_run => {
                file_io::atomic_write(path, &bytes)
                    .with_context(|| format!("cannot write {}", path.display()))?;
                eprintln!(
                    "regx: wrote {} as Registry.pol rooted at {} ({} key block(s), {} skipped, {} refused)",
                    path.display(),
                    root.long_name(),
                    file.keys.len(),
                    r.skipped,
                    r.refused
                );
            }
            _ => std::io::stdout()
                .lock()
                .write_all(&bytes)
                .context("cannot write Registry.pol output to stdout")?,
        }
        return Ok(if r.skipped > 0 {
            exit::PARTIAL
        } else {
            exit::OK
        });
    }

    let rendered = match to {
        DataFormat::Reg => {
            writer::validate_reg_names(&file).map_err(|error| anyhow!(error))?;
            writer::to_string(&file)
        }
        DataFormat::Json => writer::to_json(&file),
        DataFormat::Csv => writer::to_csv(&file),
        DataFormat::Pol => unreachable!("handled as binary output above"),
    };
    match out {
        Some(p) if !cli.global.dry_run => {
            if to == DataFormat::Reg {
                write_reg(p, &file, None, &[])?;
            } else {
                file_io::atomic_write(p, rendered.as_bytes())
                    .with_context(|| format!("cannot write {}", p.display()))?;
            }
            eprintln!(
                "regx: wrote {} as {:?} ({} key block(s), {} skipped, {} refused)",
                p.display(),
                to,
                file.keys.len(),
                r.skipped,
                r.refused
            );
        }
        _ if to == DataFormat::Reg && file.format == RegFormat::V4 => {
            let bytes = encoding::encode_ansi(&rendered).map_err(|error| anyhow!(error))?;
            std::io::stdout()
                .lock()
                .write_all(&bytes)
                .context("cannot write REGEDIT4 output to stdout")?;
        }
        _ => print!("{rendered}"),
    }
    Ok(if r.skipped > 0 {
        exit::PARTIAL
    } else {
        exit::OK
    })
}

fn cmd_merge(
    cli: &Cli,
    files: &[PathBuf],
    input: &cli::InputOpts,
    out: Option<&Path>,
    to: DataFormat,
    conflicts: cli::MergeConflictPolicy,
    reg4: bool,
) -> anyhow::Result<i32> {
    if reg4 && to != DataFormat::Reg {
        return Err(usage("--reg4 can only be used with --to reg"));
    }
    ensure_single_stdin(files.iter().map(PathBuf::as_path))?;
    let mut all = Vec::new();
    for p in files {
        let outcome = require_lossless_input(read_any(cli, p, input)?, p, "merge")?;
        require_allowed_conflicts(&outcome, p, conflicts, "merge")?;
        all.extend(outcome.file.keys);
    }

    let (keys, report) = coalesce::coalesce(all);
    for c in &report.conflicts {
        eprintln!(
            "  conflict {}\\{}: {:?} overridden by {:?}",
            c.path, c.value, c.old, c.new
        );
    }
    if conflicts == cli::MergeConflictPolicy::Error && !report.conflicts.is_empty() {
        return Err(coded(
            exit::PARSE,
            format!(
                "merge refused {} semantic conflict(s); \
                 reorder or reconcile the inputs, or use --conflicts last-wins",
                report.conflicts.len()
            ),
        ));
    }
    let file = RegFile {
        format: if reg4 { RegFormat::V4 } else { RegFormat::V5 },
        encoding: encoding::SourceEncoding::Utf16Le,
        keys,
    };
    eprintln!(
        "regx: merged {} file(s) -> {} key block(s), {} conflict(s)",
        files.len(),
        file.keys.len(),
        report.conflicts.len()
    );

    if to == DataFormat::Pol {
        let (bytes, root) = formats::pol::write(&file).map_err(|error| anyhow!(error))?;
        match out {
            Some(path) if !cli.global.dry_run => {
                file_io::atomic_write(path, &bytes)
                    .with_context(|| format!("cannot write {}", path.display()))?;
                eprintln!(
                    "regx: wrote {} as Registry.pol rooted at {}",
                    path.display(),
                    root.long_name()
                );
            }
            _ => std::io::stdout()
                .lock()
                .write_all(&bytes)
                .context("cannot write Registry.pol output to stdout")?,
        }
        return Ok(exit::OK);
    }

    let rendered = match to {
        DataFormat::Reg => {
            writer::validate_reg_names(&file).map_err(|error| anyhow!(error))?;
            writer::to_string(&file)
        }
        DataFormat::Json => writer::to_json(&file),
        DataFormat::Csv => writer::to_csv(&file),
        DataFormat::Pol => unreachable!("handled as binary output above"),
    };
    match out {
        Some(path) if !cli.global.dry_run => {
            if to == DataFormat::Reg {
                write_reg(path, &file, None, &[])?;
            } else {
                file_io::atomic_write(path, rendered.as_bytes())
                    .with_context(|| format!("cannot write {}", path.display()))?;
            }
        }
        _ => print!("{rendered}"),
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
    values: Option<&'a cli::ValueFilterOpts>,
    backup: Option<&'a Path>,
    no_backup: bool,
    prune: bool,
    prune_keys: bool,
    conflicts: cli::MergeConflictPolicy,
}

struct PreparedImport {
    file: RegFile,
    redirect: RedirectOutcome,
}

struct ValueFilterReport {
    selected: usize,
    omitted: usize,
    key_operations_omitted: usize,
}

fn filter_value_names(
    file: &mut RegFile,
    options: &cli::ValueFilterOpts,
) -> anyhow::Result<Option<ValueFilterReport>> {
    if options.include.is_empty() && options.exclude.is_empty() {
        return Ok(None);
    }
    let include = search::glob_matchers(&options.include, false).map_err(|error| anyhow!(error))?;
    let exclude = search::glob_matchers(&options.exclude, false).map_err(|error| anyhow!(error))?;
    let mut selected = 0;
    let mut omitted = 0;
    let mut key_operations_omitted = 0;
    let mut keys = Vec::new();
    for mut key in std::mem::take(&mut file.keys) {
        if key.delete || key.values.is_empty() {
            key_operations_omitted += 1;
            continue;
        }
        key.values.retain(|value| {
            let name = match &value.name {
                ValueName::Default => "@",
                ValueName::Named(name) => name,
            };
            let keep = (include.is_empty() || include.iter().any(|item| item.matches(name)))
                && !exclude.iter().any(|item| item.matches(name));
            if keep {
                selected += 1;
            } else {
                omitted += 1;
            }
            keep
        });
        if !key.values.is_empty() {
            keys.push(key);
        }
    }
    file.keys = keys;
    Ok(Some(ValueFilterReport {
        selected,
        omitted,
        key_operations_omitted,
    }))
}

fn filter_key_paths(file: &mut RegFile, options: &cli::KeyFilterOpts) -> anyhow::Result<bool> {
    if options.include_keys.is_empty() && options.exclude_keys.is_empty() {
        return Ok(false);
    }
    let filters =
        search::Filters::compile_globs(&options.include_keys, &options.exclude_keys, false)
            .map_err(usage)?;
    file.keys
        .retain(|block| filters.allows(&block.path.to_string()));
    Ok(true)
}

struct ViewApplyReport {
    label: &'static str,
    applied: Option<engine::ApplyReport>,
    rollback: Option<engine::ApplyReport>,
}

struct ViewSnapshot {
    label: &'static str,
    view: View,
    file: RegFile,
    snapshot: undo::Snapshot,
}

type IncompleteViewSnapshots = Vec<(&'static str, Vec<(String, String)>)>;

fn selected_views(view: cli::View) -> Vec<(&'static str, View)> {
    match view {
        cli::View::Native => vec![("native", View::Native)],
        cli::View::Bits32 => vec![("32", View::Bits32)],
        cli::View::Bits64 => vec![("64", View::Bits64)],
        cli::View::Both => vec![("32", View::Bits32), ("64", View::Bits64)],
    }
}

fn capture_view_snapshots(
    roots: &Roots,
    file: &RegFile,
    views: &[(&'static str, View)],
) -> Result<Vec<ViewSnapshot>, IncompleteViewSnapshots> {
    let snapshots = views
        .iter()
        .map(|(label, view)| ViewSnapshot {
            label,
            view: *view,
            file: file.clone(),
            snapshot: undo::snapshot(roots, file, *view),
        })
        .collect::<Vec<_>>();
    let incomplete = snapshots
        .iter()
        .filter(|item| !item.snapshot.is_complete())
        .map(|item| (item.label, item.snapshot.unreadable.clone()))
        .collect::<Vec<_>>();
    if !incomplete.is_empty() {
        return Err(incomplete);
    }
    Ok(snapshots)
}

fn capture_prepared_view_snapshots(
    roots: &Roots,
    files: Vec<(&'static str, View, RegFile)>,
) -> Result<Vec<ViewSnapshot>, IncompleteViewSnapshots> {
    let snapshots = files
        .into_iter()
        .map(|(label, view, file)| {
            let snapshot = undo::snapshot(roots, &file, view);
            ViewSnapshot {
                label,
                view,
                file,
                snapshot,
            }
        })
        .collect::<Vec<_>>();
    let incomplete = snapshots
        .iter()
        .filter(|item| !item.snapshot.is_complete())
        .map(|item| (item.label, item.snapshot.unreadable.clone()))
        .collect::<Vec<_>>();
    if incomplete.is_empty() {
        Ok(snapshots)
    } else {
        Err(incomplete)
    }
}

fn apply_with_view_snapshots(
    roots: &Roots,
    snapshots: &[ViewSnapshot],
    dry_run: bool,
    mut audit: Option<&mut audit::Logger>,
) -> Vec<ViewApplyReport> {
    let mut reports = snapshots
        .iter()
        .map(|snapshot| ViewApplyReport {
            label: snapshot.label,
            applied: None,
            rollback: None,
        })
        .collect::<Vec<_>>();
    for index in 0..snapshots.len() {
        let applied = engine::apply_audited(
            roots,
            &snapshots[index].file,
            snapshots[index].view,
            dry_run,
            audit.as_deref_mut(),
        );
        let failed = !applied.failures.is_empty();
        reports[index].applied = Some(applied);
        if failed && !dry_run {
            // Roll back the failing view (which may itself be partial) and
            // every earlier view, in reverse order. No later view was touched.
            for rollback_index in (0..=index).rev() {
                let touched = reports[rollback_index]
                    .applied
                    .as_ref()
                    .is_some_and(|report| report.touched() > 0);
                if touched {
                    reports[rollback_index].rollback = Some(engine::apply_audited(
                        roots,
                        &snapshots[rollback_index].snapshot.file,
                        snapshots[rollback_index].view,
                        false,
                        audit.as_deref_mut(),
                    ));
                }
            }
            break;
        }
    }
    reports
}

fn prepare_import(
    cli: &Cli,
    policy: &policy::Policy,
    files: &[PathBuf],
    iopts: &cli::InputOpts,
    ropts: &RedirectOpts,
    conflicts: cli::MergeConflictPolicy,
) -> anyhow::Result<PreparedImport> {
    ensure_single_stdin(files.iter().map(PathBuf::as_path))?;
    let mut all = Vec::new();
    for path in files {
        let outcome =
            require_lossless_input(read_any(cli, path, iopts)?, path, "registry mutation")?;
        require_allowed_conflicts(&outcome, path, conflicts, "registry mutation")?;
        all.extend(outcome.file.keys);
    }
    let mut file = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys: all,
    };
    let redirect = apply_redirect(&mut file, ropts, policy, cli.global.log_level);
    if conflicts == cli::MergeConflictPolicy::Error && redirect.conflicts > 0 {
        return Err(coded(
            exit::PARSE,
            format!(
                "registry mutation refused {} semantic conflict(s) after combining and \
                 redirecting inputs; reconcile the sources or use --conflicts last-wins",
                redirect.conflicts
            ),
        ));
    }
    Ok(PreparedImport { file, redirect })
}

fn cmd_import(cli: &Cli, policy: &policy::Policy, job: ImportJob<'_>) -> anyhow::Result<i32> {
    let ImportJob {
        files,
        input: iopts,
        redirect: ropts,
        values,
        backup,
        no_backup,
        prune,
        prune_keys,
        conflicts,
    } = job;

    if files.iter().any(|p| is_stream_input(p))
        && !cli.global.dry_run
        && (!cli.global.yes || policy.require_confirm)
    {
        return Err(usage(
            "importing from stdin or a named pipe requires -y (and cannot be used when policy \
             requires interactive confirmation)",
        ));
    }

    let mut prepared = prepare_import(cli, policy, files, iopts, ropts, conflicts)?;
    if let Some(options) = values {
        if let Some(report) = filter_value_names(&mut prepared.file, options)? {
            eprintln!(
                "regx: value selection kept {}, omitted {} value(s) and {} whole-key operation(s)",
                report.selected, report.omitted, report.key_operations_omitted
            );
        }
    }
    let file = prepared.file;
    let r = prepared.redirect;
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

    // Checked here, before anything happens: redirection has resolved the final
    // destinations, and nothing has been written or asked yet. Leaving it until
    // just before the apply meant a denied import still read the whole subtree
    // to build an undo file, wrote that file, prompted the operator, waited for
    // a yes — and only then refused, claiming "Nothing was written" while an
    // undo file sat on disk.
    enforce_denies(policy, &file)?;

    let roots = Roots::live();
    let views = selected_views(cli.global.view);

    let mut prepared_files = Vec::with_capacity(views.len());
    for (label, view) in &views {
        let mut per_view = file.clone();
        if prune {
            per_view.keys = match add_prune_deletes(&roots, &per_view.keys, *view) {
                Ok(keys) => keys,
                Err(error) => {
                    eprintln!(
                        "regx: refusing incomplete value reconciliation in view {label}: {error}"
                    );
                    return Ok(exit::PARTIAL);
                }
            };
        }
        if prune_keys {
            per_view.keys = match add_prune_key_deletes(&roots, &per_view.keys, *view) {
                Ok(keys) => keys,
                Err(error) => {
                    eprintln!(
                        "regx: refusing incomplete key reconciliation in view {label}: {error}"
                    );
                    return Ok(exit::PARTIAL);
                }
            };
        }
        if prune || prune_keys {
            enforce_denies(policy, &per_view)?;
        }
        prepared_files.push((*label, *view, per_view));
    }

    // Capture every inverse before writing any view. These exact snapshots are
    // both persisted and later used for rollback, avoiding a second read and a
    // race between the undo file and the compensation transaction.
    let snapshots = if !no_backup {
        match capture_prepared_view_snapshots(&roots, prepared_files.clone()) {
            Ok(snapshots) => Some(snapshots),
            Err(incomplete) => {
                print_incomplete_view_snapshots(&incomplete);
                return Ok(exit::PARTIAL);
            }
        }
    } else {
        None
    };
    let mut undo_paths = Vec::new();
    if let Some(snapshots) = &snapshots {
        let base = backup.map(Path::to_path_buf).unwrap_or_else(|| {
            if is_stream_input(&files[0]) {
                undo::temporary_path("stream")
            } else {
                undo::default_path(&files[0])
            }
        });
        for snapshot in snapshots {
            let dest = view_undo_path(&base, snapshot.label, snapshots.len() > 1);
            undo_paths.push((snapshot.label, dest.clone()));
        }
    }

    let n = prepared_files
        .iter()
        .map(|(_, _, file)| file.keys.len())
        .max()
        .unwrap_or(0);
    if !confirm(
        &cli.global,
        policy,
        &format!("Apply {n} key block(s) to the live registry?"),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }

    if !cli.global.dry_run {
        if let Some(snapshots) = &snapshots {
            for (snapshot, (_, dest)) in snapshots.iter().zip(&undo_paths) {
                let banner = vec![
                    format!(
                        "regx undo snapshot for: {} (view {})",
                        input_label(&files[0]),
                        snapshot.label
                    ),
                    format!(
                        "{} value(s) captured, {} key(s) to remove on rollback",
                        snapshot.snapshot.restored_values,
                        snapshot.snapshot.new_keys.len()
                    ),
                    format!("Revert with `regx undo` and --view {}.", snapshot.label,),
                ];
                write_reg(dest, &snapshot.snapshot.file, None, &banner)?;
                eprintln!(
                    "regx: undo snapshot (view {}) -> {}",
                    snapshot.label,
                    dest.display()
                );
            }
        }
    }

    let mut logger = open_audit(cli, policy, &command_line())?;
    let reports = if let Some(snapshots) = &snapshots {
        apply_with_view_snapshots(&roots, snapshots, cli.global.dry_run, logger.as_mut())
    } else {
        let mut reports = prepared_files
            .iter()
            .map(|(label, _, _)| ViewApplyReport {
                label,
                applied: None,
                rollback: None,
            })
            .collect::<Vec<_>>();
        for (index, (_, view, file)) in prepared_files.iter().enumerate() {
            let applied =
                engine::apply_audited(&roots, file, *view, cli.global.dry_run, logger.as_mut());
            let failed = !applied.failures.is_empty();
            reports[index].applied = Some(applied);
            if failed && !cli.global.dry_run {
                break;
            }
        }
        reports
    };

    if cli.global.output == OutputFormat::Json {
        let rendered = reports
            .iter()
            .map(|report| {
                let undo_path = undo_paths
                    .iter()
                    .find(|(label, _)| *label == report.label)
                    .map(|(_, path)| path);
                let undo = undo_path
                    .map(|path| jstr(&path.display().to_string()))
                    .unwrap_or_else(|| "null".into());
                let evidence = undo_path
                    .map(|path| undo_evidence_json(path, cli.global.dry_run))
                    .transpose()?
                    .unwrap_or_else(|| "\"undoBytes\":null,\"undoSha256\":null".into());
                Ok(format!(
                    "{{\"view\":{},\"undo\":{}, {},\"apply\":{},\"rolledBack\":{},\"rollback\":{}}}",
                    jstr(report.label),
                    undo,
                    evidence,
                    report
                        .applied
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into()),
                    report.rollback.is_some(),
                    report
                        .rollback
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into())
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        println!(
            "{{\"atomic\":{},\"views\":[{}]}}",
            !no_backup,
            rendered.join(",")
        );
    } else {
        print_view_apply_reports(cli, &reports);
        if no_backup
            && reports.iter().any(|report| {
                report
                    .applied
                    .as_ref()
                    .is_some_and(|apply| !apply.failures.is_empty() && apply.touched() > 0)
            })
        {
            eprintln!("regx: WARNING - partial changes remain because --no-backup disabled automatic rollback");
        }
    }

    let result = view_apply_exit(&reports);
    Ok(if result == exit::OK && r.skipped > 0 {
        exit::PARTIAL
    } else {
        result
    })
}

fn view_undo_path(base: &Path, label: &str, multiple: bool) -> PathBuf {
    if !multiple {
        return base.to_path_buf();
    }
    let extension = base
        .extension()
        .and_then(|part| part.to_str())
        .unwrap_or("");
    let stem = base
        .file_stem()
        .and_then(|part| part.to_str())
        .unwrap_or("undo");
    let name = if extension.is_empty() {
        format!("{stem}.{label}")
    } else {
        format!("{stem}.{label}.{extension}")
    };
    base.with_file_name(name)
}

fn undo_bundle_base(path: &Path) -> PathBuf {
    if let Some(name) = path.file_name().and_then(|part| part.to_str()) {
        if let Some(base_name) = name
            .strip_suffix(".32")
            .or_else(|| name.strip_suffix(".64"))
        {
            return path.with_file_name(base_name);
        }
    }
    let Some(stem) = path.file_stem().and_then(|part| part.to_str()) else {
        return path.to_path_buf();
    };
    let Some(base_stem) = stem
        .strip_suffix(".32")
        .or_else(|| stem.strip_suffix(".64"))
    else {
        return path.to_path_buf();
    };
    let name = match path.extension().and_then(|part| part.to_str()) {
        Some(extension) if !extension.is_empty() => format!("{base_stem}.{extension}"),
        _ => base_stem.to_string(),
    };
    path.with_file_name(name)
}

fn cmd_undo(
    cli: &Cli,
    policy: &policy::Policy,
    file: &Path,
    backup: Option<&Path>,
) -> anyhow::Result<i32> {
    let input = cli::InputOpts {
        from: Some("reg".into()),
        admx_state: "enabled".into(),
        ..Default::default()
    };
    let redirect = RedirectOpts {
        redirect: RedirectMode::Off,
        min_confidence: MinConfidence::Medium,
        on_refuse: OnRefuse::Fail,
    };
    let views = selected_views(cli.global.view);
    let bundle_base = undo_bundle_base(file);
    let paired = views.len() > 1;
    let mut prepared = Vec::with_capacity(views.len());
    let mut inputs = Vec::with_capacity(views.len());
    for (label, view) in views {
        let source = if paired {
            view_undo_path(&bundle_base, label, true)
        } else {
            file.to_path_buf()
        };
        if !source.is_file() {
            return Err(anyhow!(
                "undo snapshot not found: {}{}",
                source.display(),
                if paired {
                    "; a dual-view undo requires both .32 and .64 bundle members"
                } else {
                    ""
                }
            ));
        }
        let parsed = prepare_import(
            cli,
            policy,
            std::slice::from_ref(&source),
            &input,
            &redirect,
            cli::MergeConflictPolicy::LastWins,
        )?;
        let file = parsed.file;
        enforce_denies(policy, &file)?;
        prepared.push((label, view, file));
        inputs.push((label, source));
    }
    let roots = Roots::live();
    let snapshots = match capture_prepared_view_snapshots(&roots, prepared) {
        Ok(snapshots) => snapshots,
        Err(incomplete) => {
            print_incomplete_view_snapshots(&incomplete);
            return Ok(exit::PARTIAL);
        }
    };
    let redo_base = backup
        .map(Path::to_path_buf)
        .unwrap_or_else(|| undo::default_path(&bundle_base));
    let redo_paths = snapshots
        .iter()
        .map(|snapshot| {
            (
                snapshot.label,
                view_undo_path(&redo_base, snapshot.label, paired),
            )
        })
        .collect::<Vec<_>>();
    let key_blocks = snapshots
        .iter()
        .map(|snapshot| snapshot.file.keys.len())
        .max()
        .unwrap_or(0);
    if !confirm(
        &cli.global,
        policy,
        &format!(
            "Undo {key_blocks} key block(s) in {} registry view(s)?",
            snapshots.len()
        ),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }
    if !cli.global.dry_run {
        for (snapshot, (_, redo_path)) in snapshots.iter().zip(&redo_paths) {
            let source = inputs
                .iter()
                .find(|(label, _)| *label == snapshot.label)
                .map(|(_, path)| path)
                .expect("prepared undo input");
            write_reg(
                redo_path,
                &snapshot.snapshot.file,
                None,
                &[
                    format!(
                        "regx redo snapshot for undo (view {}): {}",
                        snapshot.label,
                        source.display()
                    ),
                    format!(
                        "{} value(s) captured, {} key(s) to remove on rollback",
                        snapshot.snapshot.restored_values,
                        snapshot.snapshot.new_keys.len()
                    ),
                ],
            )?;
            eprintln!(
                "regx: redo snapshot (view {}) -> {}",
                snapshot.label,
                redo_path.display()
            );
        }
    }
    let mut logger = open_audit(cli, policy, &command_line())?;
    let reports =
        apply_with_view_snapshots(&roots, &snapshots, cli.global.dry_run, logger.as_mut());
    if cli.global.output == OutputFormat::Json {
        let rendered = reports
            .iter()
            .map(|report| {
                let redo_path = redo_paths
                    .iter()
                    .find(|(label, _)| *label == report.label)
                    .map(|(_, path)| path);
                let redo = redo_path
                    .map(|path| jstr(&path.display().to_string()))
                    .unwrap_or_else(|| "null".into());
                let evidence = redo_path
                    .map(|path| redo_evidence_json(path, cli.global.dry_run))
                    .transpose()?
                    .unwrap_or_else(|| "\"redoBytes\":null,\"redoSha256\":null".into());
                Ok(format!(
                    "{{\"view\":{},\"redo\":{}, {},\"apply\":{},\"rolledBack\":{},\"rollback\":{}}}",
                    jstr(report.label),
                    redo,
                    evidence,
                    report
                        .applied
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into()),
                    report.rollback.is_some(),
                    report
                        .rollback
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into())
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        println!("{{\"atomic\":true,\"views\":[{}]}}", rendered.join(","));
    } else {
        print_view_apply_reports(cli, &reports);
    }
    Ok(view_apply_exit(&reports))
}

#[cfg(test)]
mod undo_command_tests {
    use super::undo_bundle_base;
    use std::path::Path;

    #[test]
    fn bundle_base_accepts_base_or_either_view_member() {
        assert_eq!(
            undo_bundle_base(Path::new(r"C:\snapshots\change.reg")),
            Path::new(r"C:\snapshots\change.reg")
        );
        assert_eq!(
            undo_bundle_base(Path::new(r"C:\snapshots\change.32.reg")),
            Path::new(r"C:\snapshots\change.reg")
        );
        assert_eq!(
            undo_bundle_base(Path::new(r"C:\snapshots\change.64.reg")),
            Path::new(r"C:\snapshots\change.reg")
        );
        assert_eq!(
            undo_bundle_base(Path::new(r"C:\snapshots\change.32")),
            Path::new(r"C:\snapshots\change")
        );
    }
}

fn apply_with_rollback(
    roots: &Roots,
    file: &RegFile,
    snapshot: Option<&undo::Snapshot>,
    view: View,
    dry_run: bool,
    mut audit: Option<&mut audit::Logger>,
) -> (engine::ApplyReport, Option<engine::ApplyReport>) {
    let applied = engine::apply_audited(roots, file, view, dry_run, audit.as_deref_mut());
    let rollback = if !dry_run && !applied.failures.is_empty() && applied.touched() > 0 {
        snapshot.map(|snapshot| engine::apply_audited(roots, &snapshot.file, view, false, audit))
    } else {
        None
    };
    (applied, rollback)
}

/// For `--prune`: any live value under a declared key that the file does not
/// mention becomes an explicit `"name"=-` delete, making the apply idempotent.
fn add_prune_deletes(
    roots: &Roots,
    keys: &[KeyBlock],
    view: View,
) -> anyhow::Result<Vec<KeyBlock>> {
    let mut out = Vec::with_capacity(keys.len());
    for block in keys {
        let mut block = block.clone();
        if !block.delete {
            match engine::export(roots, &block.path, view, false) {
                Ok((live, report)) => {
                    if !report.skipped.is_empty() {
                        return Err(anyhow!(
                            "{} key(s) at {} were unreadable",
                            report.skipped.len(),
                            block.path
                        ));
                    }
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
                Err(error) if error.is_not_found() => {}
                Err(error) => return Err(anyhow!("{}: {error}", block.path)),
            }
        }
        out.push(block);
    }
    Ok(out)
}

fn add_prune_key_deletes(
    roots: &Roots,
    keys: &[KeyBlock],
    view: View,
) -> anyhow::Result<Vec<KeyBlock>> {
    let declared = keys
        .iter()
        .filter(|block| !block.delete)
        .map(|block| block.path.clone())
        .collect::<Vec<_>>();
    let mut live = Vec::new();
    for parent in &declared {
        match engine::export(roots, parent, view, true) {
            Ok((blocks, report)) => {
                if !report.skipped.is_empty() {
                    let details = report
                        .skipped
                        .iter()
                        .take(5)
                        .map(|(path, why)| format!("{path}: {why}"))
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Err(anyhow!(
                        "{} subtree(s) below {} were unreadable ({details})",
                        report.skipped.len(),
                        parent
                    ));
                }
                live.extend(blocks.into_iter().map(|block| block.path));
            }
            Err(error) if error.is_not_found() => {}
            Err(error) => return Err(anyhow!("{parent}: {error}")),
        }
    }

    let deletes = undeclared_subtree_roots(&declared, &live);
    let mut out = keys.to_vec();
    out.extend(deletes.into_iter().map(|path| KeyBlock {
        path,
        delete: true,
        values: Vec::new(),
        line: 0,
    }));
    Ok(out)
}

fn undeclared_subtree_roots(declared: &[RegPath], live: &[RegPath]) -> Vec<RegPath> {
    let mut candidates = Vec::new();
    for parent in declared {
        let parent_parts = if parent.sub.is_empty() {
            0
        } else {
            parent.sub.split('\\').count()
        };
        for live_path in live {
            if !path_is_within(live_path, parent) {
                continue;
            }
            let parts = live_path.sub.split('\\').collect::<Vec<_>>();
            if parts.len() <= parent_parts {
                continue;
            }
            let child_sub = parts[..=parent_parts].join("\\");
            let child = RegPath {
                hive: parent.hive,
                sub: child_sub,
            };
            let represented = declared
                .iter()
                .any(|wanted| wanted.fold() == child.fold() || path_is_within(wanted, &child));
            if !represented {
                candidates.push(child);
            }
        }
    }
    candidates.sort_by_key(RegPath::fold);
    candidates.dedup_by(|a, b| a.fold() == b.fold());
    candidates
}

#[derive(Clone, Copy)]
struct PlanJob<'a> {
    files: &'a [PathBuf],
    input: &'a cli::InputOpts,
    redirect: &'a RedirectOpts,
    prune: bool,
    prune_keys: bool,
    save: Option<&'a Path>,
    conflicts: cli::MergeConflictPolicy,
}

fn cmd_plan(cli: &Cli, policy: &policy::Policy, job: PlanJob<'_>) -> anyhow::Result<i32> {
    let PlanJob {
        files,
        input: iopts,
        redirect: ropts,
        prune,
        prune_keys,
        save,
        conflicts,
    } = job;
    if save.is_some() && files.iter().any(|path| is_stream_input(path)) {
        return Err(usage(
            "a saved plan requires named source files; stream input cannot be re-verified",
        ));
    }
    let prepared = prepare_import(cli, policy, files, iopts, ropts, conflicts)?;
    if cli.global.view == cli::View::Both {
        return cmd_plan_both(cli, policy, &job, prepared);
    }
    let mut denied: Vec<(String, String)> = prepared
        .file
        .keys
        .iter()
        .filter_map(|block| {
            policy
                .denies(&block.path)
                .map(|rule| (block.path.to_string(), rule.to_string()))
        })
        .collect();
    let initially_blocked = !denied.is_empty();
    let mut planned_file = prepared.file;
    let mut reconciliation_failure = None;
    if !initially_blocked && prune {
        match add_prune_deletes(&Roots::live(), &planned_file.keys, view_of(&cli.global)) {
            Ok(keys) => planned_file.keys = keys,
            Err(error) => reconciliation_failure = Some(error.to_string()),
        }
    }
    if !initially_blocked && prune_keys {
        if reconciliation_failure.is_none() {
            match add_prune_key_deletes(&Roots::live(), &planned_file.keys, view_of(&cli.global)) {
                Ok(keys) => planned_file.keys = keys,
                Err(error) => reconciliation_failure = Some(error.to_string()),
            }
        }
        denied.extend(planned_file.keys.iter().filter_map(|block| {
            policy
                .denies(&block.path)
                .map(|rule| (block.path.to_string(), rule.to_string()))
        }));
        denied.sort();
        denied.dedup();
    }
    let blocked = !denied.is_empty() || reconciliation_failure.is_some();
    let empty = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys: Vec::new(),
    };
    // Import is all-or-nothing at the policy boundary: one denied destination
    // aborts the whole operation, so an honest plan must not show the remaining
    // blocks as mutations that would still happen.
    let effective = if blocked { &empty } else { &planned_file };
    let roots = Roots::live();
    let view = view_of(&cli.global);
    let mut mutations = engine::plan(&roots, effective, view);
    if let Some(error) = reconciliation_failure {
        mutations
            .failures
            .push(("subkey reconciliation".into(), error));
    }
    let rollback = undo::snapshot(&roots, effective, view);
    let rollback_path = if is_stream_input(&files[0]) {
        undo::temporary_path("stream-plan")
    } else {
        undo::default_path(&files[0])
    };
    let redact = cli.global.audit_redact || policy.audit_redact;
    let unsafe_plan = !denied.is_empty()
        || !mutations.failures.is_empty()
        || !rollback.is_complete()
        || prepared.redirect.skipped > 0
        || prepared.redirect.refused > 0;
    let mut saved_plan_evidence = None;
    if let Some(destination) = save {
        if unsafe_plan {
            eprintln!("regx: saved plan not written because the plan is incomplete or blocked");
        } else {
            let label = match cli.global.view {
                cli::View::Native => "native",
                cli::View::Bits32 => "32",
                cli::View::Bits64 => "64",
                cli::View::Both => unreachable!(),
            };
            saved_plan::save(
                destination,
                files,
                prune,
                prune_keys,
                &[(label, effective, &rollback)],
            )
            .map_err(|error| anyhow!(error))?;
            saved_plan_evidence = Some(sha256::hash_file(destination).with_context(|| {
                format!("cannot checksum saved plan {}", destination.display())
            })?);
            eprintln!("regx: saved digest-bound plan -> {}", destination.display());
        }
    }

    if cli.global.output == OutputFormat::Json {
        let (saved_plan, saved_plan_bytes, saved_plan_sha256) =
            match (save, saved_plan_evidence.as_ref()) {
                (Some(path), Some((bytes, digest))) => (
                    jstr(&path.display().to_string()),
                    bytes.to_string(),
                    jstr(digest),
                ),
                _ => ("null".into(), "null".into(), "null".into()),
            };
        let changes = mutations
            .changes
            .iter()
            .map(|change| {
                format!(
                    "    {{\"op\": {}, \"path\": {}, \"name\": {}, \"before\": {}, \"after\": {}}}",
                    jstr(match change.op {
                        engine::PlanOp::KeyCreate => "key.create",
                        engine::PlanOp::KeyDelete => "key.delete",
                        engine::PlanOp::ValueSet => "value.set",
                        engine::PlanOp::ValueDelete => "value.delete",
                    }),
                    jstr(&change.path.to_string()),
                    change
                        .name
                        .as_ref()
                        .map(|name| jstr(&name.to_string()))
                        .unwrap_or_else(|| "null".into()),
                    plan_data_json(change.name.as_ref(), change.before.as_ref(), redact),
                    plan_data_json(change.name.as_ref(), change.after.as_ref(), redact),
                )
            })
            .collect::<Vec<_>>();
        let failures = mutations
            .failures
            .iter()
            .map(|(target, why)| {
                format!(
                    "    {{\"target\": {}, \"problem\": {}}}",
                    jstr(target),
                    jstr(why)
                )
            })
            .collect::<Vec<_>>();
        let denied_json = denied
            .iter()
            .map(|(path, rule)| {
                format!(
                    "    {{\"path\": {}, \"rule\": {}}}",
                    jstr(&path.to_string()),
                    jstr(rule)
                )
            })
            .collect::<Vec<_>>();
        let policy_lines = policy
            .describe()
            .iter()
            .map(|line| jstr(line))
            .collect::<Vec<_>>();
        println!(
            "{{\n  \"files\": [{}],\n  \"prune\": {prune},\n  \"redacted\": {redact},\n  \"blocked\": {blocked},\n  \
             \"savedPlan\": {saved_plan},\n  \"savedPlanBytes\": {saved_plan_bytes},\n  \
             \"savedPlanSha256\": {saved_plan_sha256},\n  \
             \"redirect\": {{\"skipped\": {}, \"refused\": {}}},\n  \
             \"policy\": {{\"configured\": {}, \"decisions\": [{}], \"denied\": [\n{}\n  ]}},\n  \
             \"rollback\": {{\"path\": {}, \"complete\": {}, \"restoredValues\": {}, \
             \"newKeys\": {}, \"unreadable\": {}}},\n  \"changes\": [\n{}\n  ],\n  \
             \"failures\": [\n{}\n  ]\n}}",
            files
                .iter()
                .map(|path| jstr(&input_label(path)))
                .collect::<Vec<_>>()
                .join(", "),
            prepared.redirect.skipped,
            prepared.redirect.refused,
            policy.configured,
            policy_lines.join(", "),
            denied_json.join(",\n"),
            jstr(&rollback_path.display().to_string()),
            rollback.is_complete(),
            rollback.restored_values,
            rollback.new_keys.len(),
            rollback.unreadable.len(),
            changes.join(",\n"),
            failures.join(",\n"),
        );
    } else {
        println!(
            "Plan for {}",
            files
                .iter()
                .map(|p| input_label(p))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!(
            "  redirect  {} skipped, {} refused",
            prepared.redirect.skipped, prepared.redirect.refused
        );
        println!(
            "  rollback  {} ({})",
            rollback_path.display(),
            if rollback.is_complete() {
                "complete"
            } else {
                "INCOMPLETE"
            }
        );
        for (path, rule) in &denied {
            println!("  DENY      {path} (policy rule: {rule})");
        }
        for change in &mutations.changes {
            let op = match change.op {
                engine::PlanOp::KeyCreate => "CREATE KEY",
                engine::PlanOp::KeyDelete => "DELETE KEY",
                engine::PlanOp::ValueSet => "SET",
                engine::PlanOp::ValueDelete => "DELETE",
            };
            match &change.name {
                Some(name) => println!(
                    "  {op:<10} {}\\{}  {} -> {}",
                    change.path,
                    name,
                    plan_data_text(change.before.as_ref(), redact),
                    plan_data_text(change.after.as_ref(), redact)
                ),
                None => println!("  {op:<10} {}", change.path),
            }
        }
        for (target, why) in &mutations.failures {
            println!("  FAILED    {target}: {why}");
        }
        println!("  {} mutation(s); nothing written", mutations.changes.len());
    }

    Ok(if unsafe_plan { exit::PARTIAL } else { exit::OK })
}

struct ViewPlan {
    label: &'static str,
    denied: Vec<(String, String)>,
    mutations: engine::PlanReport,
    rollback: undo::Snapshot,
    rollback_path: PathBuf,
    desired: RegFile,
}

fn cmd_plan_both(
    cli: &Cli,
    policy: &policy::Policy,
    job: &PlanJob<'_>,
    prepared: PreparedImport,
) -> anyhow::Result<i32> {
    let files = job.files;
    let prune = job.prune;
    let prune_keys = job.prune_keys;
    let save = job.save;
    let roots = Roots::live();
    let base_path = if is_stream_input(&files[0]) {
        undo::temporary_path("stream-plan")
    } else {
        undo::default_path(&files[0])
    };
    let initial_denied = prepared
        .file
        .keys
        .iter()
        .filter_map(|block| {
            policy
                .denies(&block.path)
                .map(|rule| (block.path.to_string(), rule.to_string()))
        })
        .collect::<Vec<_>>();
    let empty = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys: Vec::new(),
    };
    let mut plans = Vec::new();

    for (label, view) in selected_views(cli.global.view) {
        let mut file = prepared.file.clone();
        let mut denied = initial_denied.clone();
        let mut reconciliation_failure = None;
        if denied.is_empty() && prune {
            match add_prune_deletes(&roots, &file.keys, view) {
                Ok(keys) => file.keys = keys,
                Err(error) => reconciliation_failure = Some(error.to_string()),
            }
        }
        if denied.is_empty() && prune_keys && reconciliation_failure.is_none() {
            match add_prune_key_deletes(&roots, &file.keys, view) {
                Ok(keys) => file.keys = keys,
                Err(error) => reconciliation_failure = Some(error.to_string()),
            }
        }
        if prune || prune_keys {
            denied.extend(file.keys.iter().filter_map(|block| {
                policy
                    .denies(&block.path)
                    .map(|rule| (block.path.to_string(), rule.to_string()))
            }));
            denied.sort();
            denied.dedup();
        }
        let blocked = !denied.is_empty() || reconciliation_failure.is_some();
        let effective = if blocked { &empty } else { &file };
        let mut mutations = engine::plan(&roots, effective, view);
        if let Some(error) = reconciliation_failure {
            mutations
                .failures
                .push(("subkey reconciliation".into(), error));
        }
        plans.push(ViewPlan {
            label,
            denied,
            mutations,
            rollback: undo::snapshot(&roots, effective, view),
            rollback_path: view_undo_path(&base_path, label, true),
            desired: effective.clone(),
        });
    }

    let redact = cli.global.audit_redact || policy.audit_redact;
    let unsafe_plan = prepared.redirect.skipped > 0
        || prepared.redirect.refused > 0
        || plans.iter().any(|plan| {
            !plan.denied.is_empty()
                || !plan.mutations.failures.is_empty()
                || !plan.rollback.is_complete()
        });
    let mut saved_plan_evidence = None;
    if let Some(destination) = save {
        if unsafe_plan {
            eprintln!("regx: saved plan not written because the plan is incomplete or blocked");
        } else {
            let saved_views = plans
                .iter()
                .map(|plan| (plan.label, &plan.desired, &plan.rollback))
                .collect::<Vec<_>>();
            saved_plan::save(destination, files, prune, prune_keys, &saved_views)
                .map_err(|error| anyhow!(error))?;
            saved_plan_evidence = Some(sha256::hash_file(destination).with_context(|| {
                format!("cannot checksum saved plan {}", destination.display())
            })?);
            eprintln!("regx: saved digest-bound plan -> {}", destination.display());
        }
    }
    if cli.global.output == OutputFormat::Json {
        let (saved_plan, saved_plan_bytes, saved_plan_sha256) =
            match (save, saved_plan_evidence.as_ref()) {
                (Some(path), Some((bytes, digest))) => (
                    jstr(&path.display().to_string()),
                    bytes.to_string(),
                    jstr(digest),
                ),
                _ => ("null".into(), "null".into(), "null".into()),
            };
        let views = plans
            .iter()
            .map(|plan| view_plan_json(plan, redact))
            .collect::<Vec<_>>()
            .join(",\n");
        let policy_lines = policy
            .describe()
            .iter()
            .map(|line| jstr(line))
            .collect::<Vec<_>>();
        println!(
            "{{\n  \"files\": [{}],\n  \"prune\": {prune},\n  \"redacted\": {redact},\n  \
             \"savedPlan\": {saved_plan},\n  \"savedPlanBytes\": {saved_plan_bytes},\n  \
             \"savedPlanSha256\": {saved_plan_sha256},\n  \
             \"redirect\": {{\"skipped\": {}, \"refused\": {}}},\n  \
             \"policy\": {{\"configured\": {}, \"decisions\": [{}]}},\n  \"views\": [\n{}\n  ]\n}}",
            files
                .iter()
                .map(|path| jstr(&input_label(path)))
                .collect::<Vec<_>>()
                .join(", "),
            prepared.redirect.skipped,
            prepared.redirect.refused,
            policy.configured,
            policy_lines.join(", "),
            views
        );
    } else {
        println!(
            "Plan for {}",
            files
                .iter()
                .map(|path| input_label(path))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!(
            "  redirect  {} skipped, {} refused",
            prepared.redirect.skipped, prepared.redirect.refused
        );
        for plan in &plans {
            println!("View {}", plan.label);
            println!(
                "  rollback  {} ({})",
                plan.rollback_path.display(),
                if plan.rollback.is_complete() {
                    "complete"
                } else {
                    "INCOMPLETE"
                }
            );
            for (path, rule) in &plan.denied {
                println!("  DENY      {path} (policy rule: {rule})");
            }
            print_plan_changes(&plan.mutations, redact);
        }
    }

    Ok(if unsafe_plan { exit::PARTIAL } else { exit::OK })
}

fn view_plan_json(plan: &ViewPlan, redact: bool) -> String {
    let changes = plan
        .mutations
        .changes
        .iter()
        .map(|change| {
            format!(
                "      {{\"op\": {}, \"path\": {}, \"name\": {}, \"before\": {}, \"after\": {}}}",
                jstr(match change.op {
                    engine::PlanOp::KeyCreate => "key.create",
                    engine::PlanOp::KeyDelete => "key.delete",
                    engine::PlanOp::ValueSet => "value.set",
                    engine::PlanOp::ValueDelete => "value.delete",
                }),
                jstr(&change.path.to_string()),
                change
                    .name
                    .as_ref()
                    .map(|name| jstr(&name.to_string()))
                    .unwrap_or_else(|| "null".into()),
                plan_data_json(change.name.as_ref(), change.before.as_ref(), redact),
                plan_data_json(change.name.as_ref(), change.after.as_ref(), redact),
            )
        })
        .collect::<Vec<_>>();
    let failures = plan
        .mutations
        .failures
        .iter()
        .map(|(target, why)| {
            format!(
                "      {{\"target\": {}, \"problem\": {}}}",
                jstr(target),
                jstr(why)
            )
        })
        .collect::<Vec<_>>();
    let denied = plan
        .denied
        .iter()
        .map(|(path, rule)| {
            format!(
                "      {{\"path\": {}, \"rule\": {}}}",
                jstr(path),
                jstr(rule)
            )
        })
        .collect::<Vec<_>>();
    format!(
        "    {{\"view\": {}, \"blocked\": {}, \"denied\": [\n{}\n    ], \
         \"rollback\": {{\"path\": {}, \"complete\": {}, \"restoredValues\": {}, \
         \"newKeys\": {}, \"unreadable\": {}}}, \"changes\": [\n{}\n    ], \
         \"failures\": [\n{}\n    ]}}",
        jstr(plan.label),
        !plan.denied.is_empty() || !plan.mutations.failures.is_empty(),
        denied.join(",\n"),
        jstr(&plan.rollback_path.display().to_string()),
        plan.rollback.is_complete(),
        plan.rollback.restored_values,
        plan.rollback.new_keys.len(),
        plan.rollback.unreadable.len(),
        changes.join(",\n"),
        failures.join(",\n")
    )
}

fn print_plan_changes(plan: &engine::PlanReport, redact: bool) {
    for change in &plan.changes {
        let op = match change.op {
            engine::PlanOp::KeyCreate => "CREATE KEY",
            engine::PlanOp::KeyDelete => "DELETE KEY",
            engine::PlanOp::ValueSet => "SET",
            engine::PlanOp::ValueDelete => "DELETE",
        };
        match &change.name {
            Some(name) => println!(
                "  {op:<10} {}\\{}  {} -> {}",
                change.path,
                name,
                plan_data_text(change.before.as_ref(), redact),
                plan_data_text(change.after.as_ref(), redact)
            ),
            None => println!("  {op:<10} {}", change.path),
        }
    }
    for (target, why) in &plan.failures {
        println!("  FAILED    {target}: {why}");
    }
    println!("  {} mutation(s); nothing written", plan.changes.len());
}

fn cmd_apply_plan(
    cli: &Cli,
    policy: &policy::Policy,
    plan_path: &Path,
    backup: Option<&Path>,
) -> anyhow::Result<i32> {
    let artifact = saved_plan::load(plan_path).map_err(|error| anyhow!(error))?;
    if let Err(error) = saved_plan::verify_sources(&artifact) {
        eprintln!("regx: refusing stale saved plan: {error}");
        return Ok(exit::PARTIAL);
    }

    let roots = Roots::live();
    let mut snapshots = Vec::with_capacity(artifact.views.len());
    for planned in &artifact.views {
        enforce_denies(policy, &planned.desired)?;
        let snapshot = undo::snapshot(&roots, &planned.desired, planned.view);
        if !snapshot.is_complete() {
            print_incomplete_view_snapshots(&[(
                planned.label.as_str(),
                snapshot.unreadable.clone(),
            )]);
            return Ok(exit::PARTIAL);
        }
        let actual = saved_plan::snapshot_digest(&snapshot);
        if actual != planned.current_digest {
            eprintln!(
                "regx: refusing stale saved plan: view {} current state changed \
                 (expected {}, found {})",
                planned.label, planned.current_digest, actual
            );
            return Ok(exit::PARTIAL);
        }
        let label = match planned.view {
            View::Native => "native",
            View::Bits32 => "32",
            View::Bits64 => "64",
        };
        snapshots.push(ViewSnapshot {
            label,
            view: planned.view,
            file: planned.desired.clone(),
            snapshot,
        });
    }

    let base = backup
        .map(Path::to_path_buf)
        .unwrap_or_else(|| undo::default_path(plan_path));
    if !confirm(
        &cli.global,
        policy,
        &format!(
            "Apply verified saved plan {} to {} registry view(s)?",
            plan_path.display(),
            snapshots.len()
        ),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }

    let undo_paths = snapshots
        .iter()
        .map(|snapshot| {
            (
                snapshot.label,
                view_undo_path(&base, snapshot.label, snapshots.len() > 1),
            )
        })
        .collect::<Vec<_>>();
    if !cli.global.dry_run {
        for (snapshot, (_, destination)) in snapshots.iter().zip(&undo_paths) {
            write_reg(
                destination,
                &snapshot.snapshot.file,
                None,
                &[
                    format!(
                        "regx undo snapshot for saved plan: {} (view {})",
                        plan_path.display(),
                        snapshot.label
                    ),
                    format!(
                        "{} value(s) captured, {} key(s) to remove on rollback",
                        snapshot.snapshot.restored_values,
                        snapshot.snapshot.new_keys.len()
                    ),
                ],
            )?;
            eprintln!(
                "regx: view {} undo snapshot -> {}",
                snapshot.label,
                destination.display()
            );
        }
    }

    let mut logger = open_audit(cli, policy, &command_line())?;
    let reports =
        apply_with_view_snapshots(&roots, &snapshots, cli.global.dry_run, logger.as_mut());
    print_direct_mutation_reports(cli, &reports, &undo_paths)?;
    Ok(view_apply_exit(&reports))
}

struct BatchViewReport {
    label: &'static str,
    applied: engine::ApplyReport,
}

struct BatchOperationReport {
    id: String,
    attempted: bool,
    skipped: bool,
    views: Vec<BatchViewReport>,
}

fn cmd_batch(
    cli: &Cli,
    policy: &policy::Policy,
    manifest: &Path,
    redirect: &RedirectOpts,
    conflicts: cli::MergeConflictPolicy,
    backup: Option<&Path>,
) -> anyhow::Result<i32> {
    let mut operations = batch::read(manifest).map_err(|error| anyhow!(error))?;
    let mut redirect_skipped = 0usize;
    let mut redirect_refused = 0usize;
    let mut redirect_conflicts = 0usize;
    let mut operation_skipped = Vec::with_capacity(operations.len());
    for operation in &mut operations {
        let outcome = apply_redirect(&mut operation.file, redirect, policy, cli.global.log_level);
        redirect_skipped += outcome.skipped;
        redirect_refused += outcome.refused;
        redirect_conflicts += outcome.conflicts;
        operation_skipped.push(operation.file.keys.is_empty());
        enforce_denies(policy, &operation.file)?;
    }
    if conflicts == cli::MergeConflictPolicy::Error && redirect_conflicts > 0 {
        return Err(coded(
            exit::PARSE,
            format!(
                "batch refused {redirect_conflicts} semantic conflict(s) introduced inside \
                 operations by redirection; reconcile the manifest or use --conflicts last-wins"
            ),
        ));
    }
    if redirect_refused > 0 && redirect.on_refuse == OnRefuse::Fail {
        eprintln!("regx: {redirect_refused} key(s) could not be redirected; batch not started");
        return Ok(exit::REDIRECT_REFUSED);
    }

    let combined = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys: operations
            .iter()
            .flat_map(|operation| operation.file.keys.iter().cloned())
            .collect(),
    };
    if combined.keys.is_empty() {
        eprintln!("regx: batch contains no operation left to apply");
        return Ok(if redirect_refused > 0 {
            exit::REDIRECT_REFUSED
        } else if redirect_skipped > 0 {
            exit::PARTIAL
        } else {
            exit::OK
        });
    }

    let roots = Roots::live();
    let views = selected_views(cli.global.view);
    let snapshots = match capture_view_snapshots(&roots, &combined, &views) {
        Ok(snapshots) => snapshots,
        Err(incomplete) => {
            print_incomplete_view_snapshots(&incomplete);
            return Ok(exit::PARTIAL);
        }
    };
    let base = backup
        .map(Path::to_path_buf)
        .unwrap_or_else(|| undo::default_path(manifest));
    let undo_paths = snapshots
        .iter()
        .map(|snapshot| {
            (
                snapshot.label,
                view_undo_path(&base, snapshot.label, snapshots.len() > 1),
            )
        })
        .collect::<Vec<_>>();
    if !confirm(
        &cli.global,
        policy,
        &format!(
            "Apply {} batch operation(s) atomically to {} registry view(s)?",
            operations.len(),
            views.len()
        ),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }

    if !cli.global.dry_run {
        for (snapshot, (_, destination)) in snapshots.iter().zip(&undo_paths) {
            write_reg(
                destination,
                &snapshot.snapshot.file,
                None,
                &[
                    format!(
                        "regx shared undo snapshot for batch: {} (view {})",
                        manifest.display(),
                        snapshot.label
                    ),
                    format!(
                        "{} operation(s); {} value(s) captured, {} key(s) to remove",
                        operations.len(),
                        snapshot.snapshot.restored_values,
                        snapshot.snapshot.new_keys.len()
                    ),
                ],
            )?;
            eprintln!(
                "regx: shared batch undo (view {}) -> {}",
                snapshot.label,
                destination.display()
            );
        }
    }

    let mut reports = operations
        .iter()
        .zip(&operation_skipped)
        .map(|(operation, skipped)| BatchOperationReport {
            id: operation.id.clone(),
            attempted: false,
            skipped: *skipped,
            views: Vec::new(),
        })
        .collect::<Vec<_>>();
    let mut touched_views = vec![false; views.len()];
    let mut failed_at = None;
    let mut logger = open_audit(cli, policy, &command_line())?;
    'operations: for (operation_index, operation) in operations.iter().enumerate() {
        if operation_skipped[operation_index] {
            continue;
        }
        reports[operation_index].attempted = true;
        for (view_index, (label, view)) in views.iter().enumerate() {
            let applied = engine::apply_audited(
                &roots,
                &operation.file,
                *view,
                cli.global.dry_run,
                logger.as_mut(),
            );
            touched_views[view_index] |= applied.touched() > 0;
            let failed = !applied.failures.is_empty();
            reports[operation_index]
                .views
                .push(BatchViewReport { label, applied });
            if failed {
                failed_at = Some(operation_index);
                break 'operations;
            }
        }
    }

    let mut rollbacks = Vec::new();
    if failed_at.is_some() && !cli.global.dry_run {
        for view_index in (0..views.len()).rev() {
            if touched_views[view_index] {
                let rollback = engine::apply_audited(
                    &roots,
                    &snapshots[view_index].snapshot.file,
                    snapshots[view_index].view,
                    false,
                    logger.as_mut(),
                );
                rollbacks.push(BatchViewReport {
                    label: snapshots[view_index].label,
                    applied: rollback,
                });
            }
        }
    }
    let rollback_failed = rollbacks
        .iter()
        .any(|report| !report.applied.failures.is_empty());
    print_batch_report(
        cli,
        manifest,
        &undo_paths,
        &reports,
        &rollbacks,
        failed_at,
        rollback_failed,
    )?;

    if rollback_failed {
        Ok(exit::PARTIAL)
    } else if failed_at.is_some() {
        Ok(exit::ACCESS_DENIED)
    } else if redirect_skipped > 0 || redirect_refused > 0 {
        Ok(exit::PARTIAL)
    } else {
        Ok(exit::OK)
    }
}

fn batch_operation_status(
    report: &BatchOperationReport,
    index: usize,
    failed_at: Option<usize>,
    rollback_failed: bool,
    dry_run: bool,
) -> &'static str {
    if report.skipped {
        return "skipped";
    }
    if !report.attempted {
        return "notAttempted";
    }
    if dry_run {
        return if report
            .views
            .iter()
            .any(|view| !view.applied.failures.is_empty())
        {
            "failed"
        } else {
            "planned"
        };
    }
    match failed_at {
        None => "applied",
        Some(failed) if index <= failed => {
            if rollback_failed {
                "rollbackFailed"
            } else {
                "rolledBack"
            }
        }
        Some(_) => "notAttempted",
    }
}

fn print_batch_report(
    cli: &Cli,
    manifest: &Path,
    undo_paths: &[(&str, PathBuf)],
    reports: &[BatchOperationReport],
    rollbacks: &[BatchViewReport],
    failed_at: Option<usize>,
    rollback_failed: bool,
) -> anyhow::Result<()> {
    if cli.global.output == OutputFormat::Json {
        let operations = reports
            .iter()
            .enumerate()
            .map(|(index, report)| {
                let views = report
                    .views
                    .iter()
                    .map(|view| {
                        format!(
                            "{{\"view\":{},\"apply\":{}}}",
                            jstr(view.label),
                            apply_report_json(&view.applied)
                        )
                    })
                    .collect::<Vec<_>>();
                format!(
                    "{{\"id\":{},\"status\":{},\"views\":[{}]}}",
                    jstr(&report.id),
                    jstr(batch_operation_status(
                        report,
                        index,
                        failed_at,
                        rollback_failed,
                        cli.global.dry_run
                    )),
                    views.join(",")
                )
            })
            .collect::<Vec<_>>();
        let undo = undo_paths
            .iter()
            .map(|(view, path)| {
                let evidence = if cli.global.dry_run {
                    "\"bytes\":null,\"sha256\":null".into()
                } else {
                    let (bytes, digest) = sha256::hash_file(path).with_context(|| {
                        format!("cannot checksum batch undo {}", path.display())
                    })?;
                    format!("\"bytes\":{bytes},\"sha256\":{}", jstr(&digest))
                };
                Ok(format!(
                    "{{\"view\":{},\"path\":{}, {}}}",
                    jstr(view),
                    jstr(&path.display().to_string()),
                    evidence
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let rollback = rollbacks
            .iter()
            .map(|view| {
                format!(
                    "{{\"view\":{},\"apply\":{}}}",
                    jstr(view.label),
                    apply_report_json(&view.applied)
                )
            })
            .collect::<Vec<_>>();
        println!(
            "{{\"schema\":{},\"schemaVersion\":1,\"manifest\":{},\"atomic\":true,\
             \"dryRun\":{},\"undo\":[{}],\"operations\":[{}],\"rollback\":[{}]}}",
            jstr(batch::RESULT_SCHEMA_URL),
            jstr(&manifest.display().to_string()),
            cli.global.dry_run,
            undo.join(","),
            operations.join(","),
            rollback.join(",")
        );
    } else {
        for (index, report) in reports.iter().enumerate() {
            eprintln!(
                "regx: batch {}: {}",
                report.id,
                batch_operation_status(
                    report,
                    index,
                    failed_at,
                    rollback_failed,
                    cli.global.dry_run
                )
            );
            for view in &report.views {
                eprintln!("  view {}", view.label);
                print_apply(cli, &view.applied);
            }
        }
        for rollback in rollbacks {
            eprintln!("regx: batch rollback (view {}):", rollback.label);
            print_apply(cli, &rollback.applied);
        }
    }
    Ok(())
}

fn plan_data_json(name: Option<&ValueName>, data: Option<&RegData>, redact: bool) -> String {
    match data {
        None => "null".into(),
        Some(data) if redact => {
            let digest = plan_digest(data);
            format!("{{\"redacted\": true, \"sha256\": {}}}", jstr(&digest))
        }
        Some(data) => {
            let exact = writer::value_to_json(&ValueEntry {
                name: name.cloned().unwrap_or(ValueName::Default),
                data: data.clone(),
                line: 0,
            });
            format!(
                "{{\"type\": {}, \"data\": {}, \"exact\": {}}}",
                jstr(data.type_name()),
                jstr(&data.preview()),
                exact
            )
        }
    }
}

fn plan_data_text(data: Option<&RegData>, redact: bool) -> String {
    match data {
        None => "<absent>".into(),
        Some(data) if redact => format!("<redacted sha256:{}>", plan_digest(data)),
        Some(data) => format!("{} {}", data.type_name(), data.preview()),
    }
}

fn plan_digest(data: &RegData) -> String {
    let mut bytes = Vec::new();
    if let Some((ty, raw)) = engine::data_to_raw(data) {
        bytes.extend_from_slice(&ty.to_le_bytes());
        bytes.extend_from_slice(&raw);
    } else {
        bytes.extend_from_slice(b"delete");
    }
    sha256::hash_hex(&bytes)
}

struct ValueCopyMoveJob<'a> {
    source: &'a str,
    source_value: &'a str,
    source_computer: Option<&'a str>,
    dest: &'a str,
    dest_value: Option<&'a str>,
    overwrite: bool,
    backup: Option<&'a Path>,
    save_plan: Option<&'a Path>,
    remove_source: bool,
}

fn cli_value_name(name: &str) -> ValueName {
    if name == "@" {
        ValueName::Default
    } else {
        ValueName::Named(name.to_string())
    }
}

fn value_name_matches(entry: &ValueName, wanted: &ValueName) -> bool {
    model::fold_str(engine::value_api_name(entry))
        == model::fold_str(engine::value_api_name(wanted))
}

fn cmd_copy_move_value(
    cli: &Cli,
    policy: &policy::Policy,
    job: ValueCopyMoveJob<'_>,
) -> anyhow::Result<i32> {
    let source = parse_key(job.source)?;
    let dest = parse_key(job.dest)?;
    let source_name = cli_value_name(job.source_value);
    let dest_name = cli_value_name(job.dest_value.unwrap_or(job.source_value));
    let verb = if job.remove_source {
        "move-value"
    } else {
        "copy-value"
    };
    if job.source_computer.is_none()
        && source.fold() == dest.fold()
        && value_name_matches(&source_name, &dest_name)
    {
        return Err(usage("source and destination are the same registry value"));
    }

    let roots = Roots::live();
    let source_roots = roots_for_read(job.source_computer, &source)?;
    let mut prepared = Vec::new();
    for (label, view) in selected_views(cli.global.view) {
        let (source_keys, source_report) = match engine::export(&source_roots, &source, view, false)
        {
            Ok(result) => result,
            Err(error) => {
                eprintln!("regx: view {label}: {error}");
                return Ok(reg_exit(&error));
            }
        };
        if !source_report.skipped.is_empty() {
            eprintln!("regx: refusing {verb} in view {label}; the source key is unreadable");
            return Ok(exit::PARTIAL);
        }
        let Some(source_entry) = source_keys
            .first()
            .and_then(|block| {
                block
                    .values
                    .iter()
                    .find(|entry| value_name_matches(&entry.name, &source_name))
            })
            .cloned()
        else {
            eprintln!(
                "regx: source value {}\\{} does not exist in view {label}",
                source, source_name
            );
            return Ok(exit::NOT_FOUND);
        };

        let destination = engine::probe(&roots, &dest, view);
        if destination.exists {
            let (dest_keys, report) = engine::export(&roots, &dest, view, false)?;
            if !report.skipped.is_empty() {
                eprintln!(
                    "regx: refusing {verb} in view {label}; the destination key is unreadable"
                );
                return Ok(exit::PARTIAL);
            }
            let collision = dest_keys.first().is_some_and(|block| {
                block
                    .values
                    .iter()
                    .any(|entry| value_name_matches(&entry.name, &dest_name))
            });
            if collision && !job.overwrite {
                return Err(usage(format!(
                    "destination value {dest}\\{dest_name} already exists in view {label}; \
                     pass --overwrite to replace it"
                )));
            }
        }

        let source_file = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf16Le,
            keys: vec![KeyBlock {
                path: source.clone(),
                delete: false,
                values: vec![source_entry.clone()],
                line: 0,
            }],
        };
        let copy_file = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf16Le,
            keys: vec![KeyBlock {
                path: dest.clone(),
                delete: false,
                values: vec![ValueEntry {
                    name: dest_name.clone(),
                    data: source_entry.data,
                    line: 0,
                }],
                line: 0,
            }],
        };
        let delete_file = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf16Le,
            keys: if job.remove_source {
                vec![KeyBlock {
                    path: source.clone(),
                    delete: false,
                    values: vec![ValueEntry {
                        name: source_name.clone(),
                        data: RegData::Delete,
                        line: 0,
                    }],
                    line: 0,
                }]
            } else {
                Vec::new()
            },
        };
        let mut combined = copy_file.clone();
        combined.keys.extend(delete_file.keys.clone());
        enforce_denies(policy, &combined)?;
        prepared.push((label, view, combined, source_file, copy_file, delete_file));
    }

    let snapshots = match capture_prepared_view_snapshots(
        &roots,
        prepared
            .iter()
            .map(|(label, view, combined, _, _, _)| (*label, *view, combined.clone()))
            .collect(),
    ) {
        Ok(value) => value,
        Err(incomplete) => {
            print_incomplete_view_snapshots(&incomplete);
            return Ok(exit::PARTIAL);
        }
    };
    let multiple = snapshots.len() > 1;
    if let Some(plan_base) = job.save_plan {
        let plan_paths = prepared
            .iter()
            .map(|(label, _, _, _, _, _)| (*label, view_undo_path(plan_base, label, multiple)))
            .collect::<Vec<_>>();
        if let Some((_, existing)) = plan_paths.iter().find(|(_, path)| path.exists()) {
            return Err(anyhow!(
                "{} already exists; refusing to overwrite a copy/move plan",
                existing.display()
            ));
        }
        let mut saved = Vec::new();
        for (((label, _, _, source_file, copy_file, delete_file), snapshot), (_, path)) in
            prepared.iter().zip(&snapshots).zip(&plan_paths)
        {
            if let Err(error) = copy_plan::save(
                path,
                copy_plan::SaveInput {
                    operation: if job.remove_source { "move" } else { "copy" },
                    view_label: label,
                    source_computer: job.source_computer,
                    source: &source,
                    destination: &dest,
                    source_value: Some(&source_name),
                    destination_value: Some(&dest_name),
                    overwrite: job.overwrite,
                    source_file,
                    copy_file,
                    delete_file,
                    current: &snapshot.snapshot,
                },
            ) {
                for path in &saved {
                    let _ = std::fs::remove_file(path);
                }
                return Err(anyhow!(error));
            }
            saved.push(path.clone());
        }
        if cli.global.output == OutputFormat::Json {
            let plans = plan_paths
                .iter()
                .map(|(label, path)| {
                    let (bytes, digest) = sha256::hash_file(path).with_context(|| {
                        format!("cannot checksum copy/move plan {}", path.display())
                    })?;
                    Ok(format!(
                        "{{\"view\":{},\"plan\":{},\"planBytes\":{},\"planSha256\":{}}}",
                        jstr(label),
                        jstr(&path.display().to_string()),
                        bytes,
                        jstr(&digest)
                    ))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            println!(
                "{{\"operation\":{},\"source\":{},\"sourceValue\":{},\"destination\":{},\
                 \"destinationValue\":{},\"plans\":[{}],\"saved\":true}}",
                jstr(verb),
                jstr(&source.to_string()),
                jstr(engine::value_api_name(&source_name)),
                jstr(&dest.to_string()),
                jstr(engine::value_api_name(&dest_name)),
                plans.join(",")
            );
        } else {
            for (label, path) in plan_paths {
                eprintln!(
                    "regx: saved digest-bound {verb} preview{} -> {}",
                    if multiple {
                        format!(" (view {label})")
                    } else {
                        String::new()
                    },
                    path.display()
                );
            }
        }
        return Ok(exit::OK);
    }
    let backup_base = job
        .backup
        .map(Path::to_path_buf)
        .unwrap_or_else(|| undo::temporary_path(verb));
    let backup_paths = snapshots
        .iter()
        .map(|snapshot| {
            (
                snapshot.label,
                view_undo_path(&backup_base, snapshot.label, multiple),
            )
        })
        .collect::<Vec<_>>();
    if !confirm(
        &cli.global,
        policy,
        &format!(
            "{} {}\\{} -> {}\\{}{}?",
            if job.remove_source {
                "Move value"
            } else {
                "Copy value"
            },
            source,
            source_name,
            dest,
            dest_name,
            if multiple { " in both views" } else { "" }
        ),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }

    if !cli.global.dry_run {
        for (snapshot, (_, path)) in snapshots.iter().zip(&backup_paths) {
            write_reg(
                path,
                &snapshot.snapshot.file,
                None,
                &[format!(
                    "regx undo snapshot for {verb}: {source}\\{source_name} -> {dest}\\{dest_name}"
                )],
            )?;
            eprintln!(
                "regx: undo snapshot{} -> {}",
                if multiple {
                    format!(" (view {})", snapshot.label)
                } else {
                    String::new()
                },
                path.display()
            );
        }
    }

    let mut logger = open_audit(cli, policy, &command_line())?;
    let mut reports = snapshots
        .iter()
        .map(|snapshot| CopyMoveViewReport {
            label: snapshot.label,
            copied: None,
            removed: None,
            rollback: None,
        })
        .collect::<Vec<_>>();
    for index in 0..prepared.len() {
        let (_, view, _, _, copy_file, delete_file) = &prepared[index];
        let (copied, removed, rollback) = apply_copy_move_atomic(
            &roots,
            copy_file,
            delete_file,
            &snapshots[index].snapshot,
            *view,
            cli.global.dry_run,
            logger.as_mut(),
        );
        let failed = !copied.failures.is_empty()
            || removed
                .as_ref()
                .is_some_and(|report| !report.failures.is_empty());
        reports[index].copied = Some(copied);
        reports[index].removed = removed;
        reports[index].rollback = rollback;
        if failed && !cli.global.dry_run {
            for prior in (0..index).rev() {
                reports[prior].rollback = Some(engine::apply_audited(
                    &roots,
                    &snapshots[prior].snapshot.file,
                    snapshots[prior].view,
                    false,
                    logger.as_mut(),
                ));
            }
            break;
        }
    }

    if cli.global.output == OutputFormat::Json {
        let views = reports
            .iter()
            .zip(&backup_paths)
            .map(|(report, (_, path))| {
                Ok(format!(
                    "{{\"view\":{},\"backup\":{}, {},\"copy\":{},\"removeSource\":{},\
                     \"rolledBack\":{},\"rollback\":{}}}",
                    jstr(report.label),
                    if cli.global.dry_run {
                        "null".into()
                    } else {
                        jstr(&path.display().to_string())
                    },
                    backup_evidence_json(path, cli.global.dry_run)?,
                    report
                        .copied
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into()),
                    report
                        .removed
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into()),
                    report.rollback.is_some(),
                    report
                        .rollback
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into())
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?
            .join(",");
        println!(
            "{{\"operation\":{},\"source\":{},\"sourceValue\":{},\"sourceComputer\":{},\
             \"destination\":{},\"destinationValue\":{},\"overwrite\":{},\"dryRun\":{},\
             \"views\":[{views}]}}",
            jstr(verb),
            jstr(&source.to_string()),
            jstr(engine::value_api_name(&source_name)),
            job.source_computer
                .map(jstr)
                .unwrap_or_else(|| "null".into()),
            jstr(&dest.to_string()),
            jstr(engine::value_api_name(&dest_name)),
            job.overwrite,
            cli.global.dry_run
        );
    } else {
        for report in &reports {
            if multiple {
                eprintln!("regx: view {}", report.label);
            }
            if let Some(copied) = &report.copied {
                print_apply(cli, copied);
            }
            if let Some(removed) = &report.removed {
                print_apply(cli, removed);
            }
            if let Some(rollback) = &report.rollback {
                eprintln!("regx: {verb} rollback:");
                print_apply(cli, rollback);
            }
        }
    }
    let failed = reports.iter().any(|report| {
        report
            .copied
            .as_ref()
            .is_none_or(|value| !value.failures.is_empty())
            || report
                .removed
                .as_ref()
                .is_some_and(|value| !value.failures.is_empty())
    });
    let rollback_failed = reports.iter().any(|report| {
        report
            .rollback
            .as_ref()
            .is_some_and(|value| !value.failures.is_empty())
    });
    Ok(if rollback_failed {
        exit::PARTIAL
    } else if failed {
        exit::ACCESS_DENIED
    } else {
        exit::OK
    })
}

struct CopyMoveJob<'a> {
    source: &'a str,
    source_computer: Option<&'a str>,
    dest: &'a str,
    overwrite: bool,
    backup: Option<&'a Path>,
    save_plan: Option<&'a Path>,
    remove_source: bool,
}

fn artifact_evidence_json(path: &Path, dry_run: bool) -> anyhow::Result<String> {
    if dry_run {
        return Ok("\"bytes\":null,\"sha256\":null".into());
    }
    let (bytes, digest) =
        sha256::hash_file(path).with_context(|| format!("cannot checksum {}", path.display()))?;
    Ok(format!("\"bytes\":{bytes},\"sha256\":{}", jstr(&digest)))
}

fn undo_evidence_json(path: &Path, dry_run: bool) -> anyhow::Result<String> {
    if dry_run {
        return Ok("\"undoBytes\":null,\"undoSha256\":null".into());
    }
    let (bytes, digest) = sha256::hash_file(path)
        .with_context(|| format!("cannot checksum undo artifact {}", path.display()))?;
    Ok(format!(
        "\"undoBytes\":{bytes},\"undoSha256\":{}",
        jstr(&digest)
    ))
}

fn redo_evidence_json(path: &Path, dry_run: bool) -> anyhow::Result<String> {
    if dry_run {
        return Ok("\"redoBytes\":null,\"redoSha256\":null".into());
    }
    let (bytes, digest) = sha256::hash_file(path)
        .with_context(|| format!("cannot checksum redo artifact {}", path.display()))?;
    Ok(format!(
        "\"redoBytes\":{bytes},\"redoSha256\":{}",
        jstr(&digest)
    ))
}

fn backup_evidence_json(path: &Path, dry_run: bool) -> anyhow::Result<String> {
    if dry_run {
        return Ok("\"backupBytes\":null,\"backupSha256\":null".into());
    }
    let (bytes, digest) = sha256::hash_file(path)
        .with_context(|| format!("cannot checksum backup artifact {}", path.display()))?;
    Ok(format!(
        "\"backupBytes\":{bytes},\"backupSha256\":{}",
        jstr(&digest)
    ))
}

fn cmd_backup(
    cli: &Cli,
    policy: &policy::Policy,
    key: &str,
    computer: Option<&str>,
    file: &Path,
) -> anyhow::Result<i32> {
    if policy.disable_hive {
        return Err(access_denied(
            "the offline hive engine is disabled by administrative policy",
        ));
    }
    let source = parse_key(key)?;
    let roots = roots_for_read(computer, &source)?;
    let views = selected_views(cli.global.view);
    let multiple = views.len() > 1;
    let mut prepared = Vec::with_capacity(views.len());
    for (label, view) in views {
        let output = view_undo_path(file, label, multiple);
        if output.exists() {
            return Err(anyhow!(
                "{} already exists; refusing to overwrite a backup",
                output.display()
            ));
        }
        let (keys, report) = match engine::export(&roots, &source, view, true) {
            Ok(result) => result,
            Err(error) => {
                eprintln!("regx: view {label}: {error}");
                return Ok(reg_exit(&error));
            }
        };
        if !report.skipped.is_empty() {
            eprintln!(
                "regx: refusing an incomplete backup for view {label}; {} subkey(s) were unreadable",
                report.skipped.len()
            );
            return Ok(exit::PARTIAL);
        }
        let root = RegPath {
            hive: Hive::Hkcu,
            sub: String::new(),
        };
        let backup_file = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf16Le,
            keys: rebase_subtree(&keys, &source, &root)?,
        };
        prepared.push((label, output, backup_file, report));
    }

    if cli.global.dry_run {
        if cli.global.output == OutputFormat::Json {
            if multiple {
                let views = prepared
                    .iter()
                    .map(|(label, output, _, report)| {
                        Ok(format!(
                            "{{\"view\":{},\"file\":{},\"keys\":{},\"values\":{}, {}}}",
                            jstr(label),
                            jstr(&output.display().to_string()),
                            report.keys,
                            report.values,
                            artifact_evidence_json(output, true)?
                        ))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?
                    .join(",");
                println!(
                    "{{\"source\":{},\"sourceComputer\":{},\"dryRun\":true,\"views\":[{views}]}}",
                    jstr(&source.to_string()),
                    computer.map(jstr).unwrap_or_else(|| "null".into())
                );
            } else {
                let (_, output, _, report) = &prepared[0];
                println!(
                    "{{\"source\":{},\"sourceComputer\":{},\"file\":{},\"dryRun\":true,\
                     \"keys\":{},\"values\":{}, {}}}",
                    jstr(&source.to_string()),
                    computer.map(jstr).unwrap_or_else(|| "null".into()),
                    jstr(&output.display().to_string()),
                    report.keys,
                    report.values,
                    artifact_evidence_json(output, true)?
                );
            }
        } else {
            for (label, output, _, report) in &prepared {
                let suffix = if multiple {
                    format!(" (view {label})")
                } else {
                    String::new()
                };
                eprintln!(
                    "regx: would back up {} key(s), {} value(s){suffix} -> {}",
                    report.keys,
                    report.values,
                    output.display()
                );
            }
        }
        return Ok(exit::OK);
    }

    let mut logger = open_audit(cli, policy, &command_line())?;
    let mut created = Vec::new();
    for (_, output, backup_file, _) in &prepared {
        let session = match hive::open(output, true, true, true) {
            Ok(session) => session,
            Err(error) => {
                let _ = std::fs::remove_file(output);
                for path in &created {
                    let _ = std::fs::remove_file(path);
                }
                return Err(anyhow!(error));
            }
        };
        let applied = engine::apply_audited(
            &session.roots,
            backup_file,
            View::Native,
            false,
            logger.as_mut(),
        );
        let flush = if applied.failures.is_empty() {
            session.flush().map_err(|error| anyhow!(error))
        } else {
            Ok(())
        };
        drop(session);
        if !applied.failures.is_empty() || flush.is_err() {
            let _ = std::fs::remove_file(output);
            for path in &created {
                let _ = std::fs::remove_file(path);
            }
            flush?;
            print_apply(cli, &applied);
            return Ok(exit::PARTIAL);
        }
        created.push(output.clone());
    }
    if cli.global.output == OutputFormat::Json {
        if multiple {
            let views = prepared
                .iter()
                .map(|(label, output, _, report)| {
                    Ok(format!(
                        "{{\"view\":{},\"file\":{},\"keys\":{},\"values\":{}, {}}}",
                        jstr(label),
                        jstr(&output.display().to_string()),
                        report.keys,
                        report.values,
                        artifact_evidence_json(output, false)?
                    ))
                })
                .collect::<anyhow::Result<Vec<_>>>()?
                .join(",");
            println!(
                "{{\"source\":{},\"sourceComputer\":{},\"dryRun\":false,\"views\":[{views}],\
                 \"limitations\":[\"ACLs\",\"key classes\",\"timestamps\"]}}",
                jstr(&source.to_string()),
                computer.map(jstr).unwrap_or_else(|| "null".into())
            );
        } else {
            let (_, output, _, report) = &prepared[0];
            println!(
                "{{\"source\":{},\"sourceComputer\":{},\"file\":{},\"dryRun\":false,\
                 \"keys\":{},\"values\":{}, {},\
                 \"limitations\":[\"ACLs\",\"key classes\",\"timestamps\"]}}",
                jstr(&source.to_string()),
                computer.map(jstr).unwrap_or_else(|| "null".into()),
                jstr(&output.display().to_string()),
                report.keys,
                report.values,
                artifact_evidence_json(output, false)?
            );
        }
    } else {
        for (label, output, _, report) in &prepared {
            let suffix = if multiple {
                format!(" (view {label})")
            } else {
                String::new()
            };
            eprintln!(
                "regx: backed up {} key(s), {} value(s){suffix} -> {}",
                report.keys,
                report.values,
                output.display()
            );
        }
        eprintln!("regx: note: application-hive backups preserve keys, types, and raw data; not ACLs, key classes, or timestamps");
    }
    Ok(exit::OK)
}

fn cmd_restore(
    cli: &Cli,
    policy: &policy::Policy,
    file: &Path,
    dest: &str,
    overwrite: bool,
    backup: Option<&Path>,
) -> anyhow::Result<i32> {
    if cli.global.view == cli::View::Both {
        return cmd_restore_both(cli, policy, file, dest, overwrite, backup);
    }
    if policy.disable_hive {
        return Err(access_denied(
            "the offline hive engine is disabled by administrative policy",
        ));
    }
    let dest = parse_key(dest)?;
    let view = view_of(&cli.global);
    let roots = Roots::live();
    let capability = engine::probe(&roots, &dest, view);
    if capability.exists && !overwrite {
        return Err(anyhow!(
            "destination {dest} already exists; pass --overwrite to merge into it"
        ));
    }
    let session = hive::open(file, false, false, true).map_err(|error| anyhow!(error))?;
    let source = RegPath {
        hive: Hive::Hkcu,
        sub: String::new(),
    };
    let (keys, report) = engine::export(&session.roots, &source, View::Native, true)?;
    if !report.skipped.is_empty() {
        eprintln!(
            "regx: refusing an incomplete restore; {} backup subkey(s) were unreadable",
            report.skipped.len()
        );
        return Ok(exit::PARTIAL);
    }
    drop(session);
    let restore_file = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys: rebase_subtree(&keys, &source, &dest)?,
    };
    enforce_denies(policy, &restore_file)?;
    let snapshot = undo::snapshot(&roots, &restore_file, view);
    if !snapshot.is_complete() {
        eprintln!(
            "regx: refusing restore; rollback would omit {} unreadable key(s)",
            snapshot.unreadable.len()
        );
        return Ok(exit::PARTIAL);
    }
    let undo_path = backup
        .map(Path::to_path_buf)
        .unwrap_or_else(|| undo::temporary_path("restore"));
    if !confirm(
        &cli.global,
        policy,
        &format!(
            "Restore {} -> {}{}?",
            file.display(),
            dest,
            if overwrite { " (merge)" } else { "" }
        ),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }
    if !cli.global.dry_run {
        write_reg(
            &undo_path,
            &snapshot.file,
            None,
            &[format!(
                "regx undo snapshot for restore: {} -> {dest}",
                file.display()
            )],
        )?;
        eprintln!("regx: undo snapshot -> {}", undo_path.display());
    }
    let mut logger = open_audit(cli, policy, &command_line())?;
    let (applied, rollback) = apply_with_rollback(
        &roots,
        &restore_file,
        Some(&snapshot),
        view,
        cli.global.dry_run,
        logger.as_mut(),
    );
    if cli.global.output == OutputFormat::Json {
        println!(
            "{{\"file\":{},\"destination\":{},\"overwrite\":{},\"dryRun\":{},\
             \"undo\":{}, {},\"apply\":{},\"rolledBack\":{},\"rollback\":{}}}",
            jstr(&file.display().to_string()),
            jstr(&dest.to_string()),
            overwrite,
            cli.global.dry_run,
            jstr(&undo_path.display().to_string()),
            undo_evidence_json(&undo_path, cli.global.dry_run)?,
            apply_report_json(&applied),
            rollback.is_some(),
            rollback
                .as_ref()
                .map(apply_report_json)
                .unwrap_or_else(|| "null".into())
        );
    } else {
        print_apply(cli, &applied);
        if let Some(rollback) = &rollback {
            eprintln!("regx: restore was partial; automatic rollback result:");
            print_apply(cli, rollback);
        }
    }
    Ok(if applied.failures.is_empty() {
        exit::OK
    } else if rollback
        .as_ref()
        .is_some_and(|report| report.failures.is_empty())
    {
        exit::ACCESS_DENIED
    } else {
        exit::PARTIAL
    })
}

fn cmd_restore_both(
    cli: &Cli,
    policy: &policy::Policy,
    file: &Path,
    dest: &str,
    overwrite: bool,
    backup: Option<&Path>,
) -> anyhow::Result<i32> {
    if policy.disable_hive {
        return Err(access_denied(
            "the offline hive engine is disabled by administrative policy",
        ));
    }
    let dest = parse_key(dest)?;
    let roots = Roots::live();
    let source = RegPath {
        hive: Hive::Hkcu,
        sub: String::new(),
    };
    let mut prepared = Vec::with_capacity(2);
    let mut input_paths = Vec::with_capacity(2);
    for (label, view) in selected_views(cli.global.view) {
        let input = view_undo_path(file, label, true);
        if !input.is_file() {
            return Err(anyhow!(
                "paired restore requires {}; create it with `backup --view both`",
                input.display()
            ));
        }
        let capability = engine::probe(&roots, &dest, view);
        if capability.exists && !overwrite {
            return Err(anyhow!(
                "destination {dest} already exists in view {label}; pass --overwrite to merge into it"
            ));
        }
        let session = hive::open(&input, false, false, true).map_err(|error| anyhow!(error))?;
        let (keys, report) = engine::export(&session.roots, &source, View::Native, true)?;
        if !report.skipped.is_empty() {
            eprintln!(
                "regx: refusing an incomplete restore for view {label}; {} backup subkey(s) were unreadable",
                report.skipped.len()
            );
            return Ok(exit::PARTIAL);
        }
        drop(session);
        let restore_file = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf16Le,
            keys: rebase_subtree(&keys, &source, &dest)?,
        };
        enforce_denies(policy, &restore_file)?;
        prepared.push((label, view, restore_file));
        input_paths.push((label, input));
    }

    let snapshots = match capture_prepared_view_snapshots(&roots, prepared) {
        Ok(snapshots) => snapshots,
        Err(incomplete) => {
            print_incomplete_view_snapshots(&incomplete);
            return Ok(exit::PARTIAL);
        }
    };
    let undo_base = backup
        .map(Path::to_path_buf)
        .unwrap_or_else(|| undo::temporary_path("restore"));
    let undo_paths = snapshots
        .iter()
        .map(|snapshot| {
            (
                snapshot.label,
                view_undo_path(&undo_base, snapshot.label, true),
            )
        })
        .collect::<Vec<_>>();
    if !confirm(
        &cli.global,
        policy,
        &format!(
            "Restore {}.32/64{} -> {}{}?",
            file.file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("backup"),
            file.extension()
                .and_then(|extension| extension.to_str())
                .map(|extension| format!(".{extension}"))
                .unwrap_or_default(),
            dest,
            if overwrite { " (merge)" } else { "" }
        ),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }
    if !cli.global.dry_run {
        for (snapshot, (_, undo_path)) in snapshots.iter().zip(&undo_paths) {
            let input = input_paths
                .iter()
                .find(|(label, _)| *label == snapshot.label)
                .map(|(_, path)| path)
                .expect("prepared restore input");
            write_reg(
                undo_path,
                &snapshot.snapshot.file,
                None,
                &[format!(
                    "regx undo snapshot for restore (view {}): {} -> {dest}",
                    snapshot.label,
                    input.display()
                )],
            )?;
            eprintln!(
                "regx: undo snapshot (view {}) -> {}",
                snapshot.label,
                undo_path.display()
            );
        }
    }
    let mut logger = open_audit(cli, policy, &command_line())?;
    let reports =
        apply_with_view_snapshots(&roots, &snapshots, cli.global.dry_run, logger.as_mut());
    if cli.global.output == OutputFormat::Json {
        let views = reports
            .iter()
            .zip(&input_paths)
            .zip(&undo_paths)
            .map(|((report, (_, input)), (_, undo))| {
                Ok(format!(
                    "{{\"view\":{},\"file\":{},\"undo\":{}, {},\"apply\":{},\
                     \"rolledBack\":{},\"rollback\":{}}}",
                    jstr(report.label),
                    jstr(&input.display().to_string()),
                    jstr(&undo.display().to_string()),
                    undo_evidence_json(undo, cli.global.dry_run)?,
                    report
                        .applied
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into()),
                    report.rollback.is_some(),
                    report
                        .rollback
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into())
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?
            .join(",");
        println!(
            "{{\"file\":{},\"destination\":{},\"overwrite\":{},\"dryRun\":{},\"views\":[{views}]}}",
            jstr(&file.display().to_string()),
            jstr(&dest.to_string()),
            overwrite,
            cli.global.dry_run
        );
    } else {
        print_view_apply_reports(cli, &reports);
    }
    Ok(view_apply_exit(&reports))
}

fn cmd_copy_move(cli: &Cli, policy: &policy::Policy, job: CopyMoveJob<'_>) -> anyhow::Result<i32> {
    let source = parse_key(job.source)?;
    let dest = parse_key(job.dest)?;
    let verb = if job.remove_source { "move" } else { "copy" };

    if job.source_computer.is_none() && source.fold() == dest.fold() {
        return Err(usage("source and destination are the same key"));
    }
    if job.remove_source && source.sub.is_empty() {
        return Err(usage("refusing to move or delete a predefined hive root"));
    }
    if job.source_computer.is_none() && path_is_within(&dest, &source) {
        return Err(usage(format!(
            "destination {} is inside source {}; recursive {verb} would consume its own output",
            dest, source
        )));
    }
    if cli.global.view == cli::View::Both {
        return cmd_copy_move_both(cli, policy, job, source, dest, verb);
    }

    let roots = Roots::live();
    let source_roots = roots_for_read(job.source_computer, &source)?;
    let view = view_of(&cli.global);
    let (source_keys, source_report) = match engine::export(&source_roots, &source, view, true) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("regx: {error}");
            return Ok(reg_exit(&error));
        }
    };
    if !source_report.skipped.is_empty() {
        eprintln!(
            "regx: refusing an incomplete {verb}; {} source subkey(s) were unreadable:",
            source_report.skipped.len()
        );
        for (path, why) in &source_report.skipped {
            eprintln!("  {path}: {why}");
        }
        return Ok(exit::PARTIAL);
    }

    let destination = engine::probe(&roots, &dest, view);
    if destination.exists && !job.overwrite {
        return Err(usage(format!(
            "destination {dest} already exists; pass --overwrite to merge into it"
        )));
    }

    let copied_keys = rebase_subtree(&source_keys, &source, &dest)?;
    let source_file = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys: source_keys,
    };
    let copy_file = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys: copied_keys,
    };
    let delete_file = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys: if job.remove_source {
            vec![KeyBlock {
                path: source.clone(),
                delete: true,
                values: Vec::new(),
                line: 0,
            }]
        } else {
            Vec::new()
        },
    };
    let mut combined = copy_file.clone();
    combined.keys.extend(delete_file.keys.clone());
    enforce_denies(policy, &combined)?;

    let snapshot = undo::snapshot(&roots, &combined, view);
    if !snapshot.is_complete() {
        eprintln!(
            "regx: refusing {verb}; rollback would be incomplete because {} key(s) are unreadable",
            snapshot.unreadable.len()
        );
        return Ok(exit::PARTIAL);
    }
    if let Some(plan_path) = job.save_plan {
        let view_label = match view {
            View::Native => "native",
            View::Bits32 => "32",
            View::Bits64 => "64",
        };
        copy_plan::save(
            plan_path,
            copy_plan::SaveInput {
                operation: verb,
                view_label,
                source_computer: job.source_computer,
                source: &source,
                destination: &dest,
                source_value: None,
                destination_value: None,
                overwrite: job.overwrite,
                source_file: &source_file,
                copy_file: &copy_file,
                delete_file: &delete_file,
                current: &snapshot,
            },
        )
        .map_err(|error| anyhow!(error))?;
        let (plan_bytes, plan_sha256) = sha256::hash_file(plan_path)
            .with_context(|| format!("cannot checksum copy/move plan {}", plan_path.display()))?;
        if cli.global.output == OutputFormat::Json {
            println!(
                "{{\"operation\":{},\"source\":{},\"destination\":{},\"view\":{},\
                 \"sourceComputer\":{},\"plan\":{},\"planBytes\":{},\"planSha256\":{},\
                 \"sourceDigest\":{},\"currentDigest\":{},\"saved\":true}}",
                jstr(verb),
                jstr(&source.to_string()),
                jstr(&dest.to_string()),
                jstr(view_label),
                job.source_computer
                    .map(jstr)
                    .unwrap_or_else(|| "null".into()),
                jstr(&plan_path.display().to_string()),
                plan_bytes,
                jstr(&plan_sha256),
                jstr(&saved_plan::file_digest(&source_file)),
                jstr(&saved_plan::snapshot_digest(&snapshot))
            );
        } else {
            eprintln!(
                "regx: saved digest-bound {verb} preview -> {}",
                plan_path.display()
            );
        }
        return Ok(exit::OK);
    }
    let backup = job
        .backup
        .map(Path::to_path_buf)
        .unwrap_or_else(|| undo::temporary_path(verb));
    if !confirm(
        &cli.global,
        policy,
        &format!(
            "{} {} -> {}{}?",
            if job.remove_source { "Move" } else { "Copy" },
            source,
            dest,
            if job.overwrite {
                " (merge into existing destination)"
            } else {
                ""
            }
        ),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }

    if !cli.global.dry_run {
        let banner = vec![
            format!("regx undo snapshot for {verb}: {source} -> {dest}"),
            "Apply this file to restore both source and destination.".into(),
        ];
        write_reg(&backup, &snapshot.file, None, &banner)?;
        eprintln!("regx: undo snapshot -> {}", backup.display());
    }

    let mut logger = open_audit(cli, policy, &command_line())?;
    let (copied, removed, rollback) = apply_copy_move_atomic(
        &roots,
        &copy_file,
        &delete_file,
        &snapshot,
        view,
        cli.global.dry_run,
        logger.as_mut(),
    );

    if cli.global.output == OutputFormat::Json {
        println!(
            "{{\"operation\": {}, \"source\": {}, \"destination\": {}, \"overwrite\": {}, \
             \"dryRun\": {}, \"backup\": {}, {}, \"copy\": {}, \"removeSource\": {}, \
             \"rolledBack\": {}, \"rollback\": {}}}",
            jstr(verb),
            jstr(&source.to_string()),
            jstr(&dest.to_string()),
            job.overwrite,
            cli.global.dry_run,
            jstr(&backup.display().to_string()),
            backup_evidence_json(&backup, cli.global.dry_run)?,
            apply_report_json(&copied),
            removed
                .as_ref()
                .map(apply_report_json)
                .unwrap_or_else(|| "null".into()),
            rollback.is_some(),
            rollback
                .as_ref()
                .map(apply_report_json)
                .unwrap_or_else(|| "null".into()),
        );
    } else {
        print_apply(cli, &copied);
        if let Some(removed) = &removed {
            print_apply(cli, removed);
        } else if job.remove_source && !copied.failures.is_empty() {
            eprintln!("regx: source preserved because the destination copy was incomplete");
        }
        if let Some(rollback) = &rollback {
            eprintln!("regx: {verb} was partial; automatic rollback result:");
            print_apply(cli, rollback);
        }
    }

    let failed = !copied.failures.is_empty()
        || removed
            .as_ref()
            .is_some_and(|report| !report.failures.is_empty());
    Ok(if failed {
        if rollback
            .as_ref()
            .is_some_and(|report| !report.failures.is_empty())
        {
            exit::PARTIAL
        } else {
            exit::ACCESS_DENIED
        }
    } else {
        exit::OK
    })
}

struct CopyMoveViewReport {
    label: &'static str,
    copied: Option<engine::ApplyReport>,
    removed: Option<engine::ApplyReport>,
    rollback: Option<engine::ApplyReport>,
}

fn cmd_copy_move_both(
    cli: &Cli,
    policy: &policy::Policy,
    job: CopyMoveJob<'_>,
    source: RegPath,
    dest: RegPath,
    verb: &str,
) -> anyhow::Result<i32> {
    let roots = Roots::live();
    let source_roots = roots_for_read(job.source_computer, &source)?;
    let mut files = Vec::with_capacity(2);
    for (label, view) in selected_views(cli.global.view) {
        let (source_keys, source_report) = match engine::export(&source_roots, &source, view, true)
        {
            Ok(result) => result,
            Err(error) => {
                eprintln!("regx: view {label}: {error}");
                return Ok(reg_exit(&error));
            }
        };
        if !source_report.skipped.is_empty() {
            eprintln!(
                "regx: refusing an incomplete {verb} in view {label}; {} source subkey(s) were unreadable:",
                source_report.skipped.len()
            );
            for (path, why) in &source_report.skipped {
                eprintln!("  {path}: {why}");
            }
            return Ok(exit::PARTIAL);
        }
        let destination = engine::probe(&roots, &dest, view);
        if destination.exists && !job.overwrite {
            return Err(usage(format!(
                "destination {dest} already exists in view {label}; pass --overwrite to merge into it"
            )));
        }
        let copy_file = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf16Le,
            keys: rebase_subtree(&source_keys, &source, &dest)?,
        };
        let delete_file = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf16Le,
            keys: if job.remove_source {
                vec![KeyBlock {
                    path: source.clone(),
                    delete: true,
                    values: Vec::new(),
                    line: 0,
                }]
            } else {
                Vec::new()
            },
        };
        let mut combined = copy_file.clone();
        combined.keys.extend(delete_file.keys.clone());
        enforce_denies(policy, &combined)?;
        let source_file = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf16Le,
            keys: source_keys,
        };
        files.push((label, view, combined, source_file, copy_file, delete_file));
    }

    let snapshots = match capture_prepared_view_snapshots(
        &roots,
        files
            .iter()
            .map(|(label, view, combined, _, _, _)| (*label, *view, combined.clone()))
            .collect(),
    ) {
        Ok(snapshots) => snapshots,
        Err(incomplete) => {
            print_incomplete_view_snapshots(&incomplete);
            return Ok(exit::PARTIAL);
        }
    };
    if let Some(plan_base) = job.save_plan {
        let plan_paths = files
            .iter()
            .map(|(label, _, _, _, _, _)| (*label, view_undo_path(plan_base, label, true)))
            .collect::<Vec<_>>();
        if let Some((_, existing)) = plan_paths.iter().find(|(_, path)| path.exists()) {
            return Err(anyhow!(
                "{} already exists; refusing to overwrite a copy/move plan",
                existing.display()
            ));
        }
        let mut saved_paths = Vec::new();
        for (((label, _, _, source_file, copy_file, delete_file), snapshot), (_, plan_path)) in
            files.iter().zip(&snapshots).zip(&plan_paths)
        {
            if let Err(error) = copy_plan::save(
                plan_path,
                copy_plan::SaveInput {
                    operation: verb,
                    view_label: label,
                    source_computer: job.source_computer,
                    source: &source,
                    destination: &dest,
                    source_value: None,
                    destination_value: None,
                    overwrite: job.overwrite,
                    source_file,
                    copy_file,
                    delete_file,
                    current: &snapshot.snapshot,
                },
            ) {
                for saved in &saved_paths {
                    let _ = std::fs::remove_file(saved);
                }
                return Err(anyhow!(error));
            }
            saved_paths.push(plan_path.clone());
        }
        if cli.global.output == OutputFormat::Json {
            let views = plan_paths
                .iter()
                .map(|(label, path)| {
                    let (bytes, digest) = sha256::hash_file(path).with_context(|| {
                        format!("cannot checksum copy/move plan {}", path.display())
                    })?;
                    Ok(format!(
                        "{{\"view\":{},\"plan\":{},\"planBytes\":{},\"planSha256\":{},\
                         \"saved\":true}}",
                        jstr(label),
                        jstr(&path.display().to_string()),
                        bytes,
                        jstr(&digest)
                    ))
                })
                .collect::<anyhow::Result<Vec<_>>>()?
                .join(",");
            println!(
                "{{\"operation\":{},\"source\":{},\"destination\":{},\"views\":[{views}]}}",
                jstr(verb),
                jstr(&source.to_string()),
                jstr(&dest.to_string())
            );
        } else {
            for (label, path) in plan_paths {
                eprintln!(
                    "regx: saved digest-bound {verb} preview (view {label}) -> {}",
                    path.display()
                );
            }
        }
        return Ok(exit::OK);
    }
    let backup_base = job
        .backup
        .map(Path::to_path_buf)
        .unwrap_or_else(|| undo::temporary_path(verb));
    let backup_paths = snapshots
        .iter()
        .map(|snapshot| {
            (
                snapshot.label,
                view_undo_path(&backup_base, snapshot.label, true),
            )
        })
        .collect::<Vec<_>>();
    if !confirm(
        &cli.global,
        policy,
        &format!(
            "{} {} -> {} in both views{}?",
            if job.remove_source { "Move" } else { "Copy" },
            source,
            dest,
            if job.overwrite {
                " (merge into existing destinations)"
            } else {
                ""
            }
        ),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }

    if !cli.global.dry_run {
        for (snapshot, (_, backup_path)) in snapshots.iter().zip(&backup_paths) {
            write_reg(
                backup_path,
                &snapshot.snapshot.file,
                None,
                &[
                    format!(
                        "regx undo snapshot for {verb} (view {}): {source} -> {dest}",
                        snapshot.label
                    ),
                    format!(
                        "Apply this file with --view {} to restore both source and destination.",
                        snapshot.label
                    ),
                ],
            )?;
            eprintln!(
                "regx: undo snapshot (view {}) -> {}",
                snapshot.label,
                backup_path.display()
            );
        }
    }

    let mut logger = open_audit(cli, policy, &command_line())?;
    let mut reports = snapshots
        .iter()
        .map(|snapshot| CopyMoveViewReport {
            label: snapshot.label,
            copied: None,
            removed: None,
            rollback: None,
        })
        .collect::<Vec<_>>();
    for index in 0..files.len() {
        let (_, view, _, _, copy_file, delete_file) = &files[index];
        let (copied, removed, rollback) = apply_copy_move_atomic(
            &roots,
            copy_file,
            delete_file,
            &snapshots[index].snapshot,
            *view,
            cli.global.dry_run,
            logger.as_mut(),
        );
        let failed = !copied.failures.is_empty()
            || removed
                .as_ref()
                .is_some_and(|report| !report.failures.is_empty());
        reports[index].copied = Some(copied);
        reports[index].removed = removed;
        reports[index].rollback = rollback;
        if failed && !cli.global.dry_run {
            for rollback_index in (0..index).rev() {
                reports[rollback_index].rollback = Some(engine::apply_audited(
                    &roots,
                    &snapshots[rollback_index].snapshot.file,
                    snapshots[rollback_index].view,
                    false,
                    logger.as_mut(),
                ));
            }
            break;
        }
    }

    if cli.global.output == OutputFormat::Json {
        let views = reports
            .iter()
            .zip(&backup_paths)
            .map(|(report, (_, backup_path))| {
                Ok(format!(
                    "{{\"view\":{},\"backup\":{}, {},\"copy\":{},\"removeSource\":{},\
                     \"rolledBack\":{},\"rollback\":{}}}",
                    jstr(report.label),
                    jstr(&backup_path.display().to_string()),
                    backup_evidence_json(backup_path, cli.global.dry_run)?,
                    report
                        .copied
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into()),
                    report
                        .removed
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into()),
                    report.rollback.is_some(),
                    report
                        .rollback
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into())
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?
            .join(",");
        println!(
            "{{\"operation\":{},\"source\":{},\"destination\":{},\"overwrite\":{},\
             \"dryRun\":{},\"views\":[{views}]}}",
            jstr(verb),
            jstr(&source.to_string()),
            jstr(&dest.to_string()),
            job.overwrite,
            cli.global.dry_run
        );
    } else {
        for report in &reports {
            eprintln!("regx: view {}", report.label);
            if let Some(copied) = &report.copied {
                print_apply(cli, copied);
            } else {
                eprintln!("regx: not attempted because an earlier view failed");
            }
            if let Some(removed) = &report.removed {
                print_apply(cli, removed);
            }
            if let Some(rollback) = &report.rollback {
                eprintln!("regx: rollback:");
                print_apply(cli, rollback);
            }
        }
    }
    let failed = reports.iter().any(|report| {
        report
            .copied
            .as_ref()
            .is_none_or(|applied| !applied.failures.is_empty())
            || report
                .removed
                .as_ref()
                .is_some_and(|applied| !applied.failures.is_empty())
    });
    let rollback_failed = reports.iter().any(|report| {
        report
            .rollback
            .as_ref()
            .is_some_and(|rollback| !rollback.failures.is_empty())
    });
    Ok(if rollback_failed {
        exit::PARTIAL
    } else if failed {
        exit::ACCESS_DENIED
    } else {
        exit::OK
    })
}

fn apply_copy_move_atomic(
    roots: &Roots,
    copy_file: &RegFile,
    delete_file: &RegFile,
    snapshot: &undo::Snapshot,
    view: View,
    dry_run: bool,
    mut audit: Option<&mut audit::Logger>,
) -> (
    engine::ApplyReport,
    Option<engine::ApplyReport>,
    Option<engine::ApplyReport>,
) {
    let copied = engine::apply_audited(roots, copy_file, view, dry_run, audit.as_deref_mut());
    // Two-phase move: source deletion is forbidden unless every destination
    // write succeeded. This prevents data loss on a partial copy.
    let removed = if !delete_file.keys.is_empty() && copied.failures.is_empty() {
        Some(engine::apply_audited(
            roots,
            delete_file,
            view,
            dry_run,
            audit.as_deref_mut(),
        ))
    } else {
        None
    };
    let failed = !copied.failures.is_empty()
        || removed
            .as_ref()
            .is_some_and(|report| !report.failures.is_empty());
    let touched =
        copied.touched() > 0 || removed.as_ref().is_some_and(|report| report.touched() > 0);
    let rollback = if failed && touched && !dry_run {
        Some(engine::apply_audited(
            roots,
            &snapshot.file,
            view,
            false,
            audit,
        ))
    } else {
        None
    };
    (copied, removed, rollback)
}

fn copy_plan_source_file(
    source_keys: &[KeyBlock],
    artifact: &copy_plan::Artifact,
) -> Result<RegFile, String> {
    let keys = match &artifact.source_value {
        None => source_keys.to_vec(),
        Some(name) => {
            let entry = source_keys
                .first()
                .and_then(|block| {
                    block
                        .values
                        .iter()
                        .find(|entry| value_name_matches(&entry.name, name))
                })
                .cloned()
                .ok_or_else(|| format!("source value {name} no longer exists"))?;
            vec![KeyBlock {
                path: artifact.source.clone(),
                delete: false,
                values: vec![entry],
                line: 0,
            }]
        }
    };
    Ok(RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys,
    })
}

fn rebuild_copy_plan_payload(
    source_file: &RegFile,
    artifact: &copy_plan::Artifact,
) -> anyhow::Result<RegFile> {
    match (&artifact.source_value, &artifact.destination_value) {
        (None, None) => Ok(RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf16Le,
            keys: rebase_subtree(&source_file.keys, &artifact.source, &artifact.destination)?,
        }),
        (Some(_), Some(destination_name)) => {
            let source = source_file
                .keys
                .first()
                .and_then(|block| block.values.first())
                .ok_or_else(|| anyhow!("value copy/move plan has an empty bound source"))?;
            Ok(RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: vec![KeyBlock {
                    path: artifact.destination.clone(),
                    delete: false,
                    values: vec![ValueEntry {
                        name: destination_name.clone(),
                        data: source.data.clone(),
                        line: 0,
                    }],
                    line: 0,
                }],
            })
        }
        _ => Err(anyhow!(
            "copy/move plan has inconsistent source/destination value scope"
        )),
    }
}

fn copy_plan_delete_is_bound(artifact: &copy_plan::Artifact) -> bool {
    if artifact.operation != "move" {
        return artifact.delete_file.keys.is_empty();
    }
    match &artifact.source_value {
        None => {
            artifact.delete_file.keys.len() == 1
                && artifact.delete_file.keys[0].delete
                && artifact.delete_file.keys[0].path.fold() == artifact.source.fold()
                && artifact.delete_file.keys[0].values.is_empty()
        }
        Some(source_name) => {
            artifact.delete_file.keys.len() == 1
                && !artifact.delete_file.keys[0].delete
                && artifact.delete_file.keys[0].path.fold() == artifact.source.fold()
                && artifact.delete_file.keys[0].values.len() == 1
                && value_name_matches(&artifact.delete_file.keys[0].values[0].name, source_name)
                && artifact.delete_file.keys[0].values[0].data == RegData::Delete
        }
    }
}

fn cmd_apply_copy_plan(
    cli: &Cli,
    policy: &policy::Policy,
    plan_path: &Path,
    backup: Option<&Path>,
) -> anyhow::Result<i32> {
    if cli.global.view == cli::View::Both {
        return cmd_apply_copy_plan_both(cli, policy, plan_path, backup);
    }
    let artifact = copy_plan::load(plan_path).map_err(|error| anyhow!(error))?;
    let roots = Roots::live();
    let source_roots = roots_for_read(artifact.source_computer.as_deref(), &artifact.source)?;
    let (source_keys, source_report) = match engine::export(
        &source_roots,
        &artifact.source,
        artifact.view,
        artifact.source_value.is_none(),
    ) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("regx: refusing stale copy/move plan: {error}");
            return Ok(reg_exit(&error));
        }
    };
    if !source_report.skipped.is_empty() {
        eprintln!(
            "regx: refusing stale copy/move plan: {} source subkey(s) are unreadable",
            source_report.skipped.len()
        );
        return Ok(exit::PARTIAL);
    }
    let source_file = match copy_plan_source_file(&source_keys, &artifact) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("regx: refusing stale copy/move plan: {error}");
            return Ok(exit::NOT_FOUND);
        }
    };
    let actual_source = saved_plan::file_digest(&source_file);
    if actual_source != artifact.source_digest {
        eprintln!(
            "regx: refusing stale copy/move plan: source changed \
             (expected {}, found {})",
            artifact.source_digest, actual_source
        );
        return Ok(exit::PARTIAL);
    }
    let rebuilt_copy = rebuild_copy_plan_payload(&source_file, &artifact)?;
    if saved_plan::file_digest(&rebuilt_copy) != saved_plan::file_digest(&artifact.copy_file) {
        return Err(anyhow!(
            "copy/move plan payload is inconsistent with its bound source and destination"
        ));
    }
    if !copy_plan_delete_is_bound(&artifact) {
        return Err(anyhow!(
            "copy/move plan does not contain the exact bound source deletion"
        ));
    }

    let mut combined = artifact.copy_file.clone();
    combined.keys.extend(artifact.delete_file.keys.clone());
    enforce_denies(policy, &combined)?;
    let snapshot = undo::snapshot(&roots, &combined, artifact.view);
    if !snapshot.is_complete() {
        eprintln!(
            "regx: refusing stale copy/move plan: rollback is incomplete for {} target(s)",
            snapshot.unreadable.len()
        );
        return Ok(exit::PARTIAL);
    }
    let actual_current = saved_plan::snapshot_digest(&snapshot);
    if actual_current != artifact.current_digest {
        eprintln!(
            "regx: refusing stale copy/move plan: destination/current state changed \
             (expected {}, found {})",
            artifact.current_digest, actual_current
        );
        return Ok(exit::PARTIAL);
    }

    let undo_path = backup
        .map(Path::to_path_buf)
        .unwrap_or_else(|| undo::default_path(plan_path));
    if !confirm(
        &cli.global,
        policy,
        &format!(
            "Apply verified {} plan {} -> {}?",
            artifact.operation, artifact.source, artifact.destination
        ),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }

    if !cli.global.dry_run {
        write_reg(
            &undo_path,
            &snapshot.file,
            None,
            &[
                format!(
                    "regx undo snapshot for verified {} plan: {}",
                    artifact.operation,
                    plan_path.display()
                ),
                format!(
                    "{} -> {} (view {:?}, overwrite {})",
                    artifact.source, artifact.destination, artifact.view, artifact.overwrite
                ),
            ],
        )?;
        eprintln!("regx: undo snapshot -> {}", undo_path.display());
    }

    let mut logger = open_audit(cli, policy, &command_line())?;
    let (copied, removed, rollback) = apply_copy_move_atomic(
        &roots,
        &artifact.copy_file,
        &artifact.delete_file,
        &snapshot,
        artifact.view,
        cli.global.dry_run,
        logger.as_mut(),
    );
    if cli.global.output == OutputFormat::Json {
        println!(
            "{{\"schema\":{},\"schemaVersion\":2,\"plan\":{},\"operation\":{},\"scope\":{},\
             \"source\":{},\"sourceValue\":{},\"sourceComputer\":{},\
             \"destination\":{},\"destinationValue\":{},\"overwrite\":{},\"dryRun\":{},\
             \"backup\":{}, {},\"copy\":{},\"removeSource\":{},\"rolledBack\":{},\
             \"rollback\":{}}}",
            jstr(copy_plan::RESULT_SCHEMA_URL),
            jstr(&plan_path.display().to_string()),
            jstr(&artifact.operation),
            jstr(if artifact.source_value.is_some() {
                "value"
            } else {
                "subtree"
            }),
            jstr(&artifact.source.to_string()),
            artifact
                .source_value
                .as_ref()
                .map(|name| jstr(engine::value_api_name(name)))
                .unwrap_or_else(|| "null".into()),
            artifact
                .source_computer
                .as_deref()
                .map(jstr)
                .unwrap_or_else(|| "null".into()),
            jstr(&artifact.destination.to_string()),
            artifact
                .destination_value
                .as_ref()
                .map(|name| jstr(engine::value_api_name(name)))
                .unwrap_or_else(|| "null".into()),
            artifact.overwrite,
            cli.global.dry_run,
            if cli.global.dry_run {
                "null".into()
            } else {
                jstr(&undo_path.display().to_string())
            },
            backup_evidence_json(&undo_path, cli.global.dry_run)?,
            apply_report_json(&copied),
            removed
                .as_ref()
                .map(apply_report_json)
                .unwrap_or_else(|| "null".into()),
            rollback.is_some(),
            rollback
                .as_ref()
                .map(apply_report_json)
                .unwrap_or_else(|| "null".into())
        );
    } else {
        print_apply(cli, &copied);
        if let Some(removed) = &removed {
            print_apply(cli, removed);
        }
        if let Some(rollback) = &rollback {
            eprintln!("regx: verified plan failed; automatic rollback result:");
            print_apply(cli, rollback);
        }
    }
    let failed = !copied.failures.is_empty()
        || removed
            .as_ref()
            .is_some_and(|report| !report.failures.is_empty());
    Ok(if !failed {
        exit::OK
    } else if rollback
        .as_ref()
        .is_some_and(|report| !report.failures.is_empty())
    {
        exit::PARTIAL
    } else {
        exit::ACCESS_DENIED
    })
}

fn prepare_copy_plan_view(
    policy: &policy::Policy,
    roots: &Roots,
    plan_path: &Path,
    expected_view: View,
) -> anyhow::Result<Result<(copy_plan::Artifact, undo::Snapshot), i32>> {
    let artifact = copy_plan::load(plan_path).map_err(|error| anyhow!(error))?;
    if artifact.view != expected_view {
        return Err(anyhow!(
            "{} contains view {:?}, expected {:?}",
            plan_path.display(),
            artifact.view,
            expected_view
        ));
    }
    let source_roots = roots_for_read(artifact.source_computer.as_deref(), &artifact.source)?;
    let (source_keys, source_report) = match engine::export(
        &source_roots,
        &artifact.source,
        artifact.view,
        artifact.source_value.is_none(),
    ) {
        Ok(result) => result,
        Err(error) => {
            eprintln!(
                "regx: refusing stale copy/move plan {}: {error}",
                plan_path.display()
            );
            return Ok(Err(reg_exit(&error)));
        }
    };
    if !source_report.skipped.is_empty() {
        eprintln!(
            "regx: refusing stale copy/move plan {}: {} source subkey(s) are unreadable",
            plan_path.display(),
            source_report.skipped.len()
        );
        return Ok(Err(exit::PARTIAL));
    }
    let source_file = match copy_plan_source_file(&source_keys, &artifact) {
        Ok(file) => file,
        Err(error) => {
            eprintln!(
                "regx: refusing stale copy/move plan {}: {error}",
                plan_path.display()
            );
            return Ok(Err(exit::NOT_FOUND));
        }
    };
    let actual_source = saved_plan::file_digest(&source_file);
    if actual_source != artifact.source_digest {
        eprintln!(
            "regx: refusing stale copy/move plan {}: source changed \
             (expected {}, found {})",
            plan_path.display(),
            artifact.source_digest,
            actual_source
        );
        return Ok(Err(exit::PARTIAL));
    }
    let rebuilt_copy = rebuild_copy_plan_payload(&source_file, &artifact)?;
    if saved_plan::file_digest(&rebuilt_copy) != saved_plan::file_digest(&artifact.copy_file) {
        return Err(anyhow!(
            "copy/move plan {} payload is inconsistent with its bound source and destination",
            plan_path.display()
        ));
    }
    if !copy_plan_delete_is_bound(&artifact) {
        return Err(anyhow!(
            "copy/move plan {} does not contain the exact bound source deletion",
            plan_path.display()
        ));
    }
    let mut combined = artifact.copy_file.clone();
    combined.keys.extend(artifact.delete_file.keys.clone());
    enforce_denies(policy, &combined)?;
    let snapshot = undo::snapshot(roots, &combined, artifact.view);
    if !snapshot.is_complete() {
        eprintln!(
            "regx: refusing stale copy/move plan {}: rollback is incomplete for {} target(s)",
            plan_path.display(),
            snapshot.unreadable.len()
        );
        return Ok(Err(exit::PARTIAL));
    }
    let actual_current = saved_plan::snapshot_digest(&snapshot);
    if actual_current != artifact.current_digest {
        eprintln!(
            "regx: refusing stale copy/move plan {}: destination/current state changed \
             (expected {}, found {})",
            plan_path.display(),
            artifact.current_digest,
            actual_current
        );
        return Ok(Err(exit::PARTIAL));
    }
    Ok(Ok((artifact, snapshot)))
}

fn cmd_apply_copy_plan_both(
    cli: &Cli,
    policy: &policy::Policy,
    plan_base: &Path,
    backup: Option<&Path>,
) -> anyhow::Result<i32> {
    let roots = Roots::live();
    let plan_paths = [
        ("32", View::Bits32, view_undo_path(plan_base, "32", true)),
        ("64", View::Bits64, view_undo_path(plan_base, "64", true)),
    ];
    let mut prepared = Vec::with_capacity(2);
    for (label, view, path) in &plan_paths {
        let (artifact, snapshot) = match prepare_copy_plan_view(policy, &roots, path, *view)? {
            Ok(prepared) => prepared,
            Err(code) => return Ok(code),
        };
        prepared.push((*label, path.clone(), artifact, snapshot));
    }
    let first = &prepared[0].2;
    let second = &prepared[1].2;
    if first.operation != second.operation
        || first.source != second.source
        || first.destination != second.destination
        || first.source_value != second.source_value
        || first.destination_value != second.destination_value
        || first.overwrite != second.overwrite
        || first.source_computer != second.source_computer
    {
        return Err(anyhow!(
            "paired copy/move plans do not describe the same operation"
        ));
    }

    let undo_base = backup
        .map(Path::to_path_buf)
        .unwrap_or_else(|| undo::default_path(plan_base));
    let undo_paths = prepared
        .iter()
        .map(|(label, _, _, _)| (*label, view_undo_path(&undo_base, label, true)))
        .collect::<Vec<_>>();
    if !confirm(
        &cli.global,
        policy,
        &format!(
            "Apply verified {} plan {} -> {} in both views?",
            first.operation, first.source, first.destination
        ),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }

    if !cli.global.dry_run {
        for ((label, plan_path, artifact, snapshot), (_, undo_path)) in
            prepared.iter().zip(&undo_paths)
        {
            write_reg(
                undo_path,
                &snapshot.file,
                None,
                &[
                    format!(
                        "regx undo snapshot for verified {} plan (view {label}): {}",
                        artifact.operation,
                        plan_path.display()
                    ),
                    format!(
                        "{} -> {} (overwrite {})",
                        artifact.source, artifact.destination, artifact.overwrite
                    ),
                ],
            )?;
            eprintln!(
                "regx: undo snapshot (view {label}) -> {}",
                undo_path.display()
            );
        }
    }

    let mut logger = open_audit(cli, policy, &command_line())?;
    let mut reports = prepared
        .iter()
        .map(|(label, _, _, _)| CopyMoveViewReport {
            label,
            copied: None,
            removed: None,
            rollback: None,
        })
        .collect::<Vec<_>>();
    for index in 0..prepared.len() {
        let (_, _, artifact, snapshot) = &prepared[index];
        let (copied, removed, rollback) = apply_copy_move_atomic(
            &roots,
            &artifact.copy_file,
            &artifact.delete_file,
            snapshot,
            artifact.view,
            cli.global.dry_run,
            logger.as_mut(),
        );
        let failed = !copied.failures.is_empty()
            || removed
                .as_ref()
                .is_some_and(|report| !report.failures.is_empty());
        reports[index].copied = Some(copied);
        reports[index].removed = removed;
        reports[index].rollback = rollback;
        if failed && !cli.global.dry_run {
            for rollback_index in (0..index).rev() {
                let (_, _, artifact, snapshot) = &prepared[rollback_index];
                reports[rollback_index].rollback = Some(engine::apply_audited(
                    &roots,
                    &snapshot.file,
                    artifact.view,
                    false,
                    logger.as_mut(),
                ));
            }
            break;
        }
    }

    if cli.global.output == OutputFormat::Json {
        let views = reports
            .iter()
            .zip(&prepared)
            .zip(&undo_paths)
            .map(|((report, (_, plan, _, _)), (_, undo))| {
                Ok(format!(
                    "{{\"view\":{},\"plan\":{},\"backup\":{}, {},\"copy\":{},\
                     \"removeSource\":{},\"rolledBack\":{},\"rollback\":{}}}",
                    jstr(report.label),
                    jstr(&plan.display().to_string()),
                    if cli.global.dry_run {
                        "null".into()
                    } else {
                        jstr(&undo.display().to_string())
                    },
                    backup_evidence_json(undo, cli.global.dry_run)?,
                    report
                        .copied
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into()),
                    report
                        .removed
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into()),
                    report.rollback.is_some(),
                    report
                        .rollback
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into())
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?
            .join(",");
        println!(
            "{{\"schema\":{},\"schemaVersion\":2,\"plan\":{},\"operation\":{},\"scope\":{},\
             \"source\":{},\"sourceValue\":{},\"sourceComputer\":{},\
             \"destination\":{},\"destinationValue\":{},\"overwrite\":{},\
             \"dryRun\":{},\"views\":[{views}]}}",
            jstr(copy_plan::RESULT_SCHEMA_URL),
            jstr(&plan_base.display().to_string()),
            jstr(&first.operation),
            jstr(if first.source_value.is_some() {
                "value"
            } else {
                "subtree"
            }),
            jstr(&first.source.to_string()),
            first
                .source_value
                .as_ref()
                .map(|name| jstr(engine::value_api_name(name)))
                .unwrap_or_else(|| "null".into()),
            first
                .source_computer
                .as_deref()
                .map(jstr)
                .unwrap_or_else(|| "null".into()),
            jstr(&first.destination.to_string()),
            first
                .destination_value
                .as_ref()
                .map(|name| jstr(engine::value_api_name(name)))
                .unwrap_or_else(|| "null".into()),
            first.overwrite,
            cli.global.dry_run
        );
    } else {
        for report in &reports {
            eprintln!("regx: view {}", report.label);
            if let Some(copied) = &report.copied {
                print_apply(cli, copied);
            } else {
                eprintln!("regx: not attempted because an earlier view failed");
            }
            if let Some(removed) = &report.removed {
                print_apply(cli, removed);
            }
            if let Some(rollback) = &report.rollback {
                eprintln!("regx: rollback:");
                print_apply(cli, rollback);
            }
        }
    }
    let failed = reports.iter().any(|report| {
        report
            .copied
            .as_ref()
            .is_none_or(|applied| !applied.failures.is_empty())
            || report
                .removed
                .as_ref()
                .is_some_and(|applied| !applied.failures.is_empty())
    });
    let rollback_failed = reports.iter().any(|report| {
        report
            .rollback
            .as_ref()
            .is_some_and(|rollback| !rollback.failures.is_empty())
    });
    Ok(if rollback_failed {
        exit::PARTIAL
    } else if failed {
        exit::ACCESS_DENIED
    } else {
        exit::OK
    })
}

fn path_is_within(candidate: &RegPath, parent: &RegPath) -> bool {
    if candidate.hive != parent.hive {
        return false;
    }
    let candidate = model::fold_str(&candidate.sub);
    let parent = model::fold_str(&parent.sub);
    if parent.is_empty() {
        return !candidate.is_empty();
    }
    candidate.starts_with(&format!("{parent}\\"))
}

fn rebase_subtree(
    keys: &[KeyBlock],
    source: &RegPath,
    dest: &RegPath,
) -> anyhow::Result<Vec<KeyBlock>> {
    let source_fold = model::fold_str(&source.sub);
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        if key.path.hive != source.hive {
            return Err(anyhow!(
                "cannot rebase {} below source {} because the registry hives differ",
                key.path,
                source
            ));
        }
        let key_fold = model::fold_str(&key.path.sub);
        let relative = if source_fold.is_empty() {
            key.path.sub.as_str()
        } else if key_fold == source_fold {
            ""
        } else if key_fold.starts_with(&format!("{source_fold}\\")) {
            let source_parts = source.sub.split('\\').count();
            let relative_start = key
                .path
                .sub
                .match_indices('\\')
                .nth(source_parts - 1)
                .map(|(index, _)| index + 1)
                .ok_or_else(|| {
                    anyhow!(
                        "cannot derive relative path for {} below requested source {}",
                        key.path,
                        source
                    )
                })?;
            &key.path.sub[relative_start..]
        } else {
            return Err(anyhow!(
                "export returned {} outside requested source {}",
                key.path,
                source
            ));
        };
        let mut rebased = key.clone();
        rebased.path = RegPath {
            hive: dest.hive,
            sub: if relative.is_empty() {
                dest.sub.clone()
            } else if dest.sub.is_empty() {
                relative.to_string()
            } else {
                format!("{}\\{relative}", dest.sub)
            },
        };
        out.push(rebased);
    }
    Ok(out)
}

fn apply_report_json(report: &engine::ApplyReport) -> String {
    let failures = report
        .failures
        .iter()
        .map(|(target, problem)| {
            format!(
                "{{\"target\": {}, \"problem\": {}}}",
                jstr(target),
                jstr(problem)
            )
        })
        .collect::<Vec<_>>();
    format!(
        "{{\"keysCreated\": {}, \"keysDeleted\": {}, \"valuesSet\": {}, \
         \"valuesDeleted\": {}, \"failures\": [{}]}}",
        report.keys_created,
        report.keys_deleted,
        report.values_set,
        report.values_deleted,
        failures.join(", ")
    )
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

fn write_registry_data_file(path: &Path, file: &RegFile, to: DataFormat) -> anyhow::Result<()> {
    match to {
        DataFormat::Reg => write_reg(path, file, None, &[]),
        DataFormat::Json => file_io::atomic_write(path, writer::to_json(file).as_bytes())
            .with_context(|| format!("cannot write {}", path.display())),
        DataFormat::Csv => file_io::atomic_write(path, writer::to_csv(file).as_bytes())
            .with_context(|| format!("cannot write {}", path.display())),
        DataFormat::Pol => {
            let (bytes, _) = formats::pol::write(file).map_err(|error| anyhow!(error))?;
            file_io::atomic_write(path, &bytes)
                .with_context(|| format!("cannot write {}", path.display()))
        }
    }
}

fn data_format_name(format: DataFormat) -> &'static str {
    match format {
        DataFormat::Reg => "reg",
        DataFormat::Json => "json",
        DataFormat::Csv => "csv",
        DataFormat::Pol => "pol",
    }
}

fn validate_registry_data_format(file: &RegFile, to: DataFormat) -> anyhow::Result<()> {
    match to {
        DataFormat::Reg => writer::validate_reg_names(file).map_err(|error| anyhow!(error)),
        DataFormat::Json | DataFormat::Csv => Ok(()),
        DataFormat::Pol => formats::pol::write(file)
            .map(|_| ())
            .map_err(|error| anyhow!(error)),
    }
}

fn stream_registry_data(file: &RegFile, to: DataFormat) -> anyhow::Result<()> {
    match to {
        DataFormat::Reg => {
            writer::validate_reg_names(file).map_err(|error| anyhow!(error))?;
            print!("{}", writer::to_string(file));
        }
        DataFormat::Json => print!("{}", writer::to_json(file)),
        DataFormat::Csv => print!("{}", writer::to_csv(file)),
        DataFormat::Pol => {
            let (bytes, _) = formats::pol::write(file).map_err(|error| anyhow!(error))?;
            std::io::stdout()
                .lock()
                .write_all(&bytes)
                .context("cannot write Registry.pol output to stdout")?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ExportFormatOptions {
    to: DataFormat,
    reg4: bool,
}

struct ExportOptions<'a> {
    format: ExportFormatOptions,
    root_as: Option<&'a str>,
    recursive: bool,
    keys: &'a cli::KeyFilterOpts,
    values: &'a cli::ValueFilterOpts,
}

fn cmd_export(
    cli: &Cli,
    key: &str,
    computer: Option<&str>,
    out: Option<&Path>,
    options: ExportOptions<'_>,
) -> anyhow::Result<i32> {
    let ExportOptions {
        format,
        root_as,
        recursive,
        keys: key_filters,
        values,
    } = options;
    let ExportFormatOptions { to, reg4 } = format;
    if reg4 && to != DataFormat::Reg {
        return Err(usage("--reg4 can only be used with --to reg"));
    }
    if cli.global.output == OutputFormat::Json
        && out.is_none()
        && !matches!(to, DataFormat::Reg | DataFormat::Json)
    {
        return Err(usage(
            "`export --output json` owns stdout; use --out for --to csv/pol",
        ));
    }
    let path = parse_key(key)?;
    let destination_root = root_as
        .map(|root| {
            RegPath::parse(root).ok_or_else(|| {
                usage(format!(
                    "--root-as {root:?} is not an absolute registry key"
                ))
            })
        })
        .transpose()?;
    let roots = roots_for_read(computer, &path)?;
    if cli.global.view == cli::View::Both {
        return cmd_export_both(
            cli,
            ExportBothSource {
                roots: &roots,
                path: &path,
                computer,
            },
            out,
            ExportBothOptions {
                format,
                root_as: destination_root.as_ref(),
                recursive,
                key_filters,
                values,
            },
        );
    }
    let (keys, report) = match engine::export(&roots, &path, view_of(&cli.global), recursive) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("regx: {e}");
            return Ok(reg_exit(&e));
        }
    };

    let mut file = RegFile {
        format: if reg4 { RegFormat::V4 } else { RegFormat::V5 },
        encoding: encoding::SourceEncoding::Utf16Le,
        keys,
    };
    if let Some(destination) = &destination_root {
        file.keys = rebase_subtree(&file.keys, &path, destination)?;
    }
    let key_filter = filter_key_paths(&mut file, key_filters)?;
    let value_filter = filter_value_names(&mut file, values)?;

    for (p, e) in &report.skipped {
        eprintln!("  skipped {p}: {e}");
    }
    if let Some(selection) = &value_filter {
        eprintln!(
            "regx: value selection kept {}, omitted {} value(s) and {} empty key(s)",
            selection.selected, selection.omitted, selection.key_operations_omitted
        );
        if file.keys.is_empty() {
            eprintln!("regx: no registry values matched the selection");
            return Ok(if report.skipped.is_empty() {
                exit::NOT_FOUND
            } else {
                exit::PARTIAL
            });
        }
    }
    if key_filter && file.keys.is_empty() {
        eprintln!("regx: no registry keys matched the selection");
        return Ok(if report.skipped.is_empty() {
            exit::NOT_FOUND
        } else {
            exit::PARTIAL
        });
    }
    let output_keys = file.keys.len();
    let output_values = file.keys.iter().map(|key| key.values.len()).sum::<usize>();
    if cli.global.output == OutputFormat::Json {
        if let Some(p) = out {
            if !cli.global.dry_run {
                write_registry_data_file(p, &file, to)?;
            }
            println!(
                "{{\"source\":{},\"computer\":{},\"rootAs\":{},\"format\":{},\"recursive\":{},\
                 \"include\":[{}],\"exclude\":[{}],\"includeValues\":[{}],\"excludeValues\":[{}],\
                 \"file\":{},\"dryRun\":{},\
                 \"keys\":{},\"values\":{},\"skipped\":{}, {}}}",
                jstr(&path.to_string()),
                computer.map(jstr).unwrap_or_else(|| "null".into()),
                destination_root
                    .as_ref()
                    .map(|root| jstr(&root.to_string()))
                    .unwrap_or_else(|| "null".into()),
                jstr(data_format_name(to)),
                recursive,
                key_filters
                    .include_keys
                    .iter()
                    .map(|pattern| jstr(pattern))
                    .collect::<Vec<_>>()
                    .join(","),
                key_filters
                    .exclude_keys
                    .iter()
                    .map(|pattern| jstr(pattern))
                    .collect::<Vec<_>>()
                    .join(","),
                values
                    .include
                    .iter()
                    .map(|pattern| jstr(pattern))
                    .collect::<Vec<_>>()
                    .join(","),
                values
                    .exclude
                    .iter()
                    .map(|pattern| jstr(pattern))
                    .collect::<Vec<_>>()
                    .join(","),
                jstr(&p.display().to_string()),
                cli.global.dry_run,
                output_keys,
                output_values,
                report.skipped.len(),
                artifact_evidence_json(p, cli.global.dry_run)?
            );
        } else {
            print!("{}", writer::to_json(&file));
        }
        return Ok(if report.skipped.is_empty() {
            exit::OK
        } else {
            exit::PARTIAL
        });
    }
    match out {
        Some(p) if !cli.global.dry_run => {
            write_registry_data_file(p, &file, to)?;
            eprintln!(
                "regx: exported {} key(s), {} value(s) as {:?} -> {}{}",
                output_keys,
                output_values,
                to,
                p.display(),
                if report.skipped.is_empty() {
                    String::new()
                } else {
                    format!(" ({} subkey(s) skipped)", report.skipped.len())
                }
            );
        }
        _ => stream_registry_data(&file, to)?,
    }
    Ok(if report.skipped.is_empty() {
        exit::OK
    } else {
        exit::PARTIAL
    })
}

struct ExportBothSource<'a> {
    roots: &'a Roots,
    path: &'a RegPath,
    computer: Option<&'a str>,
}

struct ExportBothOptions<'a> {
    format: ExportFormatOptions,
    root_as: Option<&'a RegPath>,
    recursive: bool,
    key_filters: &'a cli::KeyFilterOpts,
    values: &'a cli::ValueFilterOpts,
}

fn cmd_export_both(
    cli: &Cli,
    source: ExportBothSource<'_>,
    out: Option<&Path>,
    options: ExportBothOptions<'_>,
) -> anyhow::Result<i32> {
    let ExportBothOptions {
        format,
        root_as,
        recursive,
        key_filters,
        values,
    } = options;
    let ExportFormatOptions { to, reg4 } = format;
    if out.is_none() && cli.global.output != OutputFormat::Json {
        eprintln!(
            "regx: `export --view both` needs --out for separate .32/.64 files, \
             or `--output json` for one structured document"
        );
        return Ok(exit::USAGE);
    }

    struct ExportedView {
        label: &'static str,
        file: RegFile,
        report: engine::ExportReport,
        destination: Option<PathBuf>,
    }

    let mut exported = Vec::new();
    let mut failures = Vec::new();
    let mut no_matches = 0usize;
    for (label, view) in [("32", View::Bits32), ("64", View::Bits64)] {
        let (keys, report) = match engine::export(source.roots, source.path, view, recursive) {
            Ok(result) => result,
            Err(error) => {
                failures.push((label, error.to_string()));
                continue;
            }
        };
        let mut file = RegFile {
            format: if reg4 { RegFormat::V4 } else { RegFormat::V5 },
            encoding: encoding::SourceEncoding::Utf16Le,
            keys,
        };
        if let Some(destination) = root_as {
            file.keys = rebase_subtree(&file.keys, source.path, destination)?;
        }
        filter_key_paths(&mut file, key_filters)?;
        filter_value_names(&mut file, values)?;
        if file.keys.is_empty() {
            no_matches += 1;
        }
        let destination = out.map(|base| view_undo_path(base, label, true));
        if let Some(destination) = &destination {
            if !cli.global.dry_run && !file.keys.is_empty() {
                write_registry_data_file(destination, &file, to)?;
            }
        }
        exported.push(ExportedView {
            label,
            file,
            report,
            destination,
        });
    }

    if cli.global.output == OutputFormat::Json {
        let views = exported
            .iter()
            .map(|view| {
                let destination = view
                    .destination
                    .as_ref()
                    .map(|path| jstr(&path.display().to_string()))
                    .unwrap_or_else(|| "null".into());
                let data = if out.is_none() {
                    writer::to_json(&view.file)
                } else {
                    "null".into()
                };
                let no_artifact =
                    cli.global.dry_run || view.destination.is_none() || view.file.keys.is_empty();
                Ok(format!(
                    "{{\"view\":{},\"file\":{},\"dryRun\":{},\"keys\":{},\"values\":{},\
                     \"skipped\":{},\"data\":{}, {}}}",
                    jstr(view.label),
                    destination,
                    cli.global.dry_run,
                    view.file.keys.len(),
                    view.file
                        .keys
                        .iter()
                        .map(|key| key.values.len())
                        .sum::<usize>(),
                    view.report.skipped.len(),
                    data,
                    match view.destination.as_deref() {
                        Some(path) => artifact_evidence_json(path, no_artifact)?,
                        None => "\"bytes\":null,\"sha256\":null".into(),
                    }
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let failures = failures
            .iter()
            .map(|(view, error)| format!("{{\"view\":{},\"problem\":{}}}", jstr(view), jstr(error)))
            .collect::<Vec<_>>();
        println!(
            "{{\"source\":{},\"computer\":{},\"rootAs\":{},\"format\":{},\"recursive\":{},\
             \"include\":[{}],\"exclude\":[{}],\"includeValues\":[{}],\"excludeValues\":[{}],\
             \"views\":[{}],\"failures\":[{}]}}",
            jstr(&source.path.to_string()),
            source.computer.map(jstr).unwrap_or_else(|| "null".into()),
            root_as
                .map(|root| jstr(&root.to_string()))
                .unwrap_or_else(|| "null".into()),
            jstr(data_format_name(to)),
            recursive,
            key_filters
                .include_keys
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            key_filters
                .exclude_keys
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            values
                .include
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            values
                .exclude
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            views.join(","),
            failures.join(",")
        );
    } else {
        for view in &exported {
            if let Some(destination) = &view.destination {
                eprintln!(
                    "regx: view {} {}exported {} key(s), {} value(s) -> {}",
                    view.label,
                    if cli.global.dry_run {
                        "would have "
                    } else {
                        ""
                    },
                    view.file.keys.len(),
                    view.file
                        .keys
                        .iter()
                        .map(|key| key.values.len())
                        .sum::<usize>(),
                    destination.display()
                );
            }
        }
        for (view, error) in &failures {
            eprintln!("regx: view {view} failed: {error}");
        }
    }

    Ok(if exported.is_empty() {
        exit::NOT_FOUND
    } else if !failures.is_empty() || exported.iter().any(|view| !view.report.skipped.is_empty()) {
        exit::PARTIAL
    } else if no_matches == exported.len() {
        exit::NOT_FOUND
    } else {
        exit::OK
    })
}

fn cmd_query(
    cli: &Cli,
    key: &str,
    computer: Option<&str>,
    value: Option<&str>,
    recursive: bool,
) -> anyhow::Result<i32> {
    let path = parse_key(key)?;
    let roots = roots_for_read(computer, &path)?;
    let remote_label = computer.map(|name| {
        format!(
            r"\\{}\{}",
            name.trim().trim_start_matches('\\'),
            path.hive.long_name()
        )
    });
    let display_path = |p: &RegPath| match remote_label.as_deref() {
        None => p.to_string(),
        Some(root) if p.sub.is_empty() => root.to_string(),
        Some(root) => format!("{root}\\{}", p.sub),
    };
    if cli.global.view == cli::View::Both {
        let mut views = Vec::new();
        let mut failures = Vec::new();
        for (label, view) in [("32", View::Bits32), ("64", View::Bits64)] {
            match query_view(&roots, &path, value, recursive, view) {
                Ok((keys, report)) => views.push((label, keys, report)),
                Err(error) => failures.push((label, error)),
            }
        }
        if cli.global.output == OutputFormat::Json {
            let rendered = views
                .iter()
                .map(|(label, keys, report)| {
                    format!(
                        "{{\"view\":{},\"keys\":{},\"incomplete\":{}}}",
                        jstr(label),
                        json_of(keys, &display_path),
                        !report.skipped.is_empty()
                    )
                })
                .collect::<Vec<_>>();
            let errors = failures
                .iter()
                .map(|(label, error)| {
                    format!(
                        "{{\"view\":{},\"error\":{}}}",
                        jstr(label),
                        jstr(&error.to_string())
                    )
                })
                .collect::<Vec<_>>();
            println!(
                "{{\"path\":{},\"views\":[{}],\"failures\":[{}]}}",
                jstr(&display_path(&path)),
                rendered.join(","),
                errors.join(",")
            );
        } else {
            for (label, keys, report) in &views {
                println!("view {label}");
                render_query_text(keys, report, &display_path);
            }
            for (label, error) in &failures {
                eprintln!("view {label} failed: {error}");
            }
        }
        let incomplete = views
            .iter()
            .any(|(_, _, report)| !report.skipped.is_empty());
        let found = views
            .iter()
            .any(|(_, keys, _)| query_has_values(keys, value));
        return Ok(if views.is_empty() {
            failures
                .first()
                .map(|(_, error)| reg_exit(error))
                .unwrap_or(exit::NOT_FOUND)
        } else if !failures.is_empty() || incomplete {
            exit::PARTIAL
        } else if value.is_some() && !found {
            exit::NOT_FOUND
        } else {
            exit::OK
        });
    }
    print_query(
        cli,
        &roots,
        &path,
        value,
        recursive,
        remote_label.as_deref(),
    )
}

fn cmd_ls(
    cli: &Cli,
    key: &str,
    computer: Option<&str>,
    recursive: bool,
    key_filters: &cli::KeyFilterOpts,
    limit: usize,
) -> anyhow::Result<i32> {
    let path = parse_key(key)?;
    let roots = roots_for_read(computer, &path)?;
    let remote_root = computer.map(|name| {
        format!(
            r"\\{}\{}",
            name.trim().trim_start_matches('\\'),
            path.hive.long_name()
        )
    });
    let display_path = |item: &RegPath| match remote_root.as_deref() {
        None => item.to_string(),
        Some(root) if item.sub.is_empty() => root.to_string(),
        Some(root) => format!("{root}\\{}", item.sub),
    };

    let mut views = Vec::new();
    let mut failures = Vec::new();
    let filters =
        search::Filters::compile_globs(&key_filters.include_keys, &key_filters.exclude_keys, false)
            .map_err(usage)?;
    for (label, view) in selected_views(cli.global.view) {
        match engine::list(&roots, &path, view, recursive, limit, |candidate| {
            filters.allows(&candidate.to_string())
        }) {
            Ok((keys, report)) => views.push((label, keys, report)),
            Err(error) => failures.push((label, error)),
        }
    }

    if cli.global.output == OutputFormat::Json {
        let rendered = views
            .iter()
            .map(|(label, keys, report)| {
                let keys = keys
                    .iter()
                    .map(|key| jstr(&display_path(key)))
                    .collect::<Vec<_>>();
                let skipped = report
                    .skipped
                    .iter()
                    .map(|(skipped_path, problem)| {
                        format!(
                            "{{\"path\":{},\"problem\":{}}}",
                            jstr(skipped_path),
                            jstr(problem)
                        )
                    })
                    .collect::<Vec<_>>();
                format!(
                    "{{\"view\":{},\"keys\":[{}],\"skipped\":[{}],\"truncated\":{}}}",
                    jstr(label),
                    keys.join(","),
                    skipped.join(","),
                    report.truncated
                )
            })
            .collect::<Vec<_>>();
        let errors = failures
            .iter()
            .map(|(label, error)| {
                format!(
                    "{{\"view\":{},\"error\":{}}}",
                    jstr(label),
                    jstr(&error.to_string())
                )
            })
            .collect::<Vec<_>>();
        println!(
            "{{\"path\":{},\"computer\":{},\"recursive\":{},\"include\":[{}],\"exclude\":[{}],\
             \"limit\":{},\"views\":[{}],\"failures\":[{}]}}",
            jstr(&display_path(&path)),
            computer.map(jstr).unwrap_or_else(|| "null".into()),
            recursive,
            key_filters
                .include_keys
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            key_filters
                .exclude_keys
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            limit,
            rendered.join(","),
            errors.join(",")
        );
    } else {
        let show_view = cli.global.view == cli::View::Both;
        for (label, keys, report) in &views {
            if show_view {
                println!("view {label}");
            }
            for key in keys {
                println!("{}", display_path(key));
            }
            for (skipped_path, problem) in &report.skipped {
                eprintln!("  skipped {skipped_path}: {problem}");
            }
            if report.truncated {
                eprintln!("regx: view {label}: result truncated at {limit} matching key(s)");
            }
        }
        for (label, error) in &failures {
            eprintln!("view {label} failed: {error}");
        }
    }

    let incomplete = views
        .iter()
        .any(|(_, _, report)| !report.skipped.is_empty());
    Ok(if views.is_empty() {
        failures
            .first()
            .map(|(_, error)| reg_exit(error))
            .unwrap_or(exit::NOT_FOUND)
    } else if !failures.is_empty() || incomplete {
        exit::PARTIAL
    } else {
        exit::OK
    })
}

#[derive(Default)]
struct RegistryStats {
    keys: usize,
    values: usize,
    key_deletes: usize,
    value_deletes: usize,
    max_depth: usize,
    payload_bytes: usize,
    types: BTreeMap<String, usize>,
}

fn registry_stats(keys: Vec<KeyBlock>, base: Option<&RegPath>) -> (RegistryStats, usize) {
    let (keys, report) = coalesce::coalesce(keys);
    let mut stats = RegistryStats::default();
    let base_depth = base.map_or(0, |path| {
        path.sub.split('\\').filter(|p| !p.is_empty()).count()
    });
    for block in keys {
        let absolute_depth = block
            .path
            .sub
            .split('\\')
            .filter(|part| !part.is_empty())
            .count();
        stats.max_depth = stats
            .max_depth
            .max(absolute_depth.saturating_sub(base_depth));
        if block.delete {
            stats.key_deletes += 1;
            continue;
        }
        stats.keys += 1;
        for value in block.values {
            if matches!(value.data, RegData::Delete) {
                stats.value_deletes += 1;
                continue;
            }
            stats.values += 1;
            *stats
                .types
                .entry(value.data.type_name().to_string())
                .or_default() += 1;
            if let Some((_, raw)) = value::data_to_raw(&value.data) {
                stats.payload_bytes += raw.len();
            }
        }
    }
    (stats, report.conflicts.len())
}

fn stats_json(stats: &RegistryStats) -> String {
    let types = stats
        .types
        .iter()
        .map(|(name, count)| format!("{}:{count}", jstr(name)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "\"keys\":{},\"values\":{},\"keyDeletes\":{},\"valueDeletes\":{},\
         \"maxDepth\":{},\"payloadBytes\":{},\"types\":{{{types}}}",
        stats.keys,
        stats.values,
        stats.key_deletes,
        stats.value_deletes,
        stats.max_depth,
        stats.payload_bytes
    )
}

fn print_stats(stats: &RegistryStats, conflicts: usize, incomplete: bool) {
    println!("keys          {}", stats.keys);
    println!("values        {}", stats.values);
    println!("key deletes   {}", stats.key_deletes);
    println!("value deletes {}", stats.value_deletes);
    println!("max depth     {}", stats.max_depth);
    println!("payload bytes {}", stats.payload_bytes);
    println!("conflicts     {conflicts}");
    println!("incomplete    {incomplete}");
    for (name, count) in &stats.types {
        println!("type {name:<20} {count}");
    }
}

fn cmd_stats(
    cli: &Cli,
    source: &str,
    computer: Option<&str>,
    root_as: Option<&str>,
    key_filters: &cli::KeyFilterOpts,
    value_filters: &cli::ValueFilterOpts,
    input: &cli::InputOpts,
) -> anyhow::Result<i32> {
    if let Some(path) = RegPath::parse(source) {
        let destination_root = root_as
            .map(|root| {
                RegPath::parse(root).ok_or_else(|| {
                    usage(format!(
                        "--root-as {root:?} is not an absolute registry key"
                    ))
                })
            })
            .transpose()?;
        let roots = roots_for_read(computer, &path)?;
        let mut views = Vec::new();
        let mut failures = Vec::new();
        for (label, view) in selected_views(cli.global.view) {
            match engine::export(&roots, &path, view, true) {
                Ok((mut keys, report)) => {
                    if let Some(destination) = &destination_root {
                        keys = rebase_subtree(&keys, &path, destination)?;
                    }
                    let selection = fingerprint_selection(keys, key_filters, value_filters, false)?;
                    let stats_base = destination_root.as_ref().unwrap_or(&path);
                    let (stats, conflicts) = registry_stats(selection.keys, Some(stats_base));
                    views.push((label, stats, conflicts, report.skipped, selection.matched));
                }
                Err(error) => failures.push((label, error)),
            }
        }
        if cli.global.output == OutputFormat::Json {
            println!(
                "{{\"source\":{},\"computer\":{},\"rootAs\":{},\"include\":[{}],\"exclude\":[{}],\
                 \"includeValues\":[{}],\"excludeValues\":[{}],\"views\":[{}],\"failures\":[{}]}}",
                jstr(source),
                computer.map(jstr).unwrap_or_else(|| "null".into()),
                destination_root
                    .as_ref()
                    .map(|root| jstr(&root.to_string()))
                    .unwrap_or_else(|| "null".into()),
                json_strings(&key_filters.include_keys),
                json_strings(&key_filters.exclude_keys),
                json_strings(&value_filters.include),
                json_strings(&value_filters.exclude),
                views
                    .iter()
                    .map(|(label, stats, conflicts, skipped, matched)| format!(
                        "{{\"view\":{}, {},\"conflicts\":{},\"incomplete\":{},\
                         \"matched\":{},\"skipped\":[{}]}}",
                        jstr(label),
                        stats_json(stats),
                        conflicts,
                        !skipped.is_empty(),
                        matched,
                        skipped
                            .iter()
                            .map(|(path, problem)| format!(
                                "{{\"path\":{},\"problem\":{}}}",
                                jstr(&path.to_string()),
                                jstr(problem)
                            ))
                            .collect::<Vec<_>>()
                            .join(",")
                    ))
                    .collect::<Vec<_>>()
                    .join(","),
                failures
                    .iter()
                    .map(|(label, error)| format!(
                        "{{\"view\":{},\"error\":{}}}",
                        jstr(label),
                        jstr(&error.to_string())
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        } else {
            let show_view = cli.global.view == cli::View::Both;
            for (label, stats, conflicts, skipped, matched) in &views {
                if show_view {
                    println!("view {label}");
                }
                print_stats(stats, *conflicts, !skipped.is_empty());
                for (path, problem) in skipped {
                    eprintln!("  skipped {path}: {problem}");
                }
                if !matched {
                    eprintln!("regx: view {label}: no registry state matched the stats scope");
                }
            }
            for (label, error) in &failures {
                eprintln!("view {label} failed: {error}");
            }
        }
        let incomplete = views
            .iter()
            .any(|(_, _, _, skipped, _)| !skipped.is_empty());
        let any_matched = views.iter().any(|(_, _, _, _, matched)| *matched);
        let missing_scope = views.iter().any(|(_, _, _, _, matched)| !matched);
        return Ok(if views.is_empty() {
            failures
                .first()
                .map(|(_, error)| reg_exit(error))
                .unwrap_or(exit::NOT_FOUND)
        } else if !any_matched {
            exit::NOT_FOUND
        } else if !failures.is_empty() || incomplete || missing_scope {
            exit::PARTIAL
        } else {
            exit::OK
        });
    }

    if let Some(computer) = computer {
        return Err(usage(format!(
            "--computer {computer:?} requires SOURCE to be an HKLM or HKU registry path"
        )));
    }
    if root_as.is_some() {
        return Err(usage(
            "stats --root-as requires SOURCE to be a live registry key".to_string(),
        ));
    }
    if cli.global.view != cli::View::Native {
        return Err(usage(
            "stats --view requires SOURCE to be a live registry key".to_string(),
        ));
    }
    let file = Path::new(source);
    if !is_stream_input(file) && !file.exists() {
        return Err(anyhow!(
            "{source:?} is neither an existing file nor a registry path starting with a known root"
        ));
    }
    let outcome = read_any(cli, file, input)?;
    let incomplete = !outcome.losses.is_empty() || !outcome.conflicts.is_empty();
    let selection = fingerprint_selection(outcome.file.keys, key_filters, value_filters, false)?;
    let (stats, conflicts) = registry_stats(selection.keys, None);
    if cli.global.output == OutputFormat::Json {
        println!(
            "{{\"source\":{},\"format\":{},\"rootAs\":null, {},\"conflicts\":{},\"incomplete\":{},\
             \"matched\":{},\"include\":[{}],\"exclude\":[{}],\"includeValues\":[{}],\
             \"excludeValues\":[{}]}}",
            jstr(source),
            jstr(&outcome.format.to_string()),
            stats_json(&stats),
            conflicts,
            incomplete,
            selection.matched,
            json_strings(&key_filters.include_keys),
            json_strings(&key_filters.exclude_keys),
            json_strings(&value_filters.include),
            json_strings(&value_filters.exclude)
        );
    } else {
        println!("source         {source}");
        println!("format         {}", outcome.format);
        print_stats(&stats, conflicts, incomplete);
        if !selection.matched {
            eprintln!("regx: no registry state matched the stats scope");
        }
    }
    Ok(if !selection.matched {
        exit::NOT_FOUND
    } else if incomplete {
        exit::PARTIAL
    } else {
        exit::OK
    })
}

struct FingerprintJob<'a> {
    source: &'a str,
    computer: Option<&'a str>,
    root_as: Option<&'a str>,
    expect: Option<&'a str>,
    expect_32: Option<&'a str>,
    expect_64: Option<&'a str>,
    key_filters: &'a cli::KeyFilterOpts,
    value_filters: &'a cli::ValueFilterOpts,
    input: &'a cli::InputOpts,
}

fn cmd_fingerprint(cli: &Cli, job: FingerprintJob<'_>) -> anyhow::Result<i32> {
    let FingerprintJob {
        source,
        computer,
        root_as,
        expect,
        expect_32,
        expect_64,
        key_filters,
        value_filters,
        input,
    } = job;
    let expect = expect.map(normalize_expected_sha256).transpose()?;
    let expect_32 = expect_32.map(normalize_expected_sha256).transpose()?;
    let expect_64 = expect_64.map(normalize_expected_sha256).transpose()?;
    if let Some(path) = RegPath::parse(source) {
        let destination_root = root_as
            .map(|root| {
                RegPath::parse(root).ok_or_else(|| {
                    usage(format!(
                        "--root-as {root:?} is not an absolute registry key"
                    ))
                })
            })
            .transpose()?;
        if cli.global.view == cli::View::Both {
            if expect.is_some() {
                return Err(usage(
                    "--expect is ambiguous with --view both; use --expect-32 and --expect-64"
                        .to_string(),
                ));
            }
            if expect_32.is_some() != expect_64.is_some() {
                return Err(usage(
                    "--view both requires --expect-32 and --expect-64 together".to_string(),
                ));
            }
        } else if expect_32.is_some() || expect_64.is_some() {
            return Err(usage(
                "--expect-32/--expect-64 require --view both".to_string(),
            ));
        }
        let roots = roots_for_read(computer, &path)?;
        let mut views = Vec::new();
        let mut failures = Vec::new();
        for (label, view) in selected_views(cli.global.view) {
            match engine::export(&roots, &path, view, true) {
                Ok((mut keys, report)) => {
                    if let Some(destination) = &destination_root {
                        keys = rebase_subtree(&keys, &path, destination)?;
                    }
                    let expected = match cli.global.view {
                        cli::View::Both => match label {
                            "32" => expect_32.as_deref(),
                            "64" => expect_64.as_deref(),
                            _ => unreachable!("both selects only 32/64 registry views"),
                        },
                        _ => expect.as_deref(),
                    };
                    let selection = fingerprint_selection(keys, key_filters, value_filters, false)?;
                    let result = fingerprint::calculate(selection.keys);
                    let matches =
                        expected.map(|expected| selection.matched && expected == result.sha256);
                    views.push((
                        label,
                        result,
                        report.skipped,
                        expected.map(str::to_string),
                        matches,
                        selection.matched,
                        selection.key_count,
                        selection.value_count,
                    ));
                }
                Err(error) => failures.push((label, error)),
            }
        }
        if cli.global.output == OutputFormat::Json {
            println!(
                "{{\"source\":{},\"computer\":{},\"rootAs\":{},\"canonicalVersion\":{},\
                 \"algorithm\":\"sha256\",\"include\":[{}],\"exclude\":[{}],\
                 \"includeValues\":[{}],\"excludeValues\":[{}],\"views\":[{}],\"failures\":[{}]}}",
                jstr(source),
                computer.map(jstr).unwrap_or_else(|| "null".into()),
                destination_root
                    .as_ref()
                    .map(|root| jstr(&root.to_string()))
                    .unwrap_or_else(|| "null".into()),
                fingerprint::VERSION,
                json_strings(&key_filters.include_keys),
                json_strings(&key_filters.exclude_keys),
                json_strings(&value_filters.include),
                json_strings(&value_filters.exclude),
                views
                    .iter()
                    .map(|(label, result, skipped, expected, matches, matched, keys, values)| format!(
                        "{{\"view\":{},\"sha256\":{},\"conflicts\":{},\
                         \"incomplete\":{},\"expected\":{},\"matches\":{},\"matched\":{},\
                         \"keys\":{},\"values\":{},\"skipped\":[{}]}}",
                        jstr(label),
                        jstr(&result.sha256),
                        result.conflicts,
                        !skipped.is_empty(),
                        expected
                            .as_deref()
                            .map(jstr)
                            .unwrap_or_else(|| "null".into()),
                        matches.map_or_else(|| "null".into(), |value| value.to_string()),
                        matched,
                        keys,
                        values,
                        skipped
                            .iter()
                            .map(|(path, problem)| format!(
                                "{{\"path\":{},\"problem\":{}}}",
                                jstr(&path.to_string()),
                                jstr(problem)
                            ))
                            .collect::<Vec<_>>()
                            .join(",")
                    ))
                    .collect::<Vec<_>>()
                    .join(","),
                failures
                    .iter()
                    .map(|(label, error)| format!(
                        "{{\"view\":{},\"error\":{}}}",
                        jstr(label),
                        jstr(&error.to_string())
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        } else {
            let show_view = cli.global.view == cli::View::Both;
            for (label, result, skipped, expected, matches, matched, _, _) in &views {
                if show_view {
                    println!("{}  {label}", result.sha256);
                } else {
                    println!("{}", result.sha256);
                }
                if result.conflicts > 0 {
                    eprintln!(
                        "regx: {source}: {} conflict(s) resolved by last-write-wins",
                        result.conflicts
                    );
                }
                for (path, problem) in skipped {
                    eprintln!("  skipped {path}: {problem}");
                }
                if matches == &Some(false) {
                    eprintln!(
                        "regx: view {label}: fingerprint mismatch (expected {})",
                        expected.as_deref().expect("mismatch has expected hash")
                    );
                }
                if !matched {
                    eprintln!(
                        "regx: view {label}: no registry state matched the fingerprint scope"
                    );
                }
            }
            for (label, error) in &failures {
                eprintln!("view {label} failed: {error}");
            }
        }
        let incomplete = views
            .iter()
            .any(|(_, _, skipped, _, _, _, _, _)| !skipped.is_empty());
        let mismatch = views
            .iter()
            .any(|(_, _, _, _, matches, _, _, _)| matches == &Some(false));
        let any_matched = views.iter().any(|(_, _, _, _, _, matched, _, _)| *matched);
        let missing_scope = views.iter().any(|(_, _, _, _, _, matched, _, _)| !matched);
        return Ok(if views.is_empty() {
            failures
                .first()
                .map(|(_, error)| reg_exit(error))
                .unwrap_or(exit::NOT_FOUND)
        } else if !any_matched {
            exit::NOT_FOUND
        } else if !failures.is_empty() || incomplete || mismatch || missing_scope {
            exit::PARTIAL
        } else {
            exit::OK
        });
    }

    if let Some(computer) = computer {
        return Err(usage(format!(
            "--computer {computer:?} requires SOURCE to be an HKLM or HKU registry path"
        )));
    }
    if root_as.is_some() {
        return Err(usage(
            "fingerprint --root-as requires SOURCE to be a live registry key".to_string(),
        ));
    }
    if cli.global.view != cli::View::Native {
        return Err(usage(
            "fingerprint --view requires SOURCE to be a live registry key".to_string(),
        ));
    }
    if expect_32.is_some() || expect_64.is_some() {
        return Err(usage(
            "--expect-32/--expect-64 require a live registry key with --view both".to_string(),
        ));
    }
    let file = Path::new(source);
    if !is_stream_input(file) && !file.exists() {
        return Err(anyhow!(
            "{source:?} is neither an existing file nor a registry path starting with a known root"
        ));
    }
    let outcome = read_any(cli, file, input)?;
    let incomplete = !outcome.losses.is_empty() || !outcome.conflicts.is_empty();
    let selection = fingerprint_selection(outcome.file.keys, key_filters, value_filters, false)?;
    let result = fingerprint::calculate(selection.keys);
    let matches = expect
        .as_deref()
        .map(|expected| selection.matched && expected == result.sha256);
    if cli.global.output == OutputFormat::Json {
        println!(
            "{{\"source\":{},\"format\":{},\"rootAs\":null,\"canonicalVersion\":{},\
             \"algorithm\":\"sha256\",\"sha256\":{},\"conflicts\":{},\"incomplete\":{},\
             \"expected\":{},\"matches\":{},\"matched\":{},\"keys\":{},\"values\":{},\
             \"include\":[{}],\"exclude\":[{}],\"includeValues\":[{}],\"excludeValues\":[{}]}}",
            jstr(source),
            jstr(&outcome.format.to_string()),
            fingerprint::VERSION,
            jstr(&result.sha256),
            result.conflicts,
            incomplete,
            expect.as_deref().map(jstr).unwrap_or_else(|| "null".into()),
            matches.map_or_else(|| "null".into(), |value| value.to_string()),
            selection.matched,
            selection.key_count,
            selection.value_count,
            json_strings(&key_filters.include_keys),
            json_strings(&key_filters.exclude_keys),
            json_strings(&value_filters.include),
            json_strings(&value_filters.exclude)
        );
    } else {
        println!("{}", result.sha256);
        if result.conflicts > 0 {
            eprintln!(
                "regx: {source}: {} conflict(s) resolved by last-write-wins",
                result.conflicts
            );
        }
        if matches == Some(false) {
            eprintln!(
                "regx: fingerprint mismatch (expected {})",
                expect.as_deref().expect("mismatch has expected hash")
            );
        }
        if !selection.matched {
            eprintln!("regx: no registry state matched the fingerprint scope");
        }
    }
    Ok(if !selection.matched {
        exit::NOT_FOUND
    } else if incomplete || matches == Some(false) {
        exit::PARTIAL
    } else {
        exit::OK
    })
}

struct FingerprintSelection {
    keys: Vec<KeyBlock>,
    matched: bool,
    key_count: usize,
    value_count: usize,
}

fn fingerprint_selection(
    keys: Vec<KeyBlock>,
    key_filters: &cli::KeyFilterOpts,
    value_filters: &cli::ValueFilterOpts,
    relative_paths: bool,
) -> anyhow::Result<FingerprintSelection> {
    let scope_active = !key_filters.include_keys.is_empty()
        || !key_filters.exclude_keys.is_empty()
        || !value_filters.include.is_empty()
        || !value_filters.exclude.is_empty();
    let mut file = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys,
    };
    if !key_filters.include_keys.is_empty() || !key_filters.exclude_keys.is_empty() {
        let filters = search::Filters::compile_globs(
            &key_filters.include_keys,
            &key_filters.exclude_keys,
            false,
        )
        .map_err(usage)?;
        file.keys.retain(|block| {
            if relative_paths {
                filters.allows(&block.path.sub)
            } else {
                filters.allows(&block.path.to_string())
            }
        });
    }
    filter_value_names(&mut file, value_filters)?;
    let key_count = file.keys.len();
    let value_count = file.keys.iter().map(|key| key.values.len()).sum();
    Ok(FingerprintSelection {
        matched: !scope_active || key_count > 0,
        keys: file.keys,
        key_count,
        value_count,
    })
}

fn json_strings(values: &[String]) -> String {
    values
        .iter()
        .map(|value| jstr(value))
        .collect::<Vec<_>>()
        .join(",")
}

fn normalize_expected_sha256(raw: &str) -> anyhow::Result<String> {
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(usage(format!(
            "expected SHA-256 must be exactly 64 hexadecimal characters, found {raw:?}"
        )));
    }
    Ok(raw.to_ascii_lowercase())
}

fn query_view(
    roots: &Roots,
    path: &RegPath,
    value: Option<&str>,
    recursive: bool,
    view: View,
) -> winreg::Result<(Vec<KeyBlock>, engine::ExportReport)> {
    let (mut keys, report) = engine::export(roots, path, view, recursive)?;
    if let Some(want) = value {
        for block in &mut keys {
            block.values.retain(|entry| {
                model::fold_str(engine::value_api_name(&entry.name)) == model::fold_str(want)
            });
        }
    }
    Ok((keys, report))
}

fn print_query(
    cli: &Cli,
    roots: &Roots,
    path: &RegPath,
    value: Option<&str>,
    recursive: bool,
    root_label: Option<&str>,
) -> anyhow::Result<i32> {
    let (keys, report) = match query_view(roots, path, value, recursive, view_of(&cli.global)) {
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
        return Ok(if !report.skipped.is_empty() {
            exit::PARTIAL
        } else if value.is_some() && !query_has_values(&keys, value) {
            exit::NOT_FOUND
        } else {
            exit::OK
        });
    }

    render_query_text(&keys, &report, &label);
    Ok(if !report.skipped.is_empty() {
        exit::PARTIAL
    } else if value.is_some() && !query_has_values(&keys, value) {
        exit::NOT_FOUND
    } else {
        exit::OK
    })
}

fn render_query_text(
    keys: &[KeyBlock],
    report: &engine::ExportReport,
    label: &dyn Fn(&RegPath) -> String,
) {
    for block in keys {
        println!("{}", label(&block.path));
        for v in &block.values {
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
}

fn query_has_values(keys: &[KeyBlock], requested: Option<&str>) -> bool {
    requested.is_none() || keys.iter().any(|block| !block.values.is_empty())
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
                "{{\"name\": {}, \"type\": {}, \"data\": {}, \"exact\": {}}}",
                jstr(&v.name.to_string()),
                jstr(v.data.type_name()),
                jstr(&v.data.preview()),
                writer::value_to_json(v)
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

struct SetJob<'a> {
    key: &'a str,
    value: &'a str,
    ty: &'a str,
    data: &'a str,
    redirect: &'a RedirectOpts,
    backup: Option<&'a Path>,
}

fn cmd_set(cli: &Cli, policy: &policy::Policy, job: SetJob<'_>) -> anyhow::Result<i32> {
    let SetJob {
        key,
        value,
        ty,
        data,
        redirect: ropts,
        backup,
    } = job;
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
    apply_redirect(&mut file, ropts, policy, cli.global.log_level);
    if file.keys.is_empty() {
        return Ok(exit::REDIRECT_REFUSED);
    }

    let roots = Roots::live();
    enforce_denies(policy, &file)?;
    let views = selected_views(cli.global.view);
    let snapshots = match capture_view_snapshots(&roots, &file, &views) {
        Ok(snapshots) => snapshots,
        Err(incomplete) => {
            print_incomplete_view_snapshots(&incomplete);
            return Ok(exit::ACCESS_DENIED);
        }
    };
    let undo_paths = direct_mutation_undo_paths("set", backup, &snapshots, cli.global.dry_run);

    if !confirm(
        &cli.global,
        policy,
        &format!("Set value {value:?} under {}?", file.keys[0].path),
    ) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }

    write_direct_mutation_undo("set", &snapshots, &undo_paths)?;
    let mut logger = open_audit(cli, policy, &command_line())?;
    let reports =
        apply_with_view_snapshots(&roots, &snapshots, cli.global.dry_run, logger.as_mut());
    print_direct_mutation_reports(cli, &reports, &undo_paths)?;
    Ok(view_apply_exit(&reports))
}

fn cmd_delete(
    cli: &Cli,
    policy: &policy::Policy,
    key: &str,
    value: Option<&str>,
    recursive: bool,
    backup: Option<&Path>,
) -> anyhow::Result<i32> {
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
                return Err(usage(
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

    let file = RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys: vec![block],
    };

    // Before the prompt, not after it. Asking someone to confirm a deletion
    // that policy is about to refuse wastes their attention and teaches them
    // the prompt does not mean what it says.
    enforce_denies(policy, &file)?;

    let roots = Roots::live();
    let views = selected_views(cli.global.view);
    let snapshots = match capture_view_snapshots(&roots, &file, &views) {
        Ok(snapshots) => snapshots,
        Err(incomplete) => {
            print_incomplete_view_snapshots(&incomplete);
            return Ok(exit::ACCESS_DENIED);
        }
    };
    let undo_paths = direct_mutation_undo_paths("delete", backup, &snapshots, cli.global.dry_run);

    if !confirm(&cli.global, policy, &format!("Delete {path}?")) {
        eprintln!("regx: aborted");
        return Ok(exit::OK);
    }

    write_direct_mutation_undo("delete", &snapshots, &undo_paths)?;
    let mut logger = open_audit(cli, policy, &command_line())?;
    let reports =
        apply_with_view_snapshots(&roots, &snapshots, cli.global.dry_run, logger.as_mut());
    print_direct_mutation_reports(cli, &reports, &undo_paths)?;
    Ok(view_apply_exit(&reports))
}

fn direct_mutation_undo_paths(
    verb: &str,
    backup: Option<&Path>,
    snapshots: &[ViewSnapshot],
    dry_run: bool,
) -> Vec<(&'static str, PathBuf)> {
    if dry_run {
        return Vec::new();
    }
    let base = backup
        .map(Path::to_path_buf)
        .unwrap_or_else(|| undo::temporary_path(verb));
    snapshots
        .iter()
        .map(|snapshot| {
            (
                snapshot.label,
                view_undo_path(&base, snapshot.label, snapshots.len() > 1),
            )
        })
        .collect()
}

fn write_direct_mutation_undo(
    verb: &str,
    snapshots: &[ViewSnapshot],
    undo_paths: &[(&'static str, PathBuf)],
) -> anyhow::Result<()> {
    for (snapshot, (_, path)) in snapshots.iter().zip(undo_paths) {
        write_reg(
            path,
            &snapshot.snapshot.file,
            None,
            &[
                format!("regx undo snapshot for {verb} (view {})", snapshot.label),
                format!(
                    "{} value(s) captured, {} key(s) to remove on rollback",
                    snapshot.snapshot.restored_values,
                    snapshot.snapshot.new_keys.len()
                ),
                format!(
                    "Apply with --view {} to revert this operation.",
                    snapshot.label
                ),
            ],
        )?;
        eprintln!(
            "regx: undo snapshot (view {}) -> {}",
            snapshot.label,
            path.display()
        );
    }
    Ok(())
}

fn print_direct_mutation_reports(
    cli: &Cli,
    reports: &[ViewApplyReport],
    undo_paths: &[(&'static str, PathBuf)],
) -> anyhow::Result<()> {
    if cli.global.output != OutputFormat::Json {
        print_view_apply_reports(cli, reports);
        return Ok(());
    }
    let views = reports
        .iter()
        .map(|report| {
            let undo_path = undo_paths
                .iter()
                .find(|(label, _)| *label == report.label)
                .map(|(_, path)| path);
            let undo = undo_path
                .map(|path| jstr(&path.display().to_string()))
                .unwrap_or_else(|| "null".into());
            let evidence = undo_path
                .map(|path| undo_evidence_json(path, cli.global.dry_run))
                .transpose()?
                .unwrap_or_else(|| "\"undoBytes\":null,\"undoSha256\":null".into());
            Ok(format!(
                "{{\"view\":{},\"undo\":{}, {},\"apply\":{},\"rolledBack\":{},\"rollback\":{}}}",
                jstr(report.label),
                undo,
                evidence,
                report
                    .applied
                    .as_ref()
                    .map(apply_report_json)
                    .unwrap_or_else(|| "null".into()),
                report.rollback.is_some(),
                report
                    .rollback
                    .as_ref()
                    .map(apply_report_json)
                    .unwrap_or_else(|| "null".into())
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    println!("{{\"views\":[{}]}}", views.join(","));
    Ok(())
}

fn print_incomplete_view_snapshots(incomplete: &[(&str, Vec<(String, String)>)]) {
    eprintln!("regx: refusing mutation because rollback is incomplete:");
    for (view, unreadable) in incomplete {
        eprintln!("  view {view}: {} unreadable target(s)", unreadable.len());
        for (path, error) in unreadable.iter().take(5) {
            eprintln!("    {path}: {error}");
        }
    }
}

fn print_view_apply_reports(cli: &Cli, reports: &[ViewApplyReport]) {
    if cli.global.output == OutputFormat::Json {
        let views = reports
            .iter()
            .map(|report| {
                format!(
                    "{{\"view\":{},\"undo\":null,\"undoBytes\":null,\"undoSha256\":null,\
                     \"apply\":{},\"rolledBack\":{},\"rollback\":{}}}",
                    jstr(report.label),
                    report
                        .applied
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into()),
                    report.rollback.is_some(),
                    report
                        .rollback
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into())
                )
            })
            .collect::<Vec<_>>();
        println!("{{\"views\":[{}]}}", views.join(","));
    } else {
        for report in reports {
            eprintln!("regx: view {}", report.label);
            if let Some(applied) = &report.applied {
                print_apply(cli, applied);
            } else {
                eprintln!("regx: not attempted because an earlier view failed");
            }
            if let Some(rollback) = &report.rollback {
                eprintln!("regx: rollback:");
                print_apply(cli, rollback);
            }
        }
    }
}

fn view_apply_exit(reports: &[ViewApplyReport]) -> i32 {
    let failed = reports.iter().any(|view| {
        view.applied
            .as_ref()
            .is_none_or(|report| !report.failures.is_empty())
    });
    let rollback_failed = reports.iter().any(|view| {
        view.rollback
            .as_ref()
            .is_some_and(|report| !report.failures.is_empty())
    });
    let unrolled_changes = reports.iter().any(|view| {
        view.applied
            .as_ref()
            .is_some_and(|report| report.touched() > 0)
            && view.rollback.is_none()
    });
    if rollback_failed || failed && unrolled_changes {
        exit::PARTIAL
    } else if failed {
        exit::ACCESS_DENIED
    } else {
        exit::OK
    }
}

fn cmd_probe(cli: &Cli, key: &str, computer: Option<&str>) -> anyhow::Result<i32> {
    let path = parse_key(key)?;
    let roots = roots_for_read(computer, &path)?;
    if cli.global.view == cli::View::Both {
        let views = [("32", View::Bits32), ("64", View::Bits64)]
            .map(|(label, view)| (label, engine::probe(&roots, &path, view)));
        if cli.global.output == OutputFormat::Json {
            let items = views
                .iter()
                .map(|(label, result)| {
                    format!(
                        "{{\"view\":{},\"exists\":{},\"readable\":{},\"writable\":{},\
                         \"creatable\":{},\"detail\":{}}}",
                        jstr(label),
                        result.exists,
                        result.readable,
                        result.writable,
                        result.creatable,
                        jstr(&result.detail)
                    )
                })
                .collect::<Vec<_>>();
            println!(
                "{{\"path\":{},\"computer\":{},\"views\":[{}]}}",
                jstr(&path.to_string()),
                computer.map(jstr).unwrap_or_else(|| "null".into()),
                items.join(",")
            );
        } else {
            println!(
                "{path}{}",
                computer
                    .map(|host| format!(" on \\\\{host}"))
                    .unwrap_or_default()
            );
            for (label, result) in &views {
                println!(
                    "  view {label}: exists={} readable={} writable={} creatable={}",
                    result.exists, result.readable, result.writable, result.creatable
                );
                if !result.detail.is_empty() {
                    println!("    {}", result.detail);
                }
            }
        }
        let usable = views
            .iter()
            .filter(|(_, result)| result.writable || result.creatable)
            .count();
        return Ok(match usable {
            2 => exit::OK,
            1 => exit::PARTIAL,
            _ => exit::ACCESS_DENIED,
        });
    }
    let r = engine::probe(&roots, &path, view_of(&cli.global));

    if cli.global.output == OutputFormat::Json {
        println!(
            "{{\"path\": {}, \"computer\": {}, \"exists\": {}, \"readable\": {}, \"writable\": {}, \"creatable\": {}, \"detail\": {}}}",
            jstr(&r.path),
            computer.map(jstr).unwrap_or_else(|| "null".into()),
            r.exists,
            r.readable,
            r.writable,
            r.creatable,
            jstr(&r.detail)
        );
    } else {
        println!(
            "{}{}",
            r.path,
            computer
                .map(|host| format!(" on \\\\{host}"))
                .unwrap_or_default()
        );
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

struct PermissionView {
    label: &'static str,
    security: winreg::SecurityInfo,
    query: bool,
    enumerate: bool,
    notify: bool,
    set_value: bool,
    create_subkey: bool,
    delete: bool,
}

fn read_permission_views(
    roots: &Roots,
    path: &RegPath,
    views: &[(&'static str, View)],
) -> (Vec<PermissionView>, Vec<(&'static str, String)>) {
    let (root, sub) = roots.resolve(path);
    let mut reports = Vec::new();
    let mut failures = Vec::new();
    for &(label, view) in views {
        let security = match root.open(&sub, winreg::READ_CONTROL, view) {
            Ok(key) => match key.security_info() {
                Ok(info) => info,
                Err(error) => {
                    failures.push((label, error.to_string()));
                    continue;
                }
            },
            Err(error) => {
                failures.push((label, error.to_string()));
                continue;
            }
        };
        let can = |access| root.open(&sub, access, view).is_ok();
        reports.push(PermissionView {
            label,
            security,
            query: can(winreg::KEY_QUERY_VALUE),
            enumerate: can(winreg::KEY_ENUMERATE_SUB_KEYS),
            notify: can(winreg::KEY_NOTIFY),
            set_value: can(winreg::KEY_SET_VALUE),
            create_subkey: can(winreg::KEY_CREATE_SUB_KEY),
            delete: can(winreg::DELETE),
        });
    }
    (reports, failures)
}

fn permission_view_json(report: &PermissionView) -> String {
    format!(
        "{{\"view\":{},\"ownerSid\":{},\"inheritanceEnabled\":{},\"sddl\":{},\
         \"effective\":{{\"queryValue\":{},\"enumerateSubkeys\":{},\"notify\":{},\
         \"setValue\":{},\"createSubkey\":{},\"delete\":{}}}}}",
        jstr(report.label),
        jstr(&report.security.owner_sid),
        report.security.inheritance_enabled,
        jstr(&report.security.sddl),
        report.query,
        report.enumerate,
        report.notify,
        report.set_value,
        report.create_subkey,
        report.delete
    )
}

fn permission_differences(a: &PermissionView, b: &PermissionView) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if a.security.owner_sid != b.security.owner_sid {
        fields.push("ownerSid");
    }
    if a.security.inheritance_enabled != b.security.inheritance_enabled {
        fields.push("inheritanceEnabled");
    }
    if a.security.sddl != b.security.sddl {
        fields.push("sddl");
    }
    for (different, field) in [
        (a.query != b.query, "effective.queryValue"),
        (a.enumerate != b.enumerate, "effective.enumerateSubkeys"),
        (a.notify != b.notify, "effective.notify"),
        (a.set_value != b.set_value, "effective.setValue"),
        (a.create_subkey != b.create_subkey, "effective.createSubkey"),
        (a.delete != b.delete, "effective.delete"),
    ] {
        if different {
            fields.push(field);
        }
    }
    fields
}

fn cmd_permissions(
    cli: &Cli,
    key: &str,
    computer: Option<&str>,
    compare: Option<&str>,
    compare_computer: Option<&str>,
    exit_code: bool,
) -> anyhow::Result<i32> {
    let path = parse_key(key)?;
    let compare_path = compare.map(parse_key).transpose()?;
    let roots = roots_for_read(computer, &path)?;
    let views: Vec<(&'static str, View)> = match cli.global.view {
        cli::View::Native => vec![("native", View::Native)],
        cli::View::Bits32 => vec![("32", View::Bits32)],
        cli::View::Bits64 => vec![("64", View::Bits64)],
        cli::View::Both => vec![("32", View::Bits32), ("64", View::Bits64)],
    };
    let (reports, failures) = read_permission_views(&roots, &path, &views);

    if let Some(compare_path) = compare_path {
        let other_roots = roots_for_read(compare_computer, &compare_path)?;
        let (other_reports, other_failures) =
            read_permission_views(&other_roots, &compare_path, &views);
        let comparisons = reports
            .iter()
            .filter_map(|before| {
                other_reports
                    .iter()
                    .find(|after| after.label == before.label)
                    .map(|after| (before, after, permission_differences(before, after)))
            })
            .collect::<Vec<_>>();
        let different = comparisons
            .iter()
            .any(|(_, _, differences)| !differences.is_empty());
        if cli.global.output == OutputFormat::Json {
            let rendered = comparisons
                .iter()
                .map(|(before, after, differences)| {
                    format!(
                        "{{\"view\":{},\"equal\":{},\"differences\":[{}],\"source\":{},\"target\":{}}}",
                        jstr(before.label),
                        differences.is_empty(),
                        differences
                            .iter()
                            .map(|field| jstr(field))
                            .collect::<Vec<_>>()
                            .join(","),
                        permission_view_json(before),
                        permission_view_json(after)
                    )
                })
                .collect::<Vec<_>>();
            let errors = failures
                .iter()
                .map(|(view, error)| {
                    format!(
                        "{{\"side\":\"source\",\"view\":{},\"error\":{}}}",
                        jstr(view),
                        jstr(error)
                    )
                })
                .chain(other_failures.iter().map(|(view, error)| {
                    format!(
                        "{{\"side\":\"target\",\"view\":{},\"error\":{}}}",
                        jstr(view),
                        jstr(error)
                    )
                }))
                .collect::<Vec<_>>();
            println!(
                "{{\"sourcePath\":{},\"sourceComputer\":{},\"targetPath\":{},\
                 \"targetComputer\":{},\"equal\":{},\"views\":[{}],\"failures\":[{}]}}",
                jstr(&path.to_string()),
                computer.map(jstr).unwrap_or_else(|| "null".into()),
                jstr(&compare_path.to_string()),
                compare_computer.map(jstr).unwrap_or_else(|| "null".into()),
                !different && failures.is_empty() && other_failures.is_empty(),
                rendered.join(","),
                errors.join(",")
            );
        } else {
            println!(
                "{path}{} compared with {compare_path}{}",
                computer
                    .map(|host| format!(" on \\\\{host}"))
                    .unwrap_or_default(),
                compare_computer
                    .map(|host| format!(" on \\\\{host}"))
                    .unwrap_or_default()
            );
            for (before, _, differences) in &comparisons {
                println!(
                    "  view {}       {}",
                    before.label,
                    if differences.is_empty() {
                        "equal"
                    } else {
                        "DIFFERENT"
                    }
                );
                for field in differences {
                    println!("    {field}");
                }
            }
            for (side, failed) in [("source", &failures), ("target", &other_failures)] {
                for (view, error) in failed {
                    eprintln!("  {side} view {view} failed: {error}");
                }
            }
        }
        return Ok(if comparisons.is_empty() {
            exit::ACCESS_DENIED
        } else if !failures.is_empty() || !other_failures.is_empty() || (exit_code && different) {
            exit::PARTIAL
        } else {
            exit::OK
        });
    }

    if cli.global.output == OutputFormat::Json {
        let views = reports.iter().map(permission_view_json).collect::<Vec<_>>();
        let errors = failures
            .iter()
            .map(|(view, error)| format!("{{\"view\":{},\"error\":{}}}", jstr(view), jstr(error)))
            .collect::<Vec<_>>();
        println!(
            "{{\"path\":{},\"computer\":{},\"views\":[{}],\"failures\":[{}]}}",
            jstr(&path.to_string()),
            computer.map(jstr).unwrap_or_else(|| "null".into()),
            views.join(","),
            errors.join(",")
        );
    } else {
        println!(
            "{path}{}",
            computer
                .map(|host| format!(" on \\\\{host}"))
                .unwrap_or_default()
        );
        for report in &reports {
            println!("  view          {}", report.label);
            println!("  owner SID     {}", report.security.owner_sid);
            println!(
                "  inheritance   {}",
                if report.security.inheritance_enabled {
                    "enabled"
                } else {
                    "protected"
                }
            );
            println!("  SDDL          {}", report.security.sddl);
            println!(
                "  effective     query={} enumerate={} notify={} set={} create-subkey={} delete={}",
                report.query,
                report.enumerate,
                report.notify,
                report.set_value,
                report.create_subkey,
                report.delete
            );
        }
        for (view, error) in &failures {
            eprintln!("  view {view} failed: {error}");
        }
    }

    Ok(if reports.is_empty() {
        exit::ACCESS_DENIED
    } else if failures.is_empty() {
        exit::OK
    } else {
        exit::PARTIAL
    })
}

// ---------------------------------------------------------------------------
// hive
// ---------------------------------------------------------------------------

fn cmd_hive(
    cli: &Cli,
    policy: &policy::Policy,
    file: &Path,
    op: &HiveOp,
    create: bool,
    exclusive: bool,
) -> anyhow::Result<i32> {
    if cli.global.view != cli::View::Native {
        return Err(usage(
            "offline application hives have no WOW64 registry-view split; omit --view",
        ));
    }
    if let HiveOp::Info = op {
        let i = hive::info(file);
        if cli.global.output == OutputFormat::Json {
            println!(
                "{{\"file\":{},\"size\":{},\"signatureValid\":{},\"readable\":{},\
                 \"writable\":{},\"detail\":{},\"rootSubkeys\":[{}]}}",
                jstr(&i.path.display().to_string()),
                i.size,
                i.signature_ok,
                i.readable,
                i.writable,
                jstr(&i.detail),
                i.root_subkeys
                    .iter()
                    .map(|key| jstr(key))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        } else {
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
        return Err(usage(
            "`hive exec` needs at least one -c OP or --script FILE",
        ));
    }

    if ops.is_empty() {
        worst = run_hive_op(cli, policy, &session, op)?;
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
            match run_hive_op(cli, policy, &session, &sub) {
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
        HiveOp::Set { .. }
        | HiveOp::Delete { .. }
        | HiveOp::Copy { .. }
        | HiveOp::Move { .. }
        | HiveOp::CopyValue { .. }
        | HiveOp::MoveValue { .. }
        | HiveOp::Import { .. }
        | HiveOp::Undo { .. }
        | HiveOp::Sync { .. }
        | HiveOp::Batch { .. } => true,
        HiveOp::Exec { cmd, script, .. } => {
            let mut lines = cmd.clone();
            if let Some(s) = script {
                if let Ok(extra) = std::fs::read_to_string(s) {
                    lines.extend(
                        extra
                            .lines()
                            .map(str::trim)
                            .filter(|line| {
                                !line.is_empty() && !line.starts_with('#') && !line.starts_with(';')
                            })
                            .map(str::to_owned),
                    );
                }
            }
            lines.iter().any(|line| {
                let argv = split_argv(line);
                // Invalid operations fail later with usage. Open conservatively
                // here because guessing read-only for an unrecognized write
                // grammar would turn the real diagnostic into access denied.
                cli::HiveOpLine::try_parse_from(argv)
                    .map(|parsed| op_needs_write(&parsed.op))
                    .unwrap_or(true)
            })
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

fn joined_reg_path(root: &RegPath, suffix: &str) -> RegPath {
    let suffix = suffix.trim_matches('\\');
    let sub = match (root.sub.is_empty(), suffix.is_empty()) {
        (true, _) => suffix.to_string(),
        (_, true) => root.sub.clone(),
        (false, false) => format!("{}\\{suffix}", root.sub),
    };
    RegPath {
        hive: root.hive,
        sub,
    }
}

/// Re-root an imported file beneath an application-hive handle.
///
/// Every key must be below the requested prefix. Silently retaining a
/// non-matching absolute key would apply it relative to the private hive under
/// a surprising path, which is especially unsafe for reconciliation.
fn strip_hive_root(file: &mut RegFile, prefix: Option<&str>) -> anyhow::Result<()> {
    let Some(prefix) = prefix else {
        return Ok(());
    };
    let prefix = prefix.trim_matches('\\');
    if prefix.is_empty() {
        return Err(usage("--strip-root cannot be empty"));
    }
    let source = RegPath::parse(prefix)
        .ok_or_else(|| usage(format!("invalid --strip-root registry path {prefix:?}")))?;
    file.keys = rebase_subtree(&file.keys, &source, &hive_path("")).map_err(|error| {
        usage(format!(
            "{error}; refusing a partially re-rooted hive import"
        ))
    })?;
    Ok(())
}

/// Refuse a hive write that policy forbids.
///
/// A mounted hive has no hive component, so the rule is matched on its subkey
/// path. Without this the offline engine was a straight bypass: an
/// administrator's denied key was protected in the live registry and not in
/// somebody's NTUSER.DAT.
fn enforce_hive_denies(policy: &policy::Policy, file: &RegFile) -> anyhow::Result<()> {
    for block in &file.keys {
        if block.delete && block.path.sub.is_empty() {
            return Err(usage(
                "refusing to delete the mounted hive root; delete named subkeys instead",
            ));
        }
        if let Some(rule) = policy.denies_hive_subkey(&block.path.sub) {
            return Err(access_denied(format!(
                "{} inside this hive is denied by administrative policy (rule: {rule}). \
                 Nothing was written.",
                if block.path.sub.is_empty() {
                    "the hive root"
                } else {
                    &block.path.sub
                }
            )));
        }
    }
    Ok(())
}

fn hive_atomic_exit(applied: &engine::ApplyReport, rollback: Option<&engine::ApplyReport>) -> i32 {
    if applied.failures.is_empty() {
        exit::OK
    } else if rollback.is_some_and(|report| report.failures.is_empty()) {
        exit::ACCESS_DENIED
    } else {
        exit::PARTIAL
    }
}

fn print_hive_atomic(
    cli: &Cli,
    applied: &engine::ApplyReport,
    rollback: Option<&engine::ApplyReport>,
    undo_path: Option<&Path>,
) -> anyhow::Result<()> {
    if cli.global.output == OutputFormat::Json {
        let evidence = undo_path
            .map(|path| undo_evidence_json(path, cli.global.dry_run))
            .transpose()?
            .unwrap_or_else(|| "\"undoBytes\":null,\"undoSha256\":null".into());
        println!(
            "{{\"undo\":{}, {},\"apply\":{},\"rolledBack\":{},\"rollback\":{}}}",
            undo_path
                .map(|path| jstr(&path.display().to_string()))
                .unwrap_or_else(|| "null".into()),
            evidence,
            apply_report_json(applied),
            rollback.is_some(),
            rollback
                .map(apply_report_json)
                .unwrap_or_else(|| "null".into())
        );
    } else {
        print_apply(cli, applied);
        if let Some(rollback) = rollback {
            eprintln!("regx: offline-hive rollback:");
            print_apply(cli, rollback);
        }
    }
    Ok(())
}

fn hive_undo_path(
    cli: &Cli,
    verb: &str,
    requested: Option<&Path>,
    input: Option<&Path>,
) -> Option<PathBuf> {
    if cli.global.dry_run {
        return None;
    }
    Some(
        requested
            .map(Path::to_path_buf)
            .or_else(|| input.map(undo::default_path))
            .unwrap_or_else(|| undo::temporary_path(&format!("hive-{verb}"))),
    )
}

fn write_hive_undo(
    snapshot: &undo::Snapshot,
    path: Option<&Path>,
    verb: &str,
) -> anyhow::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    write_reg(
        path,
        &snapshot.file,
        None,
        &[
            format!("regx undo snapshot for offline-hive {verb}"),
            format!(
                "{} value(s) captured, {} key(s) to remove on rollback",
                snapshot.restored_values,
                snapshot.new_keys.len()
            ),
            "Reapply with: regx hive HIVEFILE undo THIS_FILE -y".into(),
        ],
    )?;
    eprintln!("regx: offline-hive undo -> {}", path.display());
    Ok(())
}

fn run_hive_op(
    cli: &Cli,
    policy: &policy::Policy,
    s: &hive::Session,
    op: &HiveOp,
) -> anyhow::Result<i32> {
    let view = View::Native; // A mounted hive has no WOW64 split.
    match op {
        HiveOp::Info | HiveOp::Exec { .. } => Ok(exit::OK),

        HiveOp::Ls {
            subkey,
            recursive,
            keys: key_filters,
            limit,
        } => {
            let filters = search::Filters::compile_globs(
                &key_filters.include_keys,
                &key_filters.exclude_keys,
                false,
            )
            .map_err(usage)?;
            let (keys, rep) = match engine::list(
                &s.roots,
                &hive_path(subkey),
                view,
                *recursive,
                *limit as usize,
                |candidate| filters.allows(&candidate.sub),
            ) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("regx: {e}");
                    return Ok(reg_exit(&e));
                }
            };
            if cli.global.output == OutputFormat::Json {
                println!(
                    "{{\"subkey\":{},\"recursive\":{},\"include\":[{}],\"exclude\":[{}],\
                     \"limit\":{},\"truncated\":{},\"keys\":[{}],\"skipped\":[{}]}}",
                    jstr(subkey),
                    recursive,
                    key_filters
                        .include_keys
                        .iter()
                        .map(|pattern| jstr(pattern))
                        .collect::<Vec<_>>()
                        .join(","),
                    key_filters
                        .exclude_keys
                        .iter()
                        .map(|pattern| jstr(pattern))
                        .collect::<Vec<_>>()
                        .join(","),
                    limit,
                    rep.truncated,
                    keys.iter()
                        .map(|path| jstr(&path.sub))
                        .collect::<Vec<_>>()
                        .join(","),
                    rep.skipped
                        .iter()
                        .map(|(path, error)| format!(
                            "{{\"path\":{},\"problem\":{}}}",
                            jstr(&path.to_string()),
                            jstr(error)
                        ))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            } else {
                for path in &keys {
                    println!("{}", path.sub);
                }
                for (p, e) in &rep.skipped {
                    eprintln!("  skipped {p}: {e}");
                }
                if rep.truncated {
                    eprintln!("regx: result truncated at {limit} matching key(s)");
                }
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

        HiveOp::Stats {
            subkey,
            root_as,
            keys: key_filters,
            values: value_filters,
        } => {
            let path = hive_path(subkey);
            let destination_root = root_as
                .as_deref()
                .map(|root| {
                    RegPath::parse(root).ok_or_else(|| {
                        usage(format!(
                            "--root-as {root:?} is not an absolute registry key"
                        ))
                    })
                })
                .transpose()?;
            let (mut keys, report) = engine::export(&s.roots, &path, view, true)?;
            if let Some(destination) = &destination_root {
                keys = rebase_subtree(&keys, &hive_path(""), destination)?;
            }
            let selection = fingerprint_selection(keys, key_filters, value_filters, true)?;
            let mapped_path = destination_root
                .as_ref()
                .map(|destination| joined_reg_path(destination, subkey));
            let stats_base = mapped_path.as_ref().unwrap_or(&path);
            let (stats, conflicts) = registry_stats(selection.keys, Some(stats_base));
            let incomplete = !report.skipped.is_empty();
            if cli.global.output == OutputFormat::Json {
                println!(
                    "{{\"subkey\":{},\"rootAs\":{}, {},\"conflicts\":{},\"incomplete\":{},\"matched\":{},\
                     \"include\":[{}],\"exclude\":[{}],\"includeValues\":[{}],\
                     \"excludeValues\":[{}],\"skipped\":[{}]}}",
                    jstr(subkey),
                    destination_root
                        .as_ref()
                        .map(|root| jstr(&root.to_string()))
                        .unwrap_or_else(|| "null".into()),
                    stats_json(&stats),
                    conflicts,
                    incomplete,
                    selection.matched,
                    json_strings(&key_filters.include_keys),
                    json_strings(&key_filters.exclude_keys),
                    json_strings(&value_filters.include),
                    json_strings(&value_filters.exclude),
                    report
                        .skipped
                        .iter()
                        .map(|(path, problem)| format!(
                            "{{\"path\":{},\"problem\":{}}}",
                            jstr(&path.to_string()),
                            jstr(problem)
                        ))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            } else {
                println!(
                    "subkey         {}",
                    if subkey.is_empty() { "\\" } else { subkey }
                );
                print_stats(&stats, conflicts, incomplete);
                for (path, problem) in &report.skipped {
                    eprintln!("  skipped {path}: {problem}");
                }
                if !selection.matched {
                    eprintln!("regx: no offline-hive state matched the stats scope");
                }
            }
            Ok(if !selection.matched {
                exit::NOT_FOUND
            } else if incomplete {
                exit::PARTIAL
            } else {
                exit::OK
            })
        }

        HiveOp::Fingerprint {
            subkey,
            expect,
            root_as,
            keys: key_filters,
            values: value_filters,
        } => {
            let expected = expect
                .as_deref()
                .map(normalize_expected_sha256)
                .transpose()?;
            let path = hive_path(subkey);
            let destination_root = root_as
                .as_deref()
                .map(|root| {
                    RegPath::parse(root).ok_or_else(|| {
                        usage(format!(
                            "--root-as {root:?} is not an absolute registry key"
                        ))
                    })
                })
                .transpose()?;
            let (mut keys, report) = engine::export(&s.roots, &path, view, true)?;
            if let Some(destination) = &destination_root {
                keys = rebase_subtree(&keys, &hive_path(""), destination)?;
            }
            let selection = fingerprint_selection(keys, key_filters, value_filters, true)?;
            let result = fingerprint::calculate(selection.keys);
            let incomplete = !report.skipped.is_empty();
            let matches = expected
                .as_deref()
                .map(|expected| selection.matched && expected == result.sha256);
            if cli.global.output == OutputFormat::Json {
                println!(
                    "{{\"subkey\":{},\"rootAs\":{},\"canonicalVersion\":{},\"algorithm\":\"sha256\",\
                     \"sha256\":{},\"conflicts\":{},\"incomplete\":{},\"expected\":{},\
                     \"matches\":{},\"matched\":{},\"keys\":{},\"values\":{},\
                     \"include\":[{}],\"exclude\":[{}],\"includeValues\":[{}],\
                     \"excludeValues\":[{}],\"skipped\":[{}]}}",
                    jstr(subkey),
                    destination_root
                        .as_ref()
                        .map(|root| jstr(&root.to_string()))
                        .unwrap_or_else(|| "null".into()),
                    fingerprint::VERSION,
                    jstr(&result.sha256),
                    result.conflicts,
                    incomplete,
                    expected
                        .as_deref()
                        .map(jstr)
                        .unwrap_or_else(|| "null".into()),
                    matches.map_or_else(|| "null".into(), |value| value.to_string()),
                    selection.matched,
                    selection.key_count,
                    selection.value_count,
                    json_strings(&key_filters.include_keys),
                    json_strings(&key_filters.exclude_keys),
                    json_strings(&value_filters.include),
                    json_strings(&value_filters.exclude),
                    report
                        .skipped
                        .iter()
                        .map(|(path, problem)| format!(
                            "{{\"path\":{},\"problem\":{}}}",
                            jstr(&path.to_string()),
                            jstr(problem)
                        ))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            } else {
                println!("{}", result.sha256);
                if result.conflicts > 0 {
                    eprintln!(
                        "regx: hive {subkey}: {} conflict(s) resolved by last-write-wins",
                        result.conflicts
                    );
                }
                for (path, problem) in &report.skipped {
                    eprintln!("  skipped {path}: {problem}");
                }
                if matches == Some(false) {
                    eprintln!(
                        "regx: hive fingerprint mismatch (expected {})",
                        expected.as_deref().expect("mismatch has expected hash")
                    );
                }
                if !selection.matched {
                    eprintln!("regx: no offline-hive state matched the fingerprint scope");
                }
            }
            Ok(if !selection.matched {
                exit::NOT_FOUND
            } else if incomplete || matches == Some(false) {
                exit::PARTIAL
            } else {
                exit::OK
            })
        }

        HiveOp::Probe { subkey } => {
            let result = engine::probe(&s.roots, &hive_path(subkey), view);
            if cli.global.output == OutputFormat::Json {
                println!(
                    "{{\"subkey\":{},\"exists\":{},\"readable\":{},\"writable\":{},\
                     \"creatable\":{},\"detail\":{}}}",
                    jstr(subkey),
                    result.exists,
                    result.readable,
                    result.writable,
                    result.creatable,
                    jstr(&result.detail)
                );
            } else {
                println!(
                    "{}",
                    if subkey.is_empty() {
                        "\\"
                    } else {
                        subkey.as_str()
                    }
                );
                println!("  exists    {}", result.exists);
                println!("  readable  {}", result.readable);
                println!("  writable  {}", result.writable);
                println!("  creatable {}", result.creatable);
                if !result.detail.is_empty() {
                    println!("  detail    {}", result.detail);
                }
            }
            Ok(if result.writable || result.creatable {
                exit::OK
            } else {
                exit::ACCESS_DENIED
            })
        }

        HiveOp::Permissions { subkey } => {
            let path = hive_path(subkey);
            let (reports, failures) = read_permission_views(&s.roots, &path, &[("native", view)]);
            if cli.global.output == OutputFormat::Json {
                println!(
                    "{{\"subkey\":{},\"views\":[{}],\"failures\":[{}]}}",
                    jstr(subkey),
                    reports
                        .iter()
                        .map(permission_view_json)
                        .collect::<Vec<_>>()
                        .join(","),
                    failures
                        .iter()
                        .map(|(view, error)| format!(
                            "{{\"view\":{},\"error\":{}}}",
                            jstr(view),
                            jstr(error)
                        ))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            } else {
                println!(
                    "{}",
                    if subkey.is_empty() {
                        "\\"
                    } else {
                        subkey.as_str()
                    }
                );
                for report in &reports {
                    println!("  owner SID     {}", report.security.owner_sid);
                    println!(
                        "  inheritance   {}",
                        if report.security.inheritance_enabled {
                            "enabled"
                        } else {
                            "protected"
                        }
                    );
                    println!("  SDDL          {}", report.security.sddl);
                    println!(
                        "  effective     query={} enumerate={} notify={} set={} create-subkey={} delete={}",
                        report.query,
                        report.enumerate,
                        report.notify,
                        report.set_value,
                        report.create_subkey,
                        report.delete
                    );
                }
                for (_, error) in &failures {
                    eprintln!("  permissions failed: {error}");
                }
            }
            Ok(if reports.is_empty() {
                exit::ACCESS_DENIED
            } else if failures.is_empty() {
                exit::OK
            } else {
                exit::PARTIAL
            })
        }

        HiveOp::Search {
            subkey,
            query,
            mode,
            case_sensitive,
            field,
            include,
            exclude,
            values,
            limit,
        } => {
            let fields = field
                .iter()
                .map(|field| match field {
                    cli::SearchField::Key => search::Field::Key,
                    cli::SearchField::Name => search::Field::Name,
                    cli::SearchField::Type => search::Field::Type,
                    cli::SearchField::Data => search::Field::Data,
                })
                .collect::<Vec<_>>();
            let mode = match mode {
                cli::SearchMode::Substring => search::Mode::Substring,
                cli::SearchMode::Glob => search::Mode::Glob,
                cli::SearchMode::Regex => search::Mode::Regex,
            };
            let matcher = search::Matcher::compile(query, mode, *case_sensitive)
                .map_err(|error| usage(format!("invalid search pattern {query:?}: {error}")))?;
            let filters =
                search::Filters::compile_globs(include, exclude, *case_sensitive).map_err(usage)?;
            let value_filters =
                search::ValueFilters::compile_globs(&values.include_values, &values.exclude_values)
                    .map_err(usage)?;
            let (keys, report) = match engine::export(&s.roots, &hive_path(subkey), view, true) {
                Ok(result) => result,
                Err(error) => {
                    eprintln!("regx: {error}");
                    return Ok(reg_exit(&error));
                }
            };
            let limit = *limit as usize;
            let mut matches = search::find(
                &keys,
                &matcher,
                &fields,
                &filters,
                &value_filters,
                limit + 1,
            );
            let truncated = matches.len() > limit;
            matches.truncate(limit);
            let incomplete = !report.skipped.is_empty();
            let source = format!("{}:{}", s.path.display(), subkey);
            if cli.global.output == OutputFormat::Json {
                println!(
                    "{{\"source\":{},\"remoteComputer\":null,\"query\":{},\"mode\":{},\
                     \"caseSensitive\":{},\"include\":[{}],\"exclude\":[{}],\
                     \"includeValues\":[{}],\"excludeValues\":[{}],\"limit\":{},\
                     \"truncated\":{},\"incomplete\":{},\"matches\":[{}]}}",
                    jstr(&source),
                    jstr(query),
                    jstr(search_mode_name(mode)),
                    case_sensitive,
                    include
                        .iter()
                        .map(|item| jstr(item))
                        .collect::<Vec<_>>()
                        .join(","),
                    exclude
                        .iter()
                        .map(|item| jstr(item))
                        .collect::<Vec<_>>()
                        .join(","),
                    values
                        .include_values
                        .iter()
                        .map(|item| jstr(item))
                        .collect::<Vec<_>>()
                        .join(","),
                    values
                        .exclude_values
                        .iter()
                        .map(|item| jstr(item))
                        .collect::<Vec<_>>()
                        .join(","),
                    limit,
                    truncated,
                    incomplete,
                    search_matches_json(&matches).join(",")
                );
            } else {
                print_search_matches(&matches);
                eprintln!(
                    "regx: {} match(es){}{}",
                    matches.len(),
                    if truncated { " (limit reached)" } else { "" },
                    if incomplete { " (incomplete)" } else { "" }
                );
            }
            Ok(if incomplete {
                exit::PARTIAL
            } else if matches.is_empty() {
                exit::NOT_FOUND
            } else {
                exit::OK
            })
        }

        HiveOp::Diff {
            subkey,
            input,
            input_opts,
            strip_root,
            out,
            to,
            exit_code,
            include,
            exclude,
            values,
            summary_only,
        } => {
            let root = hive_path(subkey);
            let (actual, report) = match engine::export(&s.roots, &root, view, true) {
                Ok(result) => result,
                Err(error) => {
                    eprintln!("regx: {error}");
                    return Ok(reg_exit(&error));
                }
            };
            let outcome = read_any(cli, input, input_opts)?;
            let source_incomplete = !outcome.losses.is_empty() || !outcome.conflicts.is_empty();
            let mut desired = outcome.file;
            strip_hive_root(&mut desired, strip_root.as_deref())?;
            let (keys, conflicts) = coalesce::coalesce(std::mem::take(&mut desired.keys));
            desired.keys = keys;
            for key in &desired.keys {
                if key.path.hive != Hive::Hkcu
                    || (key.path.fold() != root.fold() && !path_is_within(&key.path, &root))
                {
                    return Err(usage(format!(
                        "desired key {} is outside hive diff subtree {}; use --strip-root or narrow the file",
                        key.path,
                        if root.sub.is_empty() { "\\" } else { &root.sub }
                    )));
                }
            }
            let filters = search::Filters::compile_globs(include, exclude, false).map_err(usage)?;
            let mut difference = filtered_diff(&actual, &desired.keys, values)?;
            difference
                .keys
                .retain(|change| filters.allows(&change.path.to_string()));
            difference
                .values
                .retain(|change| filters.allows(&change.path.to_string()));
            let incomplete =
                source_incomplete || !report.skipped.is_empty() || !conflicts.conflicts.is_empty();
            let a = format!("{}:{}", s.path.display(), subkey);
            let b = input.display().to_string();
            render_diff(
                cli,
                &difference,
                DiffRender {
                    a: &a,
                    computer_a: None,
                    b: &b,
                    computer_b: None,
                    map_a: None,
                    map_b: None,
                    incomplete,
                    summary_only: *summary_only,
                    include,
                    exclude,
                    values,
                    out: out.as_deref(),
                    to: *to,
                    exit_code: *exit_code,
                },
            )
        }

        HiveOp::Set {
            subkey,
            value,
            r#type,
            data,
            backup,
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
            enforce_hive_denies(policy, &file)?;
            let snapshot = undo::snapshot(&s.roots, &file, view);
            if !snapshot.is_complete() {
                eprintln!(
                    "regx: refusing hive set; rollback would omit {} unreadable key(s)",
                    snapshot.unreadable.len()
                );
                return Ok(exit::PARTIAL);
            }
            if !confirm(
                &cli.global,
                policy,
                &format!("Set value {}\\{} in the hive?", subkey, value),
            ) {
                eprintln!("regx: aborted");
                return Ok(exit::OK);
            }
            let undo_path = hive_undo_path(cli, "set", backup.as_deref(), None);
            write_hive_undo(&snapshot, undo_path.as_deref(), "set")?;
            let mut logger = open_audit(cli, policy, &command_line())?;
            let (applied, rollback) = apply_with_rollback(
                &s.roots,
                &file,
                Some(&snapshot),
                view,
                cli.global.dry_run,
                logger.as_mut(),
            );
            print_hive_atomic(cli, &applied, rollback.as_ref(), undo_path.as_deref())?;
            Ok(hive_atomic_exit(&applied, rollback.as_ref()))
        }

        HiveOp::Delete {
            subkey,
            value,
            recursive,
            backup,
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
                        return Err(usage("pass -r to delete a subkey and its children"));
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
            enforce_hive_denies(policy, &file)?;
            let snapshot = undo::snapshot(&s.roots, &file, view);
            if !snapshot.is_complete() {
                eprintln!(
                    "regx: refusing hive delete; rollback would omit {} unreadable key(s)",
                    snapshot.unreadable.len()
                );
                return Ok(exit::PARTIAL);
            }
            if !confirm(
                &cli.global,
                policy,
                &format!(
                    "Delete {}{} from the hive?",
                    subkey,
                    value
                        .as_ref()
                        .map(|name| format!("\\{name}"))
                        .unwrap_or_default()
                ),
            ) {
                eprintln!("regx: aborted");
                return Ok(exit::OK);
            }
            let undo_path = hive_undo_path(cli, "delete", backup.as_deref(), None);
            write_hive_undo(&snapshot, undo_path.as_deref(), "delete")?;
            let mut logger = open_audit(cli, policy, &command_line())?;
            let (applied, rollback) = apply_with_rollback(
                &s.roots,
                &file,
                Some(&snapshot),
                view,
                cli.global.dry_run,
                logger.as_mut(),
            );
            print_hive_atomic(cli, &applied, rollback.as_ref(), undo_path.as_deref())?;
            Ok(hive_atomic_exit(&applied, rollback.as_ref()))
        }

        HiveOp::Copy {
            source,
            dest,
            overwrite,
            backup,
        }
        | HiveOp::Move {
            source,
            dest,
            overwrite,
            backup,
        } => {
            let remove_source = matches!(op, HiveOp::Move { .. });
            let verb = if remove_source { "move" } else { "copy" };
            let source_path = hive_path(source);
            let dest_path = hive_path(dest);
            if source_path.fold() == dest_path.fold() {
                return Err(usage("source and destination are the same subkey"));
            }
            if remove_source && source_path.sub.is_empty() {
                return Err(usage("refusing to move or delete the hive root"));
            }
            if path_is_within(&dest_path, &source_path) {
                return Err(usage(format!(
                    "destination {} is inside source {}; recursive {verb} would consume its own output",
                    dest_path.sub, source_path.sub
                )));
            }
            let (source_keys, source_report) =
                match engine::export(&s.roots, &source_path, view, true) {
                    Ok(result) => result,
                    Err(error) => {
                        eprintln!("regx: {error}");
                        return Ok(reg_exit(&error));
                    }
                };
            if !source_report.skipped.is_empty() {
                eprintln!(
                    "regx: refusing an incomplete hive {verb}; {} source subkey(s) were unreadable",
                    source_report.skipped.len()
                );
                return Ok(exit::PARTIAL);
            }
            if engine::probe(&s.roots, &dest_path, view).exists && !overwrite {
                return Err(usage(format!(
                    "destination {} exists; pass --overwrite to merge into it",
                    dest_path.sub
                )));
            }
            let copy_file = RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: rebase_subtree(&source_keys, &source_path, &dest_path)?,
            };
            let delete_file = RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: if remove_source {
                    vec![KeyBlock {
                        path: source_path.clone(),
                        delete: true,
                        values: Vec::new(),
                        line: 0,
                    }]
                } else {
                    Vec::new()
                },
            };
            let mut combined = copy_file.clone();
            combined.keys.extend(delete_file.keys.clone());
            enforce_hive_denies(policy, &combined)?;
            let snapshot = undo::snapshot(&s.roots, &combined, view);
            if !snapshot.is_complete() {
                eprintln!(
                    "regx: refusing hive {verb}; rollback would omit {} unreadable key(s)",
                    snapshot.unreadable.len()
                );
                return Ok(exit::PARTIAL);
            }
            if !confirm(
                &cli.global,
                policy,
                &format!(
                    "{} hive subtree {} -> {}{}?",
                    if remove_source { "Move" } else { "Copy" },
                    source_path.sub,
                    dest_path.sub,
                    if *overwrite {
                        " (merge into existing destination)"
                    } else {
                        ""
                    }
                ),
            ) {
                eprintln!("regx: aborted");
                return Ok(exit::OK);
            }
            let undo_path = hive_undo_path(cli, verb, backup.as_deref(), None);
            write_hive_undo(&snapshot, undo_path.as_deref(), verb)?;
            let mut logger = open_audit(cli, policy, &command_line())?;
            let (copied, removed, rollback) = apply_copy_move_atomic(
                &s.roots,
                &copy_file,
                &delete_file,
                &snapshot,
                view,
                cli.global.dry_run,
                logger.as_mut(),
            );
            if cli.global.output == OutputFormat::Json {
                let evidence = undo_path
                    .as_deref()
                    .map(|path| undo_evidence_json(path, cli.global.dry_run))
                    .transpose()?
                    .unwrap_or_else(|| "\"undoBytes\":null,\"undoSha256\":null".into());
                println!(
                    "{{\"operation\":{},\"source\":{},\"destination\":{},\"overwrite\":{},\
                     \"dryRun\":{},\"undo\":{}, {},\"copy\":{},\"removeSource\":{},\"rolledBack\":{},\"rollback\":{}}}",
                    jstr(verb),
                    jstr(&source_path.sub),
                    jstr(&dest_path.sub),
                    overwrite,
                    cli.global.dry_run,
                    undo_path
                        .as_deref()
                        .map(|path| jstr(&path.display().to_string()))
                        .unwrap_or_else(|| "null".into()),
                    evidence,
                    apply_report_json(&copied),
                    removed
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into()),
                    rollback.is_some(),
                    rollback
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into())
                );
            } else {
                print_apply(cli, &copied);
                if let Some(removed) = &removed {
                    print_apply(cli, removed);
                }
                if let Some(rollback) = &rollback {
                    eprintln!("regx: hive {verb} rollback:");
                    print_apply(cli, rollback);
                }
            }
            let failed = !copied.failures.is_empty()
                || removed
                    .as_ref()
                    .is_some_and(|report| !report.failures.is_empty());
            Ok(if !failed {
                exit::OK
            } else if rollback
                .as_ref()
                .is_some_and(|report| !report.failures.is_empty())
            {
                exit::PARTIAL
            } else {
                exit::ACCESS_DENIED
            })
        }

        HiveOp::CopyValue {
            source,
            source_value,
            dest,
            dest_value,
            overwrite,
            backup,
        }
        | HiveOp::MoveValue {
            source,
            source_value,
            dest,
            dest_value,
            overwrite,
            backup,
        } => {
            let remove_source = matches!(op, HiveOp::MoveValue { .. });
            let verb = if remove_source {
                "move-value"
            } else {
                "copy-value"
            };
            let source_path = hive_path(source);
            let dest_path = hive_path(dest);
            let source_name = cli_value_name(source_value);
            let dest_name = cli_value_name(dest_value.as_deref().unwrap_or(source_value));
            if source_path.fold() == dest_path.fold()
                && value_name_matches(&source_name, &dest_name)
            {
                return Err(usage("source and destination are the same registry value"));
            }
            let (source_keys, source_report) = engine::export(&s.roots, &source_path, view, false)?;
            if !source_report.skipped.is_empty() {
                return Ok(exit::PARTIAL);
            }
            let Some(source_entry) = source_keys
                .first()
                .and_then(|block| {
                    block
                        .values
                        .iter()
                        .find(|entry| value_name_matches(&entry.name, &source_name))
                })
                .cloned()
            else {
                eprintln!("regx: source value {source}\\{source_name} does not exist");
                return Ok(exit::NOT_FOUND);
            };
            if engine::probe(&s.roots, &dest_path, view).exists {
                let (dest_keys, report) = engine::export(&s.roots, &dest_path, view, false)?;
                if !report.skipped.is_empty() {
                    return Ok(exit::PARTIAL);
                }
                if !overwrite
                    && dest_keys.first().is_some_and(|block| {
                        block
                            .values
                            .iter()
                            .any(|entry| value_name_matches(&entry.name, &dest_name))
                    })
                {
                    return Err(usage(format!(
                        "destination value {dest}\\{dest_name} exists; pass --overwrite"
                    )));
                }
            }
            let copy_file = RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: vec![KeyBlock {
                    path: dest_path,
                    delete: false,
                    values: vec![ValueEntry {
                        name: dest_name,
                        data: source_entry.data,
                        line: 0,
                    }],
                    line: 0,
                }],
            };
            let delete_file = RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: if remove_source {
                    vec![KeyBlock {
                        path: source_path,
                        delete: false,
                        values: vec![ValueEntry {
                            name: source_name,
                            data: RegData::Delete,
                            line: 0,
                        }],
                        line: 0,
                    }]
                } else {
                    Vec::new()
                },
            };
            let mut combined = copy_file.clone();
            combined.keys.extend(delete_file.keys.clone());
            enforce_hive_denies(policy, &combined)?;
            let snapshot = undo::snapshot(&s.roots, &combined, view);
            if !snapshot.is_complete() {
                return Ok(exit::PARTIAL);
            }
            if !confirm(
                &cli.global,
                policy,
                &format!(
                    "{} hive value {}\\{} -> {}\\{}{}?",
                    if remove_source { "Move" } else { "Copy" },
                    source,
                    source_value,
                    dest,
                    dest_value.as_deref().unwrap_or(source_value),
                    if *overwrite { " (overwrite)" } else { "" }
                ),
            ) {
                eprintln!("regx: aborted");
                return Ok(exit::OK);
            }
            let undo_path = hive_undo_path(cli, verb, backup.as_deref(), None);
            write_hive_undo(&snapshot, undo_path.as_deref(), verb)?;
            let mut logger = open_audit(cli, policy, &command_line())?;
            let (copied, removed, rollback) = apply_copy_move_atomic(
                &s.roots,
                &copy_file,
                &delete_file,
                &snapshot,
                view,
                cli.global.dry_run,
                logger.as_mut(),
            );
            if cli.global.output == OutputFormat::Json {
                let evidence = undo_path
                    .as_deref()
                    .map(|path| undo_evidence_json(path, cli.global.dry_run))
                    .transpose()?
                    .unwrap_or_else(|| "\"undoBytes\":null,\"undoSha256\":null".into());
                println!(
                    "{{\"undo\":{}, {},\"copy\":{},\"removeSource\":{},\"rolledBack\":{},\"rollback\":{}}}",
                    undo_path
                        .as_deref()
                        .map(|path| jstr(&path.display().to_string()))
                        .unwrap_or_else(|| "null".into()),
                    evidence,
                    apply_report_json(&copied),
                    removed
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into()),
                    rollback.is_some(),
                    rollback
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into())
                );
            } else {
                print_apply(cli, &copied);
                if let Some(removed) = &removed {
                    print_apply(cli, removed);
                }
                if let Some(rollback) = &rollback {
                    eprintln!("regx: value operation rollback:");
                    print_apply(cli, rollback);
                }
            }
            let failed = !copied.failures.is_empty()
                || removed
                    .as_ref()
                    .is_some_and(|report| !report.failures.is_empty());
            Ok(if !failed {
                exit::OK
            } else if rollback
                .as_ref()
                .is_some_and(|report| !report.failures.is_empty())
            {
                exit::PARTIAL
            } else {
                exit::ACCESS_DENIED
            })
        }

        HiveOp::Import {
            input,
            input_opts,
            strip_root,
            conflicts,
            backup,
        } => {
            let outcome = read_any(cli, input, input_opts)?;
            let outcome = require_lossless_input(outcome, input, "hive import")?;
            require_allowed_conflicts(&outcome, input, *conflicts, "hive import")?;
            let mut file = outcome.file;
            // `HKEY_USERS\OFFLINE\Software\X` can therefore land on
            // `Software\X` in the application hive.
            strip_hive_root(&mut file, strip_root.as_deref())?;
            let (keys, report) = coalesce::coalesce(std::mem::take(&mut file.keys));
            require_coalesce_conflicts(&report, *conflicts, "hive import")?;
            file.keys = keys;
            enforce_hive_denies(policy, &file)?;
            let snapshot = undo::snapshot(&s.roots, &file, view);
            if !snapshot.is_complete() {
                eprintln!(
                    "regx: refusing hive import; rollback would omit {} unreadable key(s)",
                    snapshot.unreadable.len()
                );
                return Ok(exit::PARTIAL);
            }
            if !confirm(
                &cli.global,
                policy,
                &format!(
                    "Import {} key block(s) from {} into the hive?",
                    file.keys.len(),
                    input.display()
                ),
            ) {
                eprintln!("regx: aborted");
                return Ok(exit::OK);
            }
            let undo_path = hive_undo_path(cli, "import", backup.as_deref(), Some(input));
            write_hive_undo(&snapshot, undo_path.as_deref(), "import")?;
            let mut logger = open_audit(cli, policy, &command_line())?;
            let (applied, rollback) = apply_with_rollback(
                &s.roots,
                &file,
                Some(&snapshot),
                view,
                cli.global.dry_run,
                logger.as_mut(),
            );
            print_hive_atomic(cli, &applied, rollback.as_ref(), undo_path.as_deref())?;
            Ok(hive_atomic_exit(&applied, rollback.as_ref()))
        }

        HiveOp::Undo { input, backup } => {
            let outcome = read_reg(input)?;
            report_diagnostics(input, &outcome, cli.global.log_level);
            if outcome.has_errors() {
                return Ok(exit::PARSE);
            }
            let mut file = outcome.file;
            strip_hive_root(&mut file, Some("HKCU"))?;
            let (keys, _) = coalesce::coalesce(std::mem::take(&mut file.keys));
            file.keys = keys;
            if file.keys.is_empty() {
                return Err(usage("hive undo snapshot contains no key blocks"));
            }
            enforce_hive_denies(policy, &file)?;
            let snapshot = undo::snapshot(&s.roots, &file, view);
            if !snapshot.is_complete() {
                eprintln!(
                    "regx: refusing hive undo; redo would omit {} unreadable key(s)",
                    snapshot.unreadable.len()
                );
                return Ok(exit::PARTIAL);
            }
            if !confirm(
                &cli.global,
                policy,
                &format!(
                    "Undo {} key block(s) from {} in the hive?",
                    file.keys.len(),
                    input.display()
                ),
            ) {
                eprintln!("regx: aborted");
                return Ok(exit::OK);
            }
            let redo_path = hive_undo_path(cli, "redo", backup.as_deref(), Some(input));
            write_hive_undo(&snapshot, redo_path.as_deref(), "undo (redo)")?;
            let mut logger = open_audit(cli, policy, &command_line())?;
            let (applied, rollback) = apply_with_rollback(
                &s.roots,
                &file,
                Some(&snapshot),
                view,
                cli.global.dry_run,
                logger.as_mut(),
            );
            if cli.global.output == OutputFormat::Json {
                let evidence = redo_path
                    .as_deref()
                    .map(|path| redo_evidence_json(path, cli.global.dry_run))
                    .transpose()?
                    .unwrap_or_else(|| "\"redoBytes\":null,\"redoSha256\":null".into());
                println!(
                    "{{\"redo\":{}, {},\"apply\":{},\"rolledBack\":{},\"rollback\":{}}}",
                    redo_path
                        .as_deref()
                        .map(|path| jstr(&path.display().to_string()))
                        .unwrap_or_else(|| "null".into()),
                    evidence,
                    apply_report_json(&applied),
                    rollback.is_some(),
                    rollback
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into())
                );
            } else {
                print_apply(cli, &applied);
                if let Some(rollback) = &rollback {
                    eprintln!("regx: offline-hive undo rollback:");
                    print_apply(cli, rollback);
                }
            }
            Ok(hive_atomic_exit(&applied, rollback.as_ref()))
        }

        HiveOp::Sync {
            input,
            input_opts,
            strip_root,
            conflicts,
            prune,
            prune_keys,
            backup,
        } => {
            let outcome = read_any(cli, input, input_opts)?;
            let outcome = require_lossless_input(outcome, input, "hive sync")?;
            require_allowed_conflicts(&outcome, input, *conflicts, "hive sync")?;
            let mut file = outcome.file;
            strip_hive_root(&mut file, strip_root.as_deref())?;
            let (keys, report) = coalesce::coalesce(std::mem::take(&mut file.keys));
            require_coalesce_conflicts(&report, *conflicts, "hive sync")?;
            file.keys = keys;
            if file.keys.is_empty() {
                return Err(usage("hive sync input contains no key blocks"));
            }
            enforce_hive_denies(policy, &file)?;
            if *prune {
                file.keys = match add_prune_deletes(&s.roots, &file.keys, view) {
                    Ok(keys) => keys,
                    Err(error) => {
                        eprintln!("regx: refusing incomplete hive value reconciliation: {error}");
                        return Ok(exit::PARTIAL);
                    }
                };
            }
            if *prune_keys {
                file.keys = match add_prune_key_deletes(&s.roots, &file.keys, view) {
                    Ok(keys) => keys,
                    Err(error) => {
                        eprintln!("regx: refusing incomplete hive key reconciliation: {error}");
                        return Ok(exit::PARTIAL);
                    }
                };
            }
            if *prune || *prune_keys {
                enforce_hive_denies(policy, &file)?;
            }
            let snapshot = undo::snapshot(&s.roots, &file, view);
            if !snapshot.is_complete() {
                eprintln!(
                    "regx: refusing hive sync; rollback would omit {} unreadable key(s)",
                    snapshot.unreadable.len()
                );
                return Ok(exit::PARTIAL);
            }
            if !confirm(
                &cli.global,
                policy,
                &format!(
                    "Synchronize {} key block(s) into the hive{}{}?",
                    file.keys.len(),
                    if *prune { " (prune values)" } else { "" },
                    if *prune_keys { " (prune subtrees)" } else { "" }
                ),
            ) {
                eprintln!("regx: aborted");
                return Ok(exit::OK);
            }
            let undo_path = hive_undo_path(cli, "sync", backup.as_deref(), Some(input));
            write_hive_undo(&snapshot, undo_path.as_deref(), "sync")?;
            let mut logger = open_audit(cli, policy, &command_line())?;
            let (applied, rollback) = apply_with_rollback(
                &s.roots,
                &file,
                Some(&snapshot),
                view,
                cli.global.dry_run,
                logger.as_mut(),
            );
            if cli.global.output == OutputFormat::Json {
                let evidence = undo_path
                    .as_deref()
                    .map(|path| undo_evidence_json(path, cli.global.dry_run))
                    .transpose()?
                    .unwrap_or_else(|| "\"undoBytes\":null,\"undoSha256\":null".into());
                println!(
                    "{{\"prune\":{},\"pruneKeys\":{},\"dryRun\":{},\"apply\":{},\
                     \"undo\":{}, {},\"rolledBack\":{},\"rollback\":{}}}",
                    prune,
                    prune_keys,
                    cli.global.dry_run,
                    apply_report_json(&applied),
                    undo_path
                        .as_deref()
                        .map(|path| jstr(&path.display().to_string()))
                        .unwrap_or_else(|| "null".into()),
                    evidence,
                    rollback.is_some(),
                    rollback
                        .as_ref()
                        .map(apply_report_json)
                        .unwrap_or_else(|| "null".into())
                );
            } else {
                print_apply(cli, &applied);
                if let Some(rollback) = &rollback {
                    eprintln!("regx: hive sync rollback:");
                    print_apply(cli, rollback);
                }
            }
            Ok(if applied.failures.is_empty() {
                exit::OK
            } else if rollback
                .as_ref()
                .is_some_and(|report| report.failures.is_empty())
            {
                exit::ACCESS_DENIED
            } else {
                exit::PARTIAL
            })
        }

        HiveOp::Batch {
            manifest,
            strip_root,
            backup,
        } => {
            let mut operations = batch::read(manifest).map_err(|error| anyhow!(error))?;
            for operation in &mut operations {
                strip_hive_root(&mut operation.file, strip_root.as_deref())?;
                let (keys, _) = coalesce::coalesce(std::mem::take(&mut operation.file.keys));
                operation.file.keys = keys;
                enforce_hive_denies(policy, &operation.file)?;
            }
            let combined = RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: operations
                    .iter()
                    .flat_map(|operation| operation.file.keys.iter().cloned())
                    .collect(),
            };
            let snapshot = undo::snapshot(&s.roots, &combined, view);
            if !snapshot.is_complete() {
                eprintln!(
                    "regx: refusing hive batch; rollback would omit {} unreadable key(s)",
                    snapshot.unreadable.len()
                );
                return Ok(exit::PARTIAL);
            }

            let backup_path = backup
                .as_deref()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| undo::default_path(manifest));
            if !confirm(
                &cli.global,
                policy,
                &format!(
                    "Apply {} batch operation(s) atomically inside this hive?",
                    operations.len()
                ),
            ) {
                eprintln!("regx: aborted");
                return Ok(exit::OK);
            }

            if !cli.global.dry_run {
                write_reg(
                    &backup_path,
                    &snapshot.file,
                    None,
                    &[
                        format!(
                            "regx shared undo snapshot for offline-hive batch: {}",
                            manifest.display()
                        ),
                        format!(
                            "{} operation(s); {} value(s) captured, {} key(s) to remove",
                            operations.len(),
                            snapshot.restored_values,
                            snapshot.new_keys.len()
                        ),
                    ],
                )?;
                eprintln!("regx: shared hive-batch undo -> {}", backup_path.display());
            }

            let mut reports = operations
                .iter()
                .map(|operation| BatchOperationReport {
                    id: operation.id.clone(),
                    attempted: false,
                    skipped: false,
                    views: Vec::new(),
                })
                .collect::<Vec<_>>();
            let mut failed_at = None;
            let mut touched = false;
            let mut logger = open_audit(cli, policy, &command_line())?;
            for (index, operation) in operations.iter().enumerate() {
                reports[index].attempted = true;
                let applied = engine::apply_audited(
                    &s.roots,
                    &operation.file,
                    view,
                    cli.global.dry_run,
                    logger.as_mut(),
                );
                touched |= applied.touched() > 0;
                let failed = !applied.failures.is_empty();
                reports[index].views.push(BatchViewReport {
                    label: "native",
                    applied,
                });
                if failed {
                    failed_at = Some(index);
                    break;
                }
            }

            let mut rollbacks = Vec::new();
            if failed_at.is_some() && touched && !cli.global.dry_run {
                let applied =
                    engine::apply_audited(&s.roots, &snapshot.file, view, false, logger.as_mut());
                rollbacks.push(BatchViewReport {
                    label: "native",
                    applied,
                });
            }
            let rollback_failed = rollbacks
                .iter()
                .any(|report| !report.applied.failures.is_empty());
            let undo_paths = vec![("native", backup_path)];
            print_batch_report(
                cli,
                manifest,
                &undo_paths,
                &reports,
                &rollbacks,
                failed_at,
                rollback_failed,
            )?;
            Ok(if rollback_failed {
                exit::PARTIAL
            } else if failed_at.is_some() {
                exit::ACCESS_DENIED
            } else {
                exit::OK
            })
        }

        HiveOp::Export {
            subkey,
            out,
            to,
            no_recursive,
            values,
            root_as,
            keys: key_filters,
        } => {
            if cli.global.output == OutputFormat::Json
                && out.is_none()
                && !matches!(to, DataFormat::Reg | DataFormat::Json)
            {
                return Err(usage(
                    "`hive export --output json` owns stdout; use --out for --to csv/pol",
                ));
            }
            let destination_root = RegPath::parse(root_as).ok_or_else(|| {
                usage(format!(
                    "--root-as {root_as:?} is not an absolute registry key"
                ))
            })?;
            let (keys, rep) =
                match engine::export(&s.roots, &hive_path(subkey), view, !no_recursive) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("regx: {e}");
                        return Ok(reg_exit(&e));
                    }
                };
            let mut file = RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: rebase_subtree(&keys, &hive_path(""), &destination_root)?,
            };
            let key_filter = filter_key_paths(&mut file, key_filters)?;
            let value_filter = filter_value_names(&mut file, values)?;
            if let Some(selection) = &value_filter {
                eprintln!(
                    "regx: value selection kept {}, omitted {} value(s) and {} key operation(s)",
                    selection.selected, selection.omitted, selection.key_operations_omitted
                );
                if file.keys.is_empty() {
                    eprintln!("regx: no offline-hive values matched the selection");
                    return Ok(if rep.skipped.is_empty() {
                        exit::NOT_FOUND
                    } else {
                        exit::PARTIAL
                    });
                }
            }
            if key_filter && file.keys.is_empty() {
                eprintln!("regx: no offline-hive keys matched the selection");
                return Ok(if rep.skipped.is_empty() {
                    exit::NOT_FOUND
                } else {
                    exit::PARTIAL
                });
            }
            let output_keys = file.keys.len();
            let output_values = file.keys.iter().map(|key| key.values.len()).sum::<usize>();
            if cli.global.output != OutputFormat::Json {
                for (p, e) in &rep.skipped {
                    eprintln!("  skipped {p}: {e}");
                }
            }
            if out.is_some() {
                validate_registry_data_format(&file, *to)?;
            }
            if cli.global.output == OutputFormat::Json {
                if let Some(path) = out {
                    if !cli.global.dry_run {
                        write_registry_data_file(path, &file, *to)?;
                    }
                    println!(
                        "{{\"hive\":{},\"subkey\":{},\"rootAs\":{},\"format\":{},\"file\":{},\
                         \"include\":[{}],\"exclude\":[{}],\"includeValues\":[{}],\
                         \"excludeValues\":[{}],\"dryRun\":{},\"keys\":{},\"values\":{},\
                         \"skipped\":{}}}",
                        jstr(&s.path.display().to_string()),
                        jstr(subkey),
                        jstr(root_as),
                        jstr(data_format_name(*to)),
                        jstr(&path.display().to_string()),
                        key_filters
                            .include_keys
                            .iter()
                            .map(|pattern| jstr(pattern))
                            .collect::<Vec<_>>()
                            .join(","),
                        key_filters
                            .exclude_keys
                            .iter()
                            .map(|pattern| jstr(pattern))
                            .collect::<Vec<_>>()
                            .join(","),
                        values
                            .include
                            .iter()
                            .map(|pattern| jstr(pattern))
                            .collect::<Vec<_>>()
                            .join(","),
                        values
                            .exclude
                            .iter()
                            .map(|pattern| jstr(pattern))
                            .collect::<Vec<_>>()
                            .join(","),
                        cli.global.dry_run,
                        output_keys,
                        output_values,
                        rep.skipped.len()
                    );
                } else {
                    println!(
                        "{{\"hive\":{},\"subkey\":{},\"rootAs\":{},\"format\":{},\
                         \"include\":[{}],\"exclude\":[{}],\"includeValues\":[{}],\
                         \"excludeValues\":[{}],\"data\":{}}}",
                        jstr(&s.path.display().to_string()),
                        jstr(subkey),
                        jstr(root_as),
                        jstr(data_format_name(*to)),
                        key_filters
                            .include_keys
                            .iter()
                            .map(|pattern| jstr(pattern))
                            .collect::<Vec<_>>()
                            .join(","),
                        key_filters
                            .exclude_keys
                            .iter()
                            .map(|pattern| jstr(pattern))
                            .collect::<Vec<_>>()
                            .join(","),
                        values
                            .include
                            .iter()
                            .map(|pattern| jstr(pattern))
                            .collect::<Vec<_>>()
                            .join(","),
                        values
                            .exclude
                            .iter()
                            .map(|pattern| jstr(pattern))
                            .collect::<Vec<_>>()
                            .join(","),
                        writer::to_json(&file)
                    );
                }
                return Ok(if rep.skipped.is_empty() {
                    exit::OK
                } else {
                    exit::PARTIAL
                });
            }
            match out {
                Some(p) if !cli.global.dry_run => {
                    write_registry_data_file(p, &file, *to)?;
                    eprintln!(
                        "regx: exported {} key(s), {} value(s) as {:?} -> {}",
                        output_keys,
                        output_values,
                        to,
                        p.display()
                    );
                }
                _ => stream_registry_data(&file, *to)?,
            }
            Ok(if rep.skipped.is_empty() {
                exit::OK
            } else {
                exit::PARTIAL
            })
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
        "Group Policy PReg binary; readable and writable with exact-state guards",
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

struct AuditJob<'a> {
    file: &'a Path,
    chain: &'a [PathBuf],
    rotate_to: Option<&'a Path>,
    write_anchor: Option<&'a Path>,
    verify_anchor: Option<&'a Path>,
    anchor_key: Option<&'a Path>,
    verbose: bool,
}

fn cmd_audit(cli: &Cli, job: AuditJob<'_>) -> anyhow::Result<i32> {
    let AuditJob {
        file,
        chain,
        rotate_to,
        write_anchor,
        verify_anchor,
        anchor_key,
        verbose,
    } = job;
    if anchor_key.is_some() && write_anchor.is_none() && verify_anchor.is_none() {
        return Err(usage(
            "--anchor-key requires --write-anchor or --verify-anchor",
        ));
    }
    let anchor_key_bytes = anchor_key
        .map(|path| {
            file_io::read_limited(path, 64 * 1024, "audit anchor key").map_err(|error| {
                anyhow!("cannot read audit anchor key {}: {error}", path.display())
            })
        })
        .transpose()?;
    if anchor_key_bytes
        .as_ref()
        .is_some_and(|key| !(32..=64 * 1024).contains(&key.len()))
    {
        return Err(usage("audit anchor key must contain 32 to 65536 raw bytes"));
    }
    if let Some(archive) = rotate_to {
        if cli.global.dry_run {
            let verification = audit::verify(file)
                .with_context(|| format!("cannot read the audit log {}", file.display()))?;
            if !verification.is_intact() {
                eprintln!("regx: refusing to rotate a broken audit log");
                return Ok(exit::PARTIAL);
            }
            if cli.global.output == OutputFormat::Json {
                println!(
                    "{{\"file\":{},\"archive\":{},\"dryRun\":true,\"records\":{},\
                     \"archiveBytes\":null,\"archiveSha256\":null,\"eligible\":true}}",
                    jstr(&file.display().to_string()),
                    jstr(&archive.display().to_string()),
                    verification.records
                );
            } else {
                eprintln!(
                    "regx: would rotate {} record(s) from {} -> {}",
                    verification.records,
                    file.display(),
                    archive.display()
                );
            }
            return Ok(exit::OK);
        }
        let rotation = audit::rotate(file, archive).with_context(|| {
            format!(
                "cannot rotate audit log {} -> {}",
                file.display(),
                archive.display()
            )
        })?;
        let (archive_bytes, archive_sha256) = sha256::hash_file(archive)
            .with_context(|| format!("cannot checksum audit archive {}", archive.display()))?;
        if cli.global.output == OutputFormat::Json {
            println!(
                "{{\"file\":{},\"archive\":{},\"dryRun\":false,\"records\":{},\
                 \"previousHash\":{},\"archiveBytes\":{},\"archiveSha256\":{},\"rotated\":true}}",
                jstr(&file.display().to_string()),
                jstr(&archive.display().to_string()),
                rotation.archived_records,
                jstr(&rotation.archived_hash),
                archive_bytes,
                jstr(&archive_sha256)
            );
        } else {
            println!(
                "rotated {} record(s): {} -> {}",
                rotation.archived_records,
                file.display(),
                archive.display()
            );
            println!("  archive sha256  {}", rotation.archived_sha256);
            println!("  previous hash   {}", rotation.archived_hash);
        }
        return Ok(exit::OK);
    }

    if !chain.is_empty() {
        let mut files = Vec::with_capacity(chain.len() + 1);
        files.push(file.to_path_buf());
        files.extend_from_slice(chain);
        let verification = audit::verify_chain(&files)?;
        if cli.global.output == OutputFormat::Json {
            let broken = verification
                .broken
                .iter()
                .map(|(index, problem)| {
                    format!(
                        "{{\"segment\":{},\"problem\":{}}}",
                        index + 1,
                        jstr(problem)
                    )
                })
                .collect::<Vec<_>>();
            println!(
                "{{\"files\":[{}],\"records\":{},\"sessions\":{},\"intact\":{},\
                 \"broken\":[{}]}}",
                files
                    .iter()
                    .map(|path| jstr(&path.display().to_string()))
                    .collect::<Vec<_>>()
                    .join(","),
                verification.records,
                verification.sessions,
                verification.is_intact(),
                broken.join(",")
            );
        } else {
            println!(
                "{} segment(s), {} record(s), {} session(s)",
                verification.files, verification.records, verification.sessions
            );
            if verification.is_intact() {
                println!("  Chain intact across every rotated segment.");
            } else {
                println!("  CHAIN BROKEN at {} point(s):", verification.broken.len());
                for (index, problem) in &verification.broken {
                    println!("    segment {}: {problem}", index + 1);
                }
            }
        }
        return Ok(if verification.is_intact() {
            exit::OK
        } else {
            exit::PARTIAL
        });
    }

    let v = audit::verify(file)
        .with_context(|| format!("cannot read the audit log {}", file.display()))?;

    if let Some(anchor_path) = write_anchor {
        if !v.is_intact() || v.records == 0 {
            eprintln!("regx: refusing to anchor an empty or broken audit log");
            return Ok(exit::PARTIAL);
        }
        if cli.global.dry_run {
            if cli.global.output == OutputFormat::Json {
                println!(
                    "{{\"file\":{},\"anchor\":{},\"dryRun\":true,\"records\":{},\
                     \"signed\":{},\"anchorBytes\":null,\"anchorSha256\":null,\"eligible\":true}}",
                    jstr(&file.display().to_string()),
                    jstr(&anchor_path.display().to_string()),
                    v.records,
                    anchor_key_bytes.is_some()
                );
            } else {
                println!(
                    "would anchor {} record(s): {} -> {}",
                    v.records,
                    file.display(),
                    anchor_path.display()
                );
            }
            return Ok(exit::OK);
        }
        let (anchor, signed) =
            audit::write_anchor_with_key(file, anchor_path, anchor_key_bytes.as_deref())
                .with_context(|| format!("cannot write audit anchor {}", anchor_path.display()))?;
        let (anchor_bytes, anchor_sha256) = sha256::hash_file(anchor_path)
            .with_context(|| format!("cannot checksum audit anchor {}", anchor_path.display()))?;
        if cli.global.output == OutputFormat::Json {
            println!(
                "{{\"file\":{},\"anchor\":{},\"dryRun\":false,\"records\":{},\
                 \"sha256\":{},\"tailHash\":{},\"signed\":{},\"anchorBytes\":{},\
                 \"anchorSha256\":{},\"written\":true}}",
                jstr(&file.display().to_string()),
                jstr(&anchor_path.display().to_string()),
                anchor.records,
                jstr(&anchor.sha256),
                jstr(&anchor.tail_hash),
                signed,
                anchor_bytes,
                jstr(&anchor_sha256)
            );
        } else {
            println!("anchor written: {}", anchor_path.display());
            println!("  records  {}", anchor.records);
            println!("  sha256   {}", anchor.sha256);
            println!("  tail     {}", anchor.tail_hash);
            println!("  signed   {}", if signed { "HMAC-SHA256" } else { "no" });
        }
        return Ok(exit::OK);
    }

    if let Some(anchor_path) = verify_anchor {
        let (expected, actual, signed) =
            match audit::verify_anchor_with_key(file, anchor_path, anchor_key_bytes.as_deref()) {
                Ok(result) => result,
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                    eprintln!(
                        "regx: audit anchor authentication failed for {}: {error}",
                        anchor_path.display()
                    );
                    return Ok(exit::PARTIAL);
                }
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                    return Err(usage(error.to_string()));
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("cannot verify audit anchor {}", anchor_path.display())
                    });
                }
            };
        let chain_intact = v.is_intact();
        let anchor_matches = expected.matches(&actual);
        let intact = chain_intact && anchor_matches;
        if cli.global.output == OutputFormat::Json {
            println!(
                "{{\"file\":{},\"anchor\":{},\"records\":{},\"chainIntact\":{},\
                 \"anchorMatches\":{},\"intact\":{},\"expectedSha256\":{},\
                 \"actualSha256\":{},\"expectedTailHash\":{},\"actualTailHash\":{},\
                 \"signed\":{},\"signatureValid\":{}}}",
                jstr(&file.display().to_string()),
                jstr(&anchor_path.display().to_string()),
                actual.records,
                chain_intact,
                anchor_matches,
                intact,
                jstr(&expected.sha256),
                jstr(&actual.sha256),
                jstr(&expected.tail_hash),
                jstr(&actual.tail_hash),
                signed,
                signed
            );
        } else {
            println!("{}", file.display());
            println!(
                "  chain    {}",
                if chain_intact { "intact" } else { "BROKEN" }
            );
            println!(
                "  anchor   {}",
                if anchor_matches {
                    "matches"
                } else {
                    "MISMATCH"
                }
            );
            println!(
                "  auth     {}",
                if signed {
                    "valid HMAC-SHA256 signature"
                } else {
                    "unsigned"
                }
            );
        }
        return Ok(if intact { exit::OK } else { exit::PARTIAL });
    }

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

fn cmd_completions(shell: CompletionShell) -> anyhow::Result<i32> {
    let generator = match shell {
        CompletionShell::Bash => clap_complete::Shell::Bash,
        CompletionShell::Elvish => clap_complete::Shell::Elvish,
        CompletionShell::Fish => clap_complete::Shell::Fish,
        CompletionShell::PowerShell => clap_complete::Shell::PowerShell,
        CompletionShell::Zsh => clap_complete::Shell::Zsh,
    };
    clap_complete::generate(
        generator,
        &mut Cli::command(),
        "regx",
        &mut std::io::stdout(),
    );
    Ok(exit::OK)
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

/// A registry-data source shared by `diff` and `search`: any supported file,
/// stdin, or a live key.
///
/// A string that parses as a registry path is treated as live. That is
/// unambiguous in practice — `HKCU\...` is not a legal relative file name — and
/// it means the same argument position accepts either kind.
#[derive(Clone)]
struct SourceData {
    keys: Vec<KeyBlock>,
    incomplete: bool,
}

fn apply_diff_mapping(
    source: &mut SourceData,
    mapping: Option<&str>,
    side: &str,
) -> anyhow::Result<()> {
    let Some(mapping) = mapping else {
        return Ok(());
    };
    let (from, to) = mapping.split_once('=').ok_or_else(|| {
        usage(format!(
            "--map-{} expects FROM=TO absolute registry keys",
            side.to_ascii_lowercase()
        ))
    })?;
    if from.is_empty() || to.is_empty() || to.contains('=') {
        return Err(usage(format!(
            "--map-{} expects exactly one FROM=TO pair",
            side.to_ascii_lowercase()
        )));
    }
    let from = RegPath::parse(from).ok_or_else(|| {
        usage(format!(
            "--map-{} source {from:?} is not an absolute registry key",
            side.to_ascii_lowercase()
        ))
    })?;
    let to = RegPath::parse(to).ok_or_else(|| {
        usage(format!(
            "--map-{} destination {to:?} is not an absolute registry key",
            side.to_ascii_lowercase()
        ))
    })?;
    source.keys = rebase_subtree(&source.keys, &from, &to).map_err(|error| {
        usage(format!(
            "--map-{} cannot be applied: {error}",
            side.to_ascii_lowercase()
        ))
    })?;
    Ok(())
}

fn filtered_diff(
    left: &[KeyBlock],
    right: &[KeyBlock],
    values: &cli::DiffValueFilterOpts,
) -> anyhow::Result<diff::Diff> {
    if values.include_values.is_empty() && values.exclude_values.is_empty() {
        return Ok(diff::compare(left, right));
    }
    let include = search::glob_matchers(&values.include_values, false).map_err(usage)?;
    let exclude = search::glob_matchers(&values.exclude_values, false).map_err(usage)?;
    let mut difference = diff::Diff {
        keys: Vec::new(),
        values: diff::compare_values(left, right),
    };
    difference.values.retain(|value| {
        let name = match &value.name {
            ValueName::Default => "@",
            ValueName::Named(name) => name,
        };
        (include.is_empty() || include.iter().any(|item| item.matches(name)))
            && !exclude.iter().any(|item| item.matches(name))
    });
    Ok(difference)
}

fn read_source_remote(
    cli: &Cli,
    spec: &str,
    iopts: &cli::InputOpts,
    computer: Option<&str>,
) -> anyhow::Result<SourceData> {
    read_source_for_view(cli, spec, iopts, computer, view_of(&cli.global))
}

fn read_source_for_view(
    cli: &Cli,
    spec: &str,
    iopts: &cli::InputOpts,
    computer: Option<&str>,
    view: View,
) -> anyhow::Result<SourceData> {
    if let Some(path) = RegPath::parse(spec) {
        let roots = roots_for_read(computer, &path)?;
        let (blocks, report) =
            engine::export(&roots, &path, view, true).map_err(|e| anyhow!("{spec}: {e}"))?;
        for (p, e) in &report.skipped {
            eprintln!("  skipped {p}: {e}");
        }
        if !report.skipped.is_empty() {
            eprintln!(
                "regx: {} subkey(s) of {spec} were unreadable; the comparison is incomplete",
                report.skipped.len()
            );
        }
        return Ok(SourceData {
            keys: blocks,
            incomplete: !report.skipped.is_empty(),
        });
    }

    if let Some(computer) = computer {
        return Err(usage(format!(
            "--computer {computer:?} requires SOURCE to be an HKLM or HKU registry path"
        )));
    }
    let file = Path::new(spec);
    if !is_stream_input(file) && !file.exists() {
        return Err(anyhow!(
            "{spec:?} is neither an existing file nor a registry path starting with a known root"
        ));
    }
    let outcome = read_any(cli, file, iopts)?;
    Ok(SourceData {
        keys: outcome.file.keys,
        incomplete: !outcome.losses.is_empty() || !outcome.conflicts.is_empty(),
    })
}

struct DiffJob<'a> {
    a: &'a str,
    computer_a: Option<&'a str>,
    b: &'a str,
    computer_b: Option<&'a str>,
    map_a: Option<&'a str>,
    map_b: Option<&'a str>,
    input: &'a cli::InputOpts,
    out: Option<&'a Path>,
    to: DataFormat,
    exit_code: bool,
    include: &'a [String],
    exclude: &'a [String],
    values: &'a cli::DiffValueFilterOpts,
    summary_only: bool,
}

fn cmd_diff(cli: &Cli, job: DiffJob<'_>) -> anyhow::Result<i32> {
    let DiffJob {
        a,
        computer_a,
        b,
        computer_b,
        map_a,
        map_b,
        input: iopts,
        out,
        to,
        exit_code,
        include,
        exclude,
        values,
        summary_only,
    } = job;
    ensure_single_stdin([Path::new(a), Path::new(b)])?;
    let filters = search::Filters::compile_globs(include, exclude, false).map_err(usage)?;
    if cli.global.view == cli::View::Both
        && (RegPath::parse(a).is_some() || RegPath::parse(b).is_some())
    {
        return cmd_diff_both(
            cli,
            DiffBothJob {
                a,
                computer_a,
                b,
                computer_b,
                map_a,
                map_b,
                input: iopts,
                out,
                to,
                exit_code,
                include,
                exclude,
                values,
                summary_only,
                filters: &filters,
            },
        );
    }
    let mut left = read_source_remote(cli, a, iopts, computer_a)?;
    let mut right = read_source_remote(cli, b, iopts, computer_b)?;
    apply_diff_mapping(&mut left, map_a, "A")?;
    apply_diff_mapping(&mut right, map_b, "B")?;
    let incomplete = left.incomplete || right.incomplete;
    let mut d = filtered_diff(&left.keys, &right.keys, values)?;
    d.keys
        .retain(|change| filters.allows(&change.path.to_string()));
    d.values
        .retain(|change| filters.allows(&change.path.to_string()));
    render_diff(
        cli,
        &d,
        DiffRender {
            a,
            computer_a,
            b,
            computer_b,
            map_a,
            map_b,
            incomplete,
            summary_only,
            include,
            exclude,
            values,
            out,
            to,
            exit_code,
        },
    )
}

struct DiffRender<'a> {
    a: &'a str,
    computer_a: Option<&'a str>,
    b: &'a str,
    computer_b: Option<&'a str>,
    map_a: Option<&'a str>,
    map_b: Option<&'a str>,
    incomplete: bool,
    summary_only: bool,
    include: &'a [String],
    exclude: &'a [String],
    values: &'a cli::DiffValueFilterOpts,
    out: Option<&'a Path>,
    to: DataFormat,
    exit_code: bool,
}

fn render_diff(cli: &Cli, difference: &diff::Diff, job: DiffRender<'_>) -> anyhow::Result<i32> {
    let DiffRender {
        a,
        computer_a,
        b,
        computer_b,
        map_a,
        map_b,
        incomplete,
        summary_only,
        include,
        exclude,
        values,
        out,
        to,
        exit_code,
    } = job;
    let (added, modified, removed) = difference.counts();
    let patch_written = out.is_some() && !incomplete && !cli.global.dry_run;
    let patch_evidence = if let Some(path) = out {
        if patch_written {
            write_registry_data_file(path, &difference.to_patch(), to)?;
        }
        artifact_evidence_json(path, !patch_written)?
    } else {
        "\"bytes\":null,\"sha256\":null".into()
    };
    if cli.global.output == OutputFormat::Json {
        let mut changes = Vec::new();
        if !summary_only {
            changes.extend(difference.keys.iter().map(|change| {
                format!(
                    "    {{\"kind\": \"key\", \"change\": {}, \"path\": {}}}",
                    jstr(&format!("{:?}", change.change).to_lowercase()),
                    jstr(&change.path.to_string())
                )
            }));
            changes.extend(difference.values.iter().map(|change| {
                format!(
                    "    {{\"kind\": \"value\", \"change\": {}, \"path\": {}, \"name\": {}, \
                     \"left\": {}, \"right\": {}, \"leftExact\": {}, \"rightExact\": {}}}",
                    jstr(&format!("{:?}", change.change).to_lowercase()),
                    jstr(&change.path.to_string()),
                    jstr(&change.name.to_string()),
                    change
                        .left
                        .as_ref()
                        .map(|value| jstr(&value.preview()))
                        .unwrap_or_else(|| "null".into()),
                    change
                        .right
                        .as_ref()
                        .map(|value| jstr(&value.preview()))
                        .unwrap_or_else(|| "null".into()),
                    diff_exact_json(&change.name, change.left.as_ref()),
                    diff_exact_json(&change.name, change.right.as_ref())
                )
            }));
        }
        println!(
            "{{\n  \"a\": {},\n  \"computerA\": {},\n  \"b\": {},\n  \"computerB\": {},\n  \
             \"mapA\": {},\n  \"mapB\": {},\n  \"incomplete\": {},\n  \"summaryOnly\": {},\n  \"include\": [{}],\n  \
             \"exclude\": [{}],\n  \"includeValues\": [{}],\n  \"excludeValues\": [{}],\n  \
             \"added\": {}, \"modified\": {}, \"removed\": {},\n  \
             \"patch\": {}, \"patchFormat\": {}, \"patchWritten\": {}, \"dryRun\": {},\n  \
             {},\n  \
             \"changes\": [\n{}\n  ]\n}}",
            jstr(a),
            computer_a.map(jstr).unwrap_or_else(|| "null".into()),
            jstr(b),
            computer_b.map(jstr).unwrap_or_else(|| "null".into()),
            map_a.map(jstr).unwrap_or_else(|| "null".into()),
            map_b.map(jstr).unwrap_or_else(|| "null".into()),
            incomplete,
            summary_only,
            include
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            exclude
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            values
                .include_values
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            values
                .exclude_values
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            added,
            modified,
            removed,
            out.map(|path| jstr(&path.display().to_string()))
                .unwrap_or_else(|| "null".into()),
            jstr(data_format_name(to)),
            patch_written,
            cli.global.dry_run,
            patch_evidence,
            changes.join(",\n")
        );
    } else if summary_only {
        println!("{added} added, {modified} modified, {removed} removed");
    } else if difference.is_empty() {
        println!("No differences.");
    } else {
        println!("--- {a}\n+++ {b}\n");
        for change in &difference.keys {
            println!("{} [{}]", change.change.sigil(), change.path);
        }
        for change in &difference.values {
            match change.change {
                diff::Change::Modified => {
                    println!("{} {}\\{}", change.change.sigil(), change.path, change.name);
                    println!(
                        "    - {}",
                        change
                            .left
                            .as_ref()
                            .map(|value| value.preview())
                            .unwrap_or_default()
                    );
                    println!(
                        "    + {}",
                        change
                            .right
                            .as_ref()
                            .map(|value| value.preview())
                            .unwrap_or_default()
                    );
                }
                _ => {
                    let shown = change.right.as_ref().or(change.left.as_ref());
                    println!(
                        "{} {}\\{} = {}",
                        change.change.sigil(),
                        change.path,
                        change.name,
                        shown.map(|value| value.preview()).unwrap_or_default()
                    );
                }
            }
        }
        println!("\n{added} added, {modified} modified, {removed} removed");
    }
    if let Some(path) = out {
        if incomplete {
            eprintln!(
                "regx: patch not written because at least one source is incomplete or ambiguous; \
                 inspect and repair the source first"
            );
        } else if cli.global.dry_run {
            eprintln!("regx: --dry-run, patch not written");
        } else {
            let patch = difference.to_patch();
            eprintln!(
                "regx: patch -> {} ({} key block(s))",
                path.display(),
                patch.keys.len()
            );
        }
    }
    Ok(if incomplete || exit_code && !difference.is_empty() {
        exit::PARTIAL
    } else {
        exit::OK
    })
}

struct DiffBothJob<'a> {
    a: &'a str,
    computer_a: Option<&'a str>,
    b: &'a str,
    computer_b: Option<&'a str>,
    map_a: Option<&'a str>,
    map_b: Option<&'a str>,
    input: &'a cli::InputOpts,
    out: Option<&'a Path>,
    to: DataFormat,
    exit_code: bool,
    include: &'a [String],
    exclude: &'a [String],
    values: &'a cli::DiffValueFilterOpts,
    summary_only: bool,
    filters: &'a search::Filters,
}

fn cmd_diff_both(cli: &Cli, job: DiffBothJob<'_>) -> anyhow::Result<i32> {
    let left_live = RegPath::parse(job.a).is_some();
    let right_live = RegPath::parse(job.b).is_some();
    let static_left = if left_live {
        None
    } else {
        Some(read_source_for_view(
            cli,
            job.a,
            job.input,
            job.computer_a,
            View::Native,
        )?)
    };
    let static_right = if right_live {
        None
    } else {
        Some(read_source_for_view(
            cli,
            job.b,
            job.input,
            job.computer_b,
            View::Native,
        )?)
    };

    struct ViewDiff {
        label: &'static str,
        difference: diff::Diff,
        incomplete: bool,
        patch: Option<PathBuf>,
    }

    let mut results = Vec::new();
    let mut failures = Vec::new();
    for (label, view) in [("32", View::Bits32), ("64", View::Bits64)] {
        let dynamic_left;
        let left = if let Some(source) = &static_left {
            source
        } else {
            dynamic_left = match read_source_for_view(cli, job.a, job.input, job.computer_a, view) {
                Ok(source) => source,
                Err(error) => {
                    failures.push((label, "a", error.to_string()));
                    continue;
                }
            };
            &dynamic_left
        };
        let dynamic_right;
        let right = if let Some(source) = &static_right {
            source
        } else {
            dynamic_right = match read_source_for_view(cli, job.b, job.input, job.computer_b, view)
            {
                Ok(source) => source,
                Err(error) => {
                    failures.push((label, "b", error.to_string()));
                    continue;
                }
            };
            &dynamic_right
        };
        let mut mapped_left = left.clone();
        let mut mapped_right = right.clone();
        apply_diff_mapping(&mut mapped_left, job.map_a, "A")?;
        apply_diff_mapping(&mut mapped_right, job.map_b, "B")?;
        let mut difference = filtered_diff(&mapped_left.keys, &mapped_right.keys, job.values)?;
        difference
            .keys
            .retain(|change| job.filters.allows(&change.path.to_string()));
        difference
            .values
            .retain(|change| job.filters.allows(&change.path.to_string()));
        let incomplete = mapped_left.incomplete || mapped_right.incomplete;
        let patch = job.out.map(|base| view_undo_path(base, label, true));
        results.push(ViewDiff {
            label,
            difference,
            incomplete,
            patch,
        });
    }

    let patches_safe = failures.is_empty() && results.iter().all(|result| !result.incomplete);
    if patches_safe && !cli.global.dry_run {
        for result in &results {
            validate_registry_data_format(&result.difference.to_patch(), job.to)?;
        }
        for result in &results {
            if let Some(destination) = &result.patch {
                write_registry_data_file(destination, &result.difference.to_patch(), job.to)?;
            }
        }
    }

    if cli.global.output == OutputFormat::Json {
        let views = results
            .iter()
            .map(|result| {
                let (added, modified, removed) = result.difference.counts();
                let changes = diff_changes_json(&result.difference, job.summary_only);
                let written = result.patch.is_some() && patches_safe && !cli.global.dry_run;
                Ok(format!(
                    "{{\"view\":{},\"incomplete\":{},\"added\":{},\"modified\":{},\
                     \"removed\":{},\"patch\":{},\"patchWritten\":{},\"dryRun\":{}, {},\
                     \"changes\":[{}]}}",
                    jstr(result.label),
                    result.incomplete,
                    added,
                    modified,
                    removed,
                    result
                        .patch
                        .as_ref()
                        .map(|path| jstr(&path.display().to_string()))
                        .unwrap_or_else(|| "null".into()),
                    written,
                    cli.global.dry_run,
                    match result.patch.as_deref() {
                        Some(path) => artifact_evidence_json(path, !written)?,
                        None => "\"bytes\":null,\"sha256\":null".into(),
                    },
                    changes.join(",")
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let failures = failures
            .iter()
            .map(|(view, side, error)| {
                format!(
                    "{{\"view\":{},\"side\":{},\"problem\":{}}}",
                    jstr(view),
                    jstr(side),
                    jstr(error)
                )
            })
            .collect::<Vec<_>>();
        println!(
            "{{\"a\":{},\"computerA\":{},\"b\":{},\"computerB\":{},\"mapA\":{},\"mapB\":{},\"summaryOnly\":{},\
             \"include\":[{}],\"exclude\":[{}],\"includeValues\":[{}],\"excludeValues\":[{}],\
             \"patchFormat\":{},\"views\":[{}],\"failures\":[{}]}}",
            jstr(job.a),
            job.computer_a.map(jstr).unwrap_or_else(|| "null".into()),
            jstr(job.b),
            job.computer_b.map(jstr).unwrap_or_else(|| "null".into()),
            job.map_a.map(jstr).unwrap_or_else(|| "null".into()),
            job.map_b.map(jstr).unwrap_or_else(|| "null".into()),
            job.summary_only,
            job.include
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            job.exclude
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            job.values
                .include_values
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            job.values
                .exclude_values
                .iter()
                .map(|pattern| jstr(pattern))
                .collect::<Vec<_>>()
                .join(","),
            jstr(data_format_name(job.to)),
            views.join(","),
            failures.join(",")
        );
    } else {
        for result in &results {
            let (added, modified, removed) = result.difference.counts();
            println!("view {}", result.label);
            if job.summary_only {
                println!("{added} added, {modified} modified, {removed} removed");
            } else {
                print_diff_changes(&result.difference, job.a, job.b);
            }
            if let Some(path) = &result.patch {
                if !patches_safe {
                    eprintln!(
                        "regx: view {} patch not written because the dual-view comparison failed or is incomplete",
                        result.label
                    );
                } else {
                    eprintln!(
                        "regx: view {} {}patch -> {}",
                        result.label,
                        if cli.global.dry_run {
                            "would write "
                        } else {
                            ""
                        },
                        path.display()
                    );
                }
            }
        }
        for (view, side, error) in &failures {
            eprintln!("regx: view {view}, side {side} failed: {error}");
        }
    }

    let incomplete = results.iter().any(|result| result.incomplete);
    let different = results.iter().any(|result| !result.difference.is_empty());
    Ok(
        if !failures.is_empty() || incomplete || job.exit_code && different {
            exit::PARTIAL
        } else {
            exit::OK
        },
    )
}

fn diff_changes_json(difference: &diff::Diff, summary_only: bool) -> Vec<String> {
    if summary_only {
        return Vec::new();
    }
    let mut items = difference
        .keys
        .iter()
        .map(|change| {
            format!(
                "{{\"kind\":\"key\",\"change\":{},\"path\":{}}}",
                jstr(&format!("{:?}", change.change).to_lowercase()),
                jstr(&change.path.to_string())
            )
        })
        .collect::<Vec<_>>();
    items.extend(difference.values.iter().map(|change| {
        format!(
            "{{\"kind\":\"value\",\"change\":{},\"path\":{},\"name\":{},\
             \"left\":{},\"right\":{},\"leftExact\":{},\"rightExact\":{}}}",
            jstr(&format!("{:?}", change.change).to_lowercase()),
            jstr(&change.path.to_string()),
            jstr(&change.name.to_string()),
            change
                .left
                .as_ref()
                .map(|value| jstr(&value.preview()))
                .unwrap_or_else(|| "null".into()),
            change
                .right
                .as_ref()
                .map(|value| jstr(&value.preview()))
                .unwrap_or_else(|| "null".into()),
            diff_exact_json(&change.name, change.left.as_ref()),
            diff_exact_json(&change.name, change.right.as_ref())
        )
    }));
    items
}

fn diff_exact_json(name: &ValueName, data: Option<&RegData>) -> String {
    data.map(|data| {
        writer::value_to_json(&ValueEntry {
            name: name.clone(),
            data: data.clone(),
            line: 0,
        })
    })
    .unwrap_or_else(|| "null".into())
}

fn print_diff_changes(difference: &diff::Diff, a: &str, b: &str) {
    if difference.is_empty() {
        println!("No differences.");
        return;
    }
    println!("--- {a}\n+++ {b}\n");
    for change in &difference.keys {
        println!("{} [{}]", change.change.sigil(), change.path);
    }
    for change in &difference.values {
        match change.change {
            diff::Change::Modified => {
                println!("{} {}\\{}", change.change.sigil(), change.path, change.name);
                println!(
                    "    - {}",
                    change
                        .left
                        .as_ref()
                        .map(|value| value.preview())
                        .unwrap_or_default()
                );
                println!(
                    "    + {}",
                    change
                        .right
                        .as_ref()
                        .map(|value| value.preview())
                        .unwrap_or_default()
                );
            }
            _ => {
                let shown = change.right.as_ref().or(change.left.as_ref());
                println!(
                    "{} {}\\{} = {}",
                    change.change.sigil(),
                    change.path,
                    change.name,
                    shown.map(|value| value.preview()).unwrap_or_default()
                );
            }
        }
    }
    let (added, modified, removed) = difference.counts();
    println!("\n{added} added, {modified} modified, {removed} removed");
}

struct SearchJob<'a> {
    source: &'a str,
    query: &'a str,
    computer: Option<&'a str>,
    mode: cli::SearchMode,
    case_sensitive: bool,
    input: &'a cli::InputOpts,
    fields: &'a [cli::SearchField],
    include: &'a [String],
    exclude: &'a [String],
    values: &'a cli::DiffValueFilterOpts,
    limit: usize,
}

fn cmd_search(cli: &Cli, job: SearchJob<'_>) -> anyhow::Result<i32> {
    let SearchJob {
        source,
        query,
        computer,
        mode,
        case_sensitive,
        input: iopts,
        fields,
        include,
        exclude,
        values,
        limit,
    } = job;
    let fields: Vec<search::Field> = fields
        .iter()
        .map(|field| match field {
            cli::SearchField::Key => search::Field::Key,
            cli::SearchField::Name => search::Field::Name,
            cli::SearchField::Type => search::Field::Type,
            cli::SearchField::Data => search::Field::Data,
        })
        .collect();
    let mode = match mode {
        cli::SearchMode::Substring => search::Mode::Substring,
        cli::SearchMode::Glob => search::Mode::Glob,
        cli::SearchMode::Regex => search::Mode::Regex,
    };
    let matcher = search::Matcher::compile(query, mode, case_sensitive)
        .map_err(|error| usage(format!("invalid search pattern {query:?}: {error}")))?;
    let filters =
        search::Filters::compile_globs(include, exclude, case_sensitive).map_err(usage)?;
    let value_filters =
        search::ValueFilters::compile_globs(&values.include_values, &values.exclude_values)
            .map_err(usage)?;
    if cli.global.view == cli::View::Both {
        if let Some(path) = RegPath::parse(source) {
            let roots = roots_for_read(computer, &path)?;
            let mut view_results = Vec::new();
            let mut failures = Vec::new();
            for (label, view) in [("32", View::Bits32), ("64", View::Bits64)] {
                let (keys, report) = match engine::export(&roots, &path, view, true) {
                    Ok(result) => result,
                    Err(error) => {
                        failures.push((label, error.to_string()));
                        continue;
                    }
                };
                let mut found = search::find(
                    &keys,
                    &matcher,
                    &fields,
                    &filters,
                    &value_filters,
                    limit + 1,
                );
                let truncated = found.len() > limit;
                found.truncate(limit);
                view_results.push((label, found, truncated, !report.skipped.is_empty()));
            }
            if cli.global.output == OutputFormat::Json {
                let views = view_results
                    .iter()
                    .map(|(label, found, truncated, incomplete)| {
                        format!(
                            "{{\"view\":{},\"truncated\":{},\"incomplete\":{},\"matches\":[{}]}}",
                            jstr(label),
                            truncated,
                            incomplete,
                            search_matches_json(found).join(",")
                        )
                    })
                    .collect::<Vec<_>>();
                let failures = failures
                    .iter()
                    .map(|(view, error)| {
                        format!("{{\"view\":{},\"problem\":{}}}", jstr(view), jstr(error))
                    })
                    .collect::<Vec<_>>();
                println!(
                    "{{\"source\":{},\"remoteComputer\":{},\"query\":{},\"mode\":{},\
                     \"caseSensitive\":{},\"include\":[{}],\"exclude\":[{}],\
                     \"includeValues\":[{}],\"excludeValues\":[{}],\"limitPerView\":{},\
                     \"views\":[{}],\"failures\":[{}]}}",
                    jstr(source),
                    computer.map(jstr).unwrap_or_else(|| "null".into()),
                    jstr(query),
                    jstr(search_mode_name(mode)),
                    case_sensitive,
                    include
                        .iter()
                        .map(|item| jstr(item))
                        .collect::<Vec<_>>()
                        .join(","),
                    exclude
                        .iter()
                        .map(|item| jstr(item))
                        .collect::<Vec<_>>()
                        .join(","),
                    values
                        .include_values
                        .iter()
                        .map(|item| jstr(item))
                        .collect::<Vec<_>>()
                        .join(","),
                    values
                        .exclude_values
                        .iter()
                        .map(|item| jstr(item))
                        .collect::<Vec<_>>()
                        .join(","),
                    limit,
                    views.join(","),
                    failures.join(",")
                );
            } else {
                for (label, found, truncated, incomplete) in &view_results {
                    println!("view {label}");
                    print_search_matches(found);
                    eprintln!(
                        "regx: view {label}: {} match(es){}{}",
                        found.len(),
                        if *truncated { " (limit reached)" } else { "" },
                        if *incomplete { " (incomplete)" } else { "" }
                    );
                }
                for (view, error) in &failures {
                    eprintln!("regx: view {view} failed: {error}");
                }
            }
            return Ok(if view_results.is_empty() {
                exit::NOT_FOUND
            } else if !failures.is_empty()
                || view_results.iter().any(|(_, _, _, incomplete)| *incomplete)
            {
                exit::PARTIAL
            } else if view_results.iter().all(|(_, found, _, _)| found.is_empty()) {
                exit::NOT_FOUND
            } else {
                exit::OK
            });
        }
    }
    let source_data = read_source_remote(cli, source, iopts, computer)?;
    let mut matches = search::find(
        &source_data.keys,
        &matcher,
        &fields,
        &filters,
        &value_filters,
        limit + 1,
    );
    let truncated = matches.len() > limit;
    matches.truncate(limit);

    if cli.global.output == OutputFormat::Json {
        let items = search_matches_json(&matches);
        println!(
            "{{\n  \"source\": {},\n  \"remoteComputer\": {},\n  \"query\": {},\n  \"mode\": {},\n  \"caseSensitive\": {case_sensitive},\n  \
             \"include\": [{}],\n  \"exclude\": [{}],\n  \"includeValues\": [{}],\n  \
             \"excludeValues\": [{}],\n  \"limit\": {limit},\n  \"truncated\": {truncated},\n  \"incomplete\": {},\n  \
             \"matches\": [\n{}\n  ]\n}}",
            jstr(source),
            computer.map(jstr).unwrap_or_else(|| "null".into()),
            jstr(query),
            jstr(search_mode_name(mode)),
            include.iter().map(|item| jstr(item)).collect::<Vec<_>>().join(","),
            exclude.iter().map(|item| jstr(item)).collect::<Vec<_>>().join(","),
            values
                .include_values
                .iter()
                .map(|item| jstr(item))
                .collect::<Vec<_>>()
                .join(","),
            values
                .exclude_values
                .iter()
                .map(|item| jstr(item))
                .collect::<Vec<_>>()
                .join(","),
            source_data.incomplete,
            items.join(",\n")
        );
    } else {
        print_search_matches(&matches);
        eprintln!(
            "regx: {} match(es){}{}",
            matches.len(),
            if truncated { " (limit reached)" } else { "" },
            if source_data.incomplete {
                " (source incomplete or ambiguous)"
            } else {
                ""
            }
        );
    }

    Ok(if source_data.incomplete {
        exit::PARTIAL
    } else if matches.is_empty() {
        exit::NOT_FOUND
    } else {
        exit::OK
    })
}

fn search_mode_name(mode: search::Mode) -> &'static str {
    match mode {
        search::Mode::Substring => "substring",
        search::Mode::Glob => "glob",
        search::Mode::Regex => "regex",
    }
}

fn search_matches_json(matches: &[search::Match]) -> Vec<String> {
    matches
        .iter()
        .map(|item| {
            format!(
                "    {{\"field\": {}, \"path\": {}, \"name\": {}, \"type\": {}, \"data\": {}, \"exact\": {}}}",
                jstr(match item.field {
                    search::Field::Key => "key",
                    search::Field::Name => "name",
                    search::Field::Type => "type",
                    search::Field::Data => "data",
                }),
                jstr(&item.path.to_string()),
                item.name
                    .as_ref()
                    .map(|name| jstr(&name.to_string()))
                    .unwrap_or_else(|| "null".into()),
                item.type_name.map(jstr).unwrap_or_else(|| "null".into()),
                item.data
                    .as_ref()
                    .map(|data| jstr(data))
                    .unwrap_or_else(|| "null".into()),
                item.exact
                    .as_ref()
                    .map(writer::value_to_json)
                    .unwrap_or_else(|| "null".into()),
            )
        })
        .collect()
}

fn print_search_matches(matches: &[search::Match]) {
    for item in matches {
        let field = match item.field {
            search::Field::Key => "key",
            search::Field::Name => "name",
            search::Field::Type => "type",
            search::Field::Data => "data",
        };
        match (&item.name, &item.type_name, &item.data) {
            (Some(name), Some(ty), Some(data)) => {
                println!("{field:<4} {}\\{}  {ty}  {data}", item.path, name);
            }
            _ => println!("{field:<4} {}", item.path),
        }
    }
}

fn cmd_watch(
    cli: &Cli,
    key: &str,
    recursive: bool,
    count: u32,
    timeout_seconds: u32,
) -> anyhow::Result<i32> {
    if cli.global.view == cli::View::Both {
        return cmd_watch_both(cli, key, recursive, count, timeout_seconds);
    }
    let path = parse_key(key)?;
    let roots = Roots::live();
    let view = view_of(&cli.global);
    let (mut before, initial) = engine::export(&roots, &path, view, recursive)?;
    if !initial.skipped.is_empty() {
        eprintln!(
            "regx: refusing an incomplete watch baseline; {} subkey(s) were unreadable",
            initial.skipped.len()
        );
        return Ok(exit::PARTIAL);
    }
    let timeout_ms = if timeout_seconds == 0 {
        u32::MAX
    } else {
        timeout_seconds.saturating_mul(1_000)
    };

    for sequence in 1..=count {
        let (root, sub) = roots.resolve(&path);
        let watched = match root.open(&sub, winreg::KEY_READ, view) {
            Ok(key) => key,
            Err(error) => {
                eprintln!("regx: {error}");
                return Ok(reg_exit(&error));
            }
        };
        if !watched.wait_for_change(recursive, timeout_ms)? {
            if cli.global.output == OutputFormat::Json {
                println!(
                    "{{\"sequence\": {sequence}, \"path\": {}, \"timedOut\": true, \
                     \"recursive\": {recursive}, \"timeoutSeconds\": {timeout_seconds}}}",
                    jstr(&path.to_string())
                );
            } else {
                eprintln!(
                    "regx: no change under {} within {} second(s)",
                    path, timeout_seconds
                );
            }
            return Ok(exit::OK);
        }

        let (after, incomplete, removed) = match engine::export(&roots, &path, view, recursive) {
            Ok((keys, report)) => (keys, !report.skipped.is_empty(), false),
            Err(error) if error.is_not_found() => (Vec::new(), false, true),
            Err(error) => {
                eprintln!("regx: {error}");
                return Ok(reg_exit(&error));
            }
        };
        let changes = diff::compare(&before, &after);
        let (added, modified, removed_count) = changes.counts();
        if cli.global.output == OutputFormat::Json {
            println!(
                "{{\"sequence\": {sequence}, \"path\": {}, \"timedOut\": false, \
                 \"recursive\": {recursive}, \"keyRemoved\": {removed}, \"incomplete\": {incomplete}, \
                 \"added\": {added}, \"modified\": {modified}, \"removed\": {removed_count}, \
                 \"changes\": {}}}",
                jstr(&path.to_string()),
                watch_changes_json(&changes)
            );
        } else {
            println!(
                "change {sequence}: {path} ({added} added, {modified} modified, {removed_count} removed)"
            );
            for key in &changes.keys {
                println!("  {} key {}", key.change.sigil(), key.path);
            }
            for value in &changes.values {
                println!(
                    "  {} value {}\\{}",
                    value.change.sigil(),
                    value.path,
                    value.name
                );
            }
        }
        if incomplete {
            eprintln!("regx: change observed, but the resulting snapshot is incomplete");
            return Ok(exit::PARTIAL);
        }
        if removed {
            return Ok(exit::OK);
        }
        before = after;
    }
    Ok(exit::OK)
}

fn cmd_watch_both(
    cli: &Cli,
    key: &str,
    recursive: bool,
    count: u32,
    timeout_seconds: u32,
) -> anyhow::Result<i32> {
    let path = parse_key(key)?;
    let roots = Roots::live();
    struct WatchView {
        label: &'static str,
        view: View,
        before: Vec<KeyBlock>,
    }
    let mut states = Vec::new();
    for (label, view) in [("32", View::Bits32), ("64", View::Bits64)] {
        let (before, report) = engine::export(&roots, &path, view, recursive)?;
        if !report.skipped.is_empty() {
            eprintln!(
                "regx: refusing an incomplete watch baseline in view {label}; \
                 {} subkey(s) were unreadable",
                report.skipped.len()
            );
            return Ok(exit::PARTIAL);
        }
        states.push(WatchView {
            label,
            view,
            before,
        });
    }
    let timeout_ms = if timeout_seconds == 0 {
        u32::MAX
    } else {
        timeout_seconds.saturating_mul(1_000)
    };

    for sequence in 1..=count {
        let mut handles = Vec::with_capacity(states.len());
        for state in &states {
            let (root, sub) = roots.resolve(&path);
            match root.open(&sub, winreg::KEY_READ, state.view) {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    eprintln!("regx: view {}: {error}", state.label);
                    return Ok(reg_exit(&error));
                }
            }
        }
        let Some(triggered_index) = winreg::wait_for_any_change(handles, recursive, timeout_ms)?
        else {
            if cli.global.output == OutputFormat::Json {
                println!(
                    "{{\"sequence\":{},\"path\":{},\"timedOut\":true,\"recursive\":{},\
                     \"timeoutSeconds\":{},\"views\":[\"32\",\"64\"]}}",
                    sequence,
                    jstr(&path.to_string()),
                    recursive,
                    timeout_seconds
                );
            } else {
                eprintln!(
                    "regx: no change in either view under {} within {} second(s)",
                    path, timeout_seconds
                );
            }
            return Ok(exit::OK);
        };
        let triggered_view = states[triggered_index].label;
        let mut view_events = Vec::new();
        let mut incomplete_any = false;
        let mut removed_any = false;
        for state in &mut states {
            let (after, incomplete, removed) =
                match engine::export(&roots, &path, state.view, recursive) {
                    Ok((keys, report)) => (keys, !report.skipped.is_empty(), false),
                    Err(error) if error.is_not_found() => (Vec::new(), false, true),
                    Err(error) => {
                        eprintln!("regx: view {}: {error}", state.label);
                        return Ok(reg_exit(&error));
                    }
                };
            let changes = diff::compare(&state.before, &after);
            let (added, modified, removed_count) = changes.counts();
            if cli.global.output == OutputFormat::Json {
                view_events.push(format!(
                    "{{\"view\":{},\"keyRemoved\":{},\"incomplete\":{},\"added\":{},\
                     \"modified\":{},\"removed\":{},\"changes\":{}}}",
                    jstr(state.label),
                    removed,
                    incomplete,
                    added,
                    modified,
                    removed_count,
                    watch_changes_json(&changes)
                ));
            } else {
                println!(
                    "view {}: {added} added, {modified} modified, {removed_count} removed{}",
                    state.label,
                    if removed { " (key removed)" } else { "" }
                );
                for key in &changes.keys {
                    println!("  {} key {}", key.change.sigil(), key.path);
                }
                for value in &changes.values {
                    println!(
                        "  {} value {}\\{}",
                        value.change.sigil(),
                        value.path,
                        value.name
                    );
                }
            }
            state.before = after;
            incomplete_any |= incomplete;
            removed_any |= removed;
        }
        if cli.global.output == OutputFormat::Json {
            println!(
                "{{\"sequence\":{},\"path\":{},\"timedOut\":false,\"recursive\":{},\
                 \"triggeredView\":{},\"views\":[{}]}}",
                sequence,
                jstr(&path.to_string()),
                recursive,
                jstr(triggered_view),
                view_events.join(",")
            );
        } else {
            eprintln!("regx: notification triggered by view {triggered_view}");
        }
        if incomplete_any {
            eprintln!("regx: change observed, but at least one resulting view is incomplete");
            return Ok(exit::PARTIAL);
        }
        if removed_any {
            return Ok(exit::OK);
        }
    }
    Ok(exit::OK)
}

fn watch_changes_json(changes: &diff::Diff) -> String {
    let mut items = changes
        .keys
        .iter()
        .map(|key| {
            format!(
                "{{\"kind\":\"key\",\"change\":{},\"path\":{}}}",
                jstr(match key.change {
                    diff::Change::Added => "added",
                    diff::Change::Modified => "modified",
                    diff::Change::Removed => "removed",
                }),
                jstr(&key.path.to_string())
            )
        })
        .collect::<Vec<_>>();
    items.extend(changes.values.iter().map(|value| {
        format!(
            "{{\"kind\":\"value\",\"change\":{},\"path\":{},\"name\":{},\
             \"leftExact\":{},\"rightExact\":{}}}",
            jstr(match value.change {
                diff::Change::Added => "added",
                diff::Change::Modified => "modified",
                diff::Change::Removed => "removed",
            }),
            jstr(&value.path.to_string()),
            jstr(&value.name.to_string()),
            diff_exact_json(&value.name, value.left.as_ref()),
            diff_exact_json(&value.name, value.right.as_ref())
        )
    }));
    format!("[{}]", items.join(","))
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
        let notes = r.notes.iter().map(|n| jstr(n)).collect::<Vec<_>>();
        let searched = r
            .searched
            .iter()
            .map(|p| jstr(&p.display().to_string()))
            .collect::<Vec<_>>();
        let items: Vec<String> = r
            .found
            .iter()
            .map(|f| {
                let risks: Vec<String> = f.risks.iter().map(|x| jstr(&format!("{x:?}"))).collect();
                let risk_details = f
                    .risks
                    .iter()
                    .map(|x| {
                        format!(
                            "{{\"kind\":{},\"explanation\":{}}}",
                            jstr(&format!("{x:?}")),
                            jstr(x.explain())
                        )
                    })
                    .collect::<Vec<_>>();
                format!(
                    "    {{\"path\": {}, \"resolvedPath\": {}, \"origin\": {}, \"rank\": {}, \
                     \"format\": {}, \"size\": {}, \"risks\": [{}], \"riskDetails\": [{}]}}",
                    jstr(&f.path.display().to_string()),
                    jstr(&f.resolved_path.display().to_string()),
                    jstr(&f.origin.label()),
                    f.origin.rank(),
                    match f.format {
                        Some(fmt) => jstr(fmt.name()),
                        None => "null".into(),
                    },
                    f.size,
                    risks.join(", "),
                    risk_details.join(", ")
                )
            })
            .collect();
        println!(
            "{{\n  \"executable\": {},\n  \"anchor\": {},\n  \"stem\": {},\n  \
             \"policy\": {},\n  \"registryPointer\": {},\n  \"strict\": {},\n  \
             \"notes\": [{}],\n  \"searched\": [{}],\n  \"risky\": {},\n  \
             \"found\": [\n{}\n  ]\n}}",
            r.exe
                .as_ref()
                .map(|p| jstr(&p.display().to_string()))
                .unwrap_or_else(|| "null".into()),
            jstr(&r.anchor.display().to_string()),
            jstr(&r.stem),
            policy,
            registry_pointer,
            strict,
            notes.join(", "),
            searched.join(", "),
            r.risky(),
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
            if f.resolved_path != f.path {
                println!("      resolved  {}", f.resolved_path.display());
            }
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
    ensure_single_stdin(files.iter().map(PathBuf::as_path))?;
    // Validate command-wide reader options before the per-file loop. A bad
    // LANGID or ADMX state is a usage error, not one parse failure per file.
    let _ = read_options(iopts)?;
    let mut worst = exit::OK;
    let mut json_reports = Vec::new();

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
            let dialect = outcome
                .source_reg_format
                .map(|format| jstr(format.header()))
                .unwrap_or_else(|| "null".into());
            let source_encoding = outcome
                .source_encoding
                .map(|encoding| jstr(&encoding.to_string()))
                .unwrap_or_else(|| "null".into());
            let conflicts = outcome
                .conflicts
                .iter()
                .map(|conflict| {
                    format!(
                        "{{\"path\":{},\"value\":{},\"firstLine\":{},\"lastLine\":{},\
                         \"old\":{},\"new\":{},\"oldExact\":{},\"newExact\":{}}}",
                        jstr(&conflict.path),
                        jstr(&conflict.value),
                        conflict.first_line,
                        conflict.last_line,
                        jstr(&conflict.old),
                        jstr(&conflict.new),
                        conflict
                            .old_exact
                            .as_ref()
                            .map(writer::value_to_json)
                            .unwrap_or_else(|| "null".into()),
                        conflict
                            .new_exact
                            .as_ref()
                            .map(writer::value_to_json)
                            .unwrap_or_else(|| "null".into())
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            json_reports.push(format!(
                "{{\"file\": {}, \"format\": {}, \"dialect\": {}, \"encoding\": {}, \
                 \"keys\": {}, \"values\": {}, \
                 \"keyDeletes\": {}, \"hives\": [{}], \"notes\": [{}], \"losses\": [{}], \
                 \"conflicts\": [{}], \"data\": {}}}",
                jstr(&input_label(path)),
                jstr(outcome.format.name()),
                dialect,
                source_encoding,
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
                outcome
                    .losses
                    .iter()
                    .map(|loss| jstr(loss))
                    .collect::<Vec<_>>()
                    .join(", "),
                conflicts,
                writer::to_json(&outcome.file),
            ));
            if !outcome.losses.is_empty() || !outcome.conflicts.is_empty() {
                worst = worst.max(exit::PARTIAL);
            }
            continue;
        }

        println!("{}", input_label(path));
        println!("  format      {}", outcome.format);
        if let Some(encoding) = outcome.source_encoding {
            println!("  encoding    {encoding}");
        }
        if let Some(format) = outcome.source_reg_format {
            println!("  dialect     {}", format.header());
        }
        println!(
            "  key blocks  {} ({deletes} whole-key delete(s))",
            outcome.file.keys.len()
        );
        println!("  values      {values}");
        println!("  hives       {}", hives.join(", "));
        for n in &outcome.notes {
            println!("  note        {n}");
        }
        for loss in &outcome.losses {
            println!("  loss        {loss}");
        }
        for conflict in &outcome.conflicts {
            println!(
                "  conflict    {}\\{}: line {} {:?} overridden by line {} {:?}",
                conflict.path,
                conflict.value,
                conflict.first_line,
                conflict.old,
                conflict.last_line,
                conflict.new
            );
        }
        if !outcome.losses.is_empty() || !outcome.conflicts.is_empty() {
            worst = worst.max(exit::PARTIAL);
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

    if cli.global.output == OutputFormat::Json {
        println!("[{}]", json_reports.join(","));
    }

    Ok(worst)
}

// ---------------------------------------------------------------------------
// self-check
// ---------------------------------------------------------------------------

fn cmd_self_check(g: &GlobalOpts, policy: &policy::Policy) -> i32 {
    let findings = selfcheck::run();

    if g.output == OutputFormat::Json {
        let mut s = String::from("{\"findings\":[\n");
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
        let pol: Vec<String> = policy.describe().iter().map(|l| jstr(l)).collect();
        s.push_str(&format!(",\"policy\":[{}]}}", pol.join(",")));
        println!("{s}");
    } else {
        println!("regx self-check");
        // What an administrator has imposed on this tool, listed alongside what
        // the environment imposes on it — both constrain what a run can do.
        for line in policy.describe() {
            println!("  [pol ] {:<16} {line}", "administration");
        }
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

#[cfg(test)]
mod main_tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn lnk_create_output_path_and_global_json_remain_unambiguous() {
        let args = [
            "regx",
            "lnk",
            "create",
            "--output",
            r"shell:Startup\App.lnk",
            "--output",
            "json",
        ]
        .into_iter()
        .map(std::ffi::OsString::from);
        let normalized = normalize_lnk_output_args(args)
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(normalized[3], "--shortcut-output");
        assert_eq!(normalized[5], "--output");
    }

    #[test]
    fn shell_tokens_are_resolved_in_any_unicode_cli_argument() {
        let args = ["regx", "lnk", "create", r"shell:Desktop\App.lnk"]
            .into_iter()
            .map(std::ffi::OsString::from);
        let resolved = resolve_shell_cli_args(args).unwrap();
        let path = resolved[3].to_string_lossy();
        assert!(!path.to_ascii_lowercase().contains("shell:desktop"));
        assert!(Path::new(path.as_ref()).is_absolute(), "{path}");
    }

    #[test]
    fn shortcut_manifest_prefers_utf8_and_accepts_utf16_bom() {
        let utf8 = "[SHORTCUT]\nDescription=Tiếng Việt ✓\n";
        assert_eq!(decode_shortcut_manifest(utf8.as_bytes()).unwrap(), utf8);
        assert_eq!(
            decode_shortcut_manifest(&encoding::encode_utf16le_bom(utf8)).unwrap(),
            utf8
        );
    }

    #[test]
    fn stream_reader_enforces_the_registry_input_limit() {
        let error = read_bounded(Cursor::new(vec![0_u8; 5]), 4, "<test-stream>").unwrap_err();
        assert!(error.to_string().contains("4-byte size limit"), "{error}");
    }

    #[test]
    fn value_selection_never_leaks_whole_key_operations() {
        let path = RegPath::parse("HKCU\\Software\\Selection").unwrap();
        let mut file = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf16Le,
            keys: vec![
                KeyBlock {
                    path: path.clone(),
                    delete: false,
                    values: vec![
                        ValueEntry {
                            name: ValueName::Default,
                            data: RegData::Sz("default".into()),
                            line: 1,
                        },
                        ValueEntry {
                            name: ValueName::Named("Keep".into()),
                            data: RegData::Sz("yes".into()),
                            line: 2,
                        },
                        ValueEntry {
                            name: ValueName::Named("KeepSecret".into()),
                            data: RegData::Sz("no".into()),
                            line: 3,
                        },
                    ],
                    line: 1,
                },
                KeyBlock {
                    path: RegPath::parse("HKCU\\Software\\Selection\\Delete").unwrap(),
                    delete: true,
                    values: vec![],
                    line: 4,
                },
                KeyBlock {
                    path: RegPath::parse("HKCU\\Software\\Selection\\Empty").unwrap(),
                    delete: false,
                    values: vec![],
                    line: 5,
                },
            ],
        };
        let report = filter_value_names(
            &mut file,
            &cli::ValueFilterOpts {
                include: vec!["@".into(), "keep*".into()],
                exclude: vec!["*secret".into()],
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(report.selected, 2);
        assert_eq!(report.omitted, 1);
        assert_eq!(report.key_operations_omitted, 2);
        assert_eq!(file.keys.len(), 1);
        assert_eq!(file.keys[0].values.len(), 2);
        assert!(!file.keys.iter().any(|key| key.delete));
    }

    #[test]
    fn plan_json_preserves_exact_data_without_weakening_redaction() {
        let name = ValueName::Named("Raw".into());
        let data = RegData::Hex {
            ty: REG_BINARY,
            bytes: vec![0x00, 0xff, 0x7a],
        };
        let clear: serde_json::Value =
            serde_json::from_str(&plan_data_json(Some(&name), Some(&data), false)).unwrap();
        assert_eq!(clear["type"], "REG_BINARY");
        assert_eq!(clear["exact"]["name"], "Raw");
        assert_eq!(clear["exact"]["typeId"], REG_BINARY);
        assert_eq!(clear["exact"]["raw"], "00 ff 7a");

        let redacted: serde_json::Value =
            serde_json::from_str(&plan_data_json(Some(&name), Some(&data), true)).unwrap();
        assert_eq!(redacted["redacted"], true);
        assert_eq!(redacted["sha256"].as_str().unwrap().len(), 64);
        assert!(redacted.get("exact").is_none());
        assert!(redacted.get("data").is_none());
    }

    #[test]
    fn copy_rebases_every_child_and_preserves_data() {
        let source = RegPath::parse("HKCU\\Software\\Source").unwrap();
        let dest = RegPath::parse("HKLM\\Software\\Dest").unwrap();
        let keys = vec![
            KeyBlock {
                path: source.clone(),
                delete: false,
                values: vec![ValueEntry {
                    name: ValueName::Named("Name".into()),
                    data: RegData::Sz("value".into()),
                    line: 1,
                }],
                line: 1,
            },
            KeyBlock {
                path: RegPath::parse("HKCU\\Software\\Source\\Child").unwrap(),
                delete: false,
                values: Vec::new(),
                line: 2,
            },
        ];
        let rebased = rebase_subtree(&keys, &source, &dest).unwrap();
        assert_eq!(
            rebased[0].path,
            RegPath::parse("HKLM\\Software\\Dest").unwrap()
        );
        assert_eq!(
            rebased[1].path,
            RegPath::parse("HKLM\\Software\\Dest\\Child").unwrap()
        );
        assert_eq!(rebased[0].values[0].data, keys[0].values[0].data);

        let wrong_hive = vec![KeyBlock {
            path: RegPath::parse("HKLM\\Software\\Source").unwrap(),
            delete: false,
            values: Vec::new(),
            line: 0,
        }];
        assert!(rebase_subtree(
            &wrong_hive,
            &RegPath::parse("HKCU").unwrap(),
            &RegPath::parse("HKCU\\Offline").unwrap()
        )
        .unwrap_err()
        .to_string()
        .contains("hives differ"));
    }

    #[test]
    fn copy_path_guard_uses_components_and_hives() {
        let source = RegPath::parse("HKCU\\Software\\Source").unwrap();
        assert!(path_is_within(
            &RegPath::parse("HKCU\\Software\\Source\\Child").unwrap(),
            &source
        ));
        assert!(!path_is_within(
            &RegPath::parse("HKCU\\Software\\SourceOther").unwrap(),
            &source
        ));
        assert!(!path_is_within(
            &RegPath::parse("HKLM\\Software\\Source\\Child").unwrap(),
            &source
        ));
        assert!(path_is_within(
            &RegPath::parse("HKCU\\Software").unwrap(),
            &RegPath::parse("HKCU").unwrap()
        ));
    }

    #[test]
    fn partial_apply_automatically_restores_its_snapshot() {
        let path =
            std::env::temp_dir().join(format!("regx-atomic-main-{}.hiv", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let session = hive::open(&path, true, true, true).expect("create private test hive");
        let good = RegPath::parse("HKCU\\Atomic\\Created").unwrap();
        let change = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf8,
            keys: vec![
                KeyBlock {
                    path: good.clone(),
                    delete: false,
                    values: vec![ValueEntry {
                        name: ValueName::Named("Name".into()),
                        data: RegData::Sz("temporary".into()),
                        line: 0,
                    }],
                    line: 0,
                },
                KeyBlock {
                    path: RegPath {
                        hive: Hive::Hkcu,
                        sub: format!("Atomic\\{}", "x".repeat(40_000)),
                    },
                    delete: false,
                    values: Vec::new(),
                    line: 0,
                },
            ],
        };
        let inverse = undo::Snapshot {
            file: RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: vec![KeyBlock {
                    path: good.clone(),
                    delete: true,
                    values: Vec::new(),
                    line: 0,
                }],
            },
            new_keys: vec![good.to_string()],
            restored_values: 0,
            unreadable: Vec::new(),
        };

        let (applied, rollback) = apply_with_rollback(
            &session.roots,
            &change,
            Some(&inverse),
            View::Native,
            false,
            None,
        );
        assert!(applied.touched() > 0);
        assert!(!applied.failures.is_empty());
        assert!(
            rollback
                .as_ref()
                .is_some_and(|report| report.failures.is_empty()),
            "{rollback:?}"
        );
        assert!(!engine::probe(&session.roots, &good, View::Native).exists);

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn partial_copy_automatically_restores_its_combined_snapshot() {
        let path =
            std::env::temp_dir().join(format!("regx-copy-atomic-{}.hiv", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let session = hive::open(&path, true, true, true).expect("create private test hive");
        let copied_path = RegPath::parse("HKCU\\Copied\\Good").unwrap();
        let copy_file = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf8,
            keys: vec![
                KeyBlock {
                    path: copied_path.clone(),
                    delete: false,
                    values: vec![ValueEntry {
                        name: ValueName::Named("State".into()),
                        data: RegData::Sz("temporary".into()),
                        line: 0,
                    }],
                    line: 0,
                },
                KeyBlock {
                    path: RegPath {
                        hive: Hive::Hkcu,
                        sub: format!("Copied\\{}", "x".repeat(40_000)),
                    },
                    delete: false,
                    values: Vec::new(),
                    line: 0,
                },
            ],
        };
        let empty_delete = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf8,
            keys: Vec::new(),
        };
        let inverse = undo::Snapshot {
            file: RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: vec![KeyBlock {
                    path: RegPath::parse("HKCU\\Copied").unwrap(),
                    delete: true,
                    values: Vec::new(),
                    line: 0,
                }],
            },
            new_keys: vec!["HKEY_CURRENT_USER\\Copied".into()],
            restored_values: 0,
            unreadable: Vec::new(),
        };

        let (copied, removed, rollback) = apply_copy_move_atomic(
            &session.roots,
            &copy_file,
            &empty_delete,
            &inverse,
            View::Native,
            false,
            None,
        );
        assert!(copied.touched() > 0);
        assert!(!copied.failures.is_empty());
        assert!(removed.is_none());
        assert!(
            rollback
                .as_ref()
                .is_some_and(|report| report.failures.is_empty()),
            "{rollback:?}"
        );
        assert!(!engine::probe(&session.roots, &copied_path, View::Native).exists);

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn key_reconciliation_deletes_only_topmost_unrepresented_branches() {
        let paths = |items: &[&str]| {
            items
                .iter()
                .map(|path| RegPath::parse(path).unwrap())
                .collect::<Vec<_>>()
        };
        let declared = paths(&[
            "HKCU\\Software\\Desired",
            "HKCU\\Software\\Desired\\Keep\\Leaf",
        ]);
        let live = paths(&[
            "HKCU\\Software\\Desired",
            "HKCU\\Software\\Desired\\Keep",
            "HKCU\\Software\\Desired\\Keep\\Leaf",
            "HKCU\\Software\\Desired\\Drop",
            "HKCU\\Software\\Desired\\Drop\\Nested",
        ]);
        assert_eq!(
            undeclared_subtree_roots(&declared, &live),
            paths(&["HKCU\\Software\\Desired\\Drop"])
        );
    }

    #[test]
    fn declared_child_is_itself_reconciled_when_listed() {
        let declared = [
            RegPath::parse("HKCU\\Software\\Desired").unwrap(),
            RegPath::parse("HKCU\\Software\\Desired\\Keep").unwrap(),
        ];
        let live = [
            RegPath::parse("HKCU\\Software\\Desired\\Keep").unwrap(),
            RegPath::parse("HKCU\\Software\\Desired\\Keep\\Extra").unwrap(),
        ];
        assert_eq!(
            undeclared_subtree_roots(&declared, &live),
            vec![RegPath::parse("HKCU\\Software\\Desired\\Keep\\Extra").unwrap()]
        );
    }

    #[test]
    fn complete_reconciliation_round_trips_on_a_private_hive() {
        let path =
            std::env::temp_dir().join(format!("regx-reconcile-main-{}.hiv", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let session = hive::open(&path, true, true, true).expect("create private test hive");
        let block = |path: &str, name: &str| KeyBlock {
            path: RegPath::parse(path).unwrap(),
            delete: false,
            values: vec![ValueEntry {
                name: ValueName::Named(name.into()),
                data: RegData::Sz("present".into()),
                line: 0,
            }],
            line: 0,
        };
        let seed = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf8,
            keys: vec![
                block("HKCU\\Desired", "RootValue"),
                block("HKCU\\Desired\\Keep", "KeepValue"),
                block("HKCU\\Desired\\Drop", "DropValue"),
            ],
        };
        assert!(
            engine::apply_audited(&session.roots, &seed, View::Native, false, None)
                .failures
                .is_empty()
        );

        let desired = vec![
            block("HKCU\\Desired", "RootValue"),
            block("HKCU\\Desired\\Keep", "KeepValue"),
        ];
        let desired = add_prune_deletes(&session.roots, &desired, View::Native).unwrap();
        let reconciled = add_prune_key_deletes(&session.roots, &desired, View::Native).unwrap();
        assert!(reconciled
            .iter()
            .any(|entry| entry.delete && entry.path.sub == "Desired\\Drop"));
        let snapshot = undo::snapshot(
            &session.roots,
            &RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: reconciled.clone(),
            },
            View::Native,
        );
        assert!(snapshot.is_complete());
        let report = engine::apply_audited(
            &session.roots,
            &RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys: reconciled,
            },
            View::Native,
            false,
            None,
        );
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert!(
            engine::probe(
                &session.roots,
                &RegPath::parse("HKCU\\Desired\\Keep").unwrap(),
                View::Native
            )
            .exists
        );
        assert!(
            !engine::probe(
                &session.roots,
                &RegPath::parse("HKCU\\Desired\\Drop").unwrap(),
                View::Native
            )
            .exists
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn watch_json_preserves_exact_value_state_on_both_sides() {
        let changes = diff::Diff {
            keys: Vec::new(),
            values: vec![diff::ValueDiff {
                path: RegPath::parse("HKCU\\Software\\Watch").unwrap(),
                name: ValueName::Named("Raw".into()),
                change: diff::Change::Modified,
                left: Some(RegData::Hex {
                    ty: 0x1234,
                    bytes: vec![0x00, 0xff],
                }),
                right: Some(RegData::Hex {
                    ty: 0x1234,
                    bytes: vec![0x01, 0xff],
                }),
            }],
        };
        let json: serde_json::Value = serde_json::from_str(&watch_changes_json(&changes)).unwrap();
        assert_eq!(json[0]["leftExact"]["typeId"], 0x1234);
        assert_eq!(json[0]["leftExact"]["raw"], "00 ff");
        assert_eq!(json[0]["rightExact"]["typeId"], 0x1234);
        assert_eq!(json[0]["rightExact"]["raw"], "01 ff");
    }
}
