//! Command-line surface. AzCopy-style: one verb, terse flags, machine-readable
//! output behind `--output json`, and exit codes a pipeline can branch on.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "regx",
    version,
    about = "Portable, non-admin Windows Registry CLI",
    long_about = "regx reads, converts and merges .reg files offline and applies them to \
                  HKEY_CURRENT_USER live. It never requests elevation: the executable is \
                  manifested asInvoker, so it never raises a UAC prompt.",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,

    /// Report how this environment constrains a portable, non-admin tool
    /// (AppLocker, SRP, WDAC, token integrity, WOW64 view) and exit.
    #[arg(long, global = true)]
    pub self_check: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Args, Debug, Clone)]
pub struct GlobalOpts {
    /// Show what would change without writing anything.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Skip confirmation prompts.
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

    /// Output format.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    pub output: OutputFormat,

    /// Registry view to use on 64-bit Windows.
    #[arg(long, global = true, value_enum, default_value_t = View::Native)]
    pub view: View,

    /// Verbosity.
    #[arg(long, global = true, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Disable ANSI colour.
    #[arg(long, global = true)]
    pub no_color: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum View {
    /// Follow the process bitness (recommended: ship x64/arm64 builds).
    Native,
    /// Force KEY_WOW64_32KEY.
    #[value(name = "32")]
    Bits32,
    /// Force KEY_WOW64_64KEY.
    #[value(name = "64")]
    Bits64,
    /// Apply to both views.
    Both,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum RedirectMode {
    /// Never rewrite paths.
    Off,
    /// Map HKLM/HKCR to HKCU where a sane per-user equivalent exists.
    Auto,
    /// Only Software\Classes, the one mapping that is reliable by design.
    ClassesOnly,
    /// Map even low-confidence paths (implies --min-confidence low).
    Force,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum MinConfidence {
    High,
    Medium,
    Low,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum OnRefuse {
    /// Drop keys that cannot be redirected and continue.
    Skip,
    /// Abort the whole operation.
    Fail,
}

/// Shared by every command that reads registry data from a file.
///
/// The format is detected from content first and the extension second, so these
/// flags are only needed when detection is wrong or when the file itself cannot
/// carry the information — a `Registry.pol` records no hive, for instance.
#[derive(Args, Debug, Clone, Default)]
pub struct InputOpts {
    /// Force the input format: reg, pol, inf, json, csv, ini.
    #[arg(long, value_name = "FORMAT")]
    pub from: Option<String>,

    /// Root hive for Registry.pol paths, which store no hive of their own.
    /// Inferred from a Machine\ or User\ path component when possible.
    #[arg(long, value_name = "HIVE")]
    pub pol_root: Option<String>,

    /// Read only this [AddReg]/[DelReg] section of an INF.
    #[arg(long, value_name = "SECTION")]
    pub inf_section: Option<String>,

    /// Which state of an ADMX policy to render. A template declares both.
    #[arg(long, value_name = "STATE", default_value = "enabled")]
    pub admx_state: String,

    /// Render only this named policy from an ADMX.
    #[arg(long, value_name = "NAME")]
    pub admx_policy: Option<String>,
}

/// Shared by every command that can rewrite HKLM paths.
#[derive(Args, Debug, Clone)]
pub struct RedirectOpts {
    #[arg(long, value_enum, default_value_t = RedirectMode::Auto)]
    pub redirect: RedirectMode,

    /// Refuse to apply mappings weaker than this.
    #[arg(long, value_enum, default_value_t = MinConfidence::Medium)]
    pub min_confidence: MinConfidence,

    /// What to do with keys that have no per-user equivalent at all.
    #[arg(long, value_enum, default_value_t = OnRefuse::Skip)]
    pub on_refuse: OnRefuse,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Merge one or more input files into the live registry.
    ///
    /// Accepts .reg, Registry.pol, .inf, .json, .csv and .ini; the format is
    /// detected per file. See `regx formats`.
    Import {
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,

        #[command(flatten)]
        input: InputOpts,

        #[command(flatten)]
        redirect: RedirectOpts,

        /// Write an undo snapshot here before applying (default: %TEMP%).
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,

        /// Do not write an undo snapshot. Not recommended.
        #[arg(long, conflicts_with = "backup")]
        no_backup: bool,
    },

    /// Export a key to a .reg file.
    Export {
        #[arg(value_name = "KEY")]
        key: String,

        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,

        /// Include subkeys.
        #[arg(long, short = 'r', default_value_t = true)]
        recursive: bool,

        /// Emit the legacy ANSI REGEDIT4 dialect.
        #[arg(long)]
        reg4: bool,
    },

    /// Read any supported format and write it out as .reg. Never touches the
    /// registry, so it is the safe way to inspect a Registry.pol or an INF.
    Convert {
        #[arg(value_name = "FILE")]
        file: PathBuf,

        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,

        #[command(flatten)]
        input: InputOpts,

        #[command(flatten)]
        redirect: RedirectOpts,

        /// Emit the legacy ANSI REGEDIT4 dialect.
        #[arg(long)]
        reg4: bool,
    },

    /// Combine several .reg files into one, last write wins.
    Merge {
        #[arg(required = true, num_args = 2.., value_name = "FILE")]
        files: Vec<PathBuf>,

        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,
    },

    /// Compare two .reg files, or a .reg file against the live registry.
    Diff {
        #[arg(value_name = "A")]
        a: String,
        #[arg(value_name = "B")]
        b: String,

        /// Write the difference as an applicable .reg patch.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },

    /// Read values from the live registry.
    Query {
        #[arg(value_name = "KEY")]
        key: String,

        /// Read a single value instead of the whole key.
        #[arg(long, short = 'v', value_name = "NAME")]
        value: Option<String>,

        #[arg(long, short = 'r')]
        recursive: bool,
    },

    /// Write a single value.
    Set {
        #[arg(value_name = "KEY")]
        key: String,

        #[arg(long, short = 'v', value_name = "NAME", default_value = "")]
        value: String,

        #[arg(long, short = 't', value_name = "TYPE", default_value = "REG_SZ")]
        r#type: String,

        #[arg(long, short = 'd', value_name = "DATA")]
        data: String,

        #[command(flatten)]
        redirect: RedirectOpts,
    },

    /// Delete a key or a single value.
    Delete {
        #[arg(value_name = "KEY")]
        key: String,

        #[arg(long, short = 'v', value_name = "NAME")]
        value: Option<String>,

        /// Delete subkeys as well.
        #[arg(long, short = 'r')]
        recursive: bool,
    },

    /// Apply an input file idempotently, optionally removing anything not declared.
    Sync {
        #[arg(value_name = "FILE")]
        file: PathBuf,

        #[command(flatten)]
        input: InputOpts,

        #[command(flatten)]
        redirect: RedirectOpts,

        /// Delete live values under the declared keys that the file does not list.
        #[arg(long)]
        prune: bool,
    },

    /// Parse and lint a .reg file. Exits non-zero on syntax errors.
    Validate {
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,

        /// Treat warnings as errors.
        #[arg(long)]
        strict: bool,

        /// Repair what can be repaired safely and rewrite the file.
        #[arg(long)]
        fix: bool,

        /// With --fix, write here instead of editing in place.
        #[arg(long, short = 'o', value_name = "FILE", requires = "fix")]
        out: Option<PathBuf>,

        /// With --fix, keep the original as FILE.bak.
        #[arg(long, requires = "fix")]
        backup: bool,
    },

    /// Report whether the current user can actually write to a key.
    Probe {
        #[arg(value_name = "KEY")]
        key: String,
    },

    /// List the input formats regx can read, and how each is detected.
    Formats,

    /// Find an application's companion configuration files the way the
    /// application itself would, and report the search order and its risks.
    ///
    /// Pass an executable to anchor on it, a directory to anchor on that, or
    /// nothing to anchor on the current directory.
    Discover {
        #[arg(value_name = "EXE_OR_DIR")]
        target: Option<PathBuf>,

        /// Also enumerate the machine's Group Policy caches and PolicyDefinitions.
        #[arg(long)]
        policy: bool,

        /// Follow the HKCU/HKLM\Software\<stem> ConfigPath convention.
        #[arg(long)]
        registry_pointer: bool,

        /// List every path probed, not just the hits.
        #[arg(long, short = 'v')]
        verbose: bool,

        /// Exit non-zero if any hit carries a security risk.
        #[arg(long)]
        strict: bool,
    },

    /// Report the format of a file and what it contains, without applying it.
    Inspect {
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,

        #[command(flatten)]
        input: InputOpts,
    },

    /// Work on an offline hive file via RegLoadAppKey - no administrator rights.
    ///
    /// The mount is process-scoped: it exists only while this command runs.
    /// Use `exec` to perform several operations under a single mount.
    Hive {
        /// The hive file (NTUSER.DAT, UsrClass.dat, or an application hive).
        #[arg(value_name = "HIVEFILE")]
        file: PathBuf,

        #[command(subcommand)]
        op: HiveOp,

        /// Create the hive file if it does not exist.
        #[arg(long, global = true)]
        create: bool,

        /// Hold the hive exclusively for this process (REG_PROCESS_APPKEY).
        #[arg(long, global = true)]
        exclusive: bool,
    },
}

/// Wrapper so a single `hive exec -c "..."` line can be parsed with the exact
/// same grammar as the top-level `hive` subcommands - one definition, no drift.
#[derive(Parser, Debug)]
#[command(name = "", no_binary_name = true, disable_help_flag = true)]
pub struct HiveOpLine {
    #[command(subcommand)]
    pub op: HiveOp,
}

#[derive(Subcommand, Debug, Clone)]
pub enum HiveOp {
    /// Report size, signature, and whether the hive can be mounted read/write.
    Info,

    /// List subkeys.
    Ls {
        #[arg(value_name = "SUBKEY", default_value = "")]
        subkey: String,
        #[arg(long, short = 'r')]
        recursive: bool,
    },

    /// Print values under a subkey.
    Query {
        #[arg(value_name = "SUBKEY", default_value = "")]
        subkey: String,
        #[arg(long, short = 'v', value_name = "NAME")]
        value: Option<String>,
        #[arg(long, short = 'r')]
        recursive: bool,
    },

    /// Write one value into the hive.
    Set {
        #[arg(value_name = "SUBKEY")]
        subkey: String,
        #[arg(long, short = 'v', value_name = "NAME", default_value = "")]
        value: String,
        #[arg(long, short = 't', value_name = "TYPE", default_value = "REG_SZ")]
        r#type: String,
        #[arg(long, short = 'd', value_name = "DATA", default_value = "")]
        data: String,
    },

    /// Delete a subkey or a single value.
    Delete {
        #[arg(value_name = "SUBKEY")]
        subkey: String,
        #[arg(long, short = 'v', value_name = "NAME")]
        value: Option<String>,
        #[arg(long, short = 'r')]
        recursive: bool,
    },

    /// Merge a .reg file into the hive.
    Import {
        #[arg(value_name = "FILE")]
        input: PathBuf,
        /// Drop this leading path from every key before applying, e.g.
        /// --strip-root "HKEY_CURRENT_USER".
        #[arg(long, value_name = "PREFIX")]
        strip_root: Option<String>,
    },

    /// Export part of the hive to a .reg file.
    Export {
        #[arg(value_name = "SUBKEY", default_value = "")]
        subkey: String,
        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,
        /// Root label written into the .reg file. A .reg file has no syntax for
        /// "app hive", so an offline export must be re-rooted somewhere.
        #[arg(long, value_name = "LABEL", default_value = "HKEY_CURRENT_USER")]
        root_as: String,
    },

    /// Run several operations under one mount. This is the working equivalent of
    /// a mount / set / unmount script, which cannot span separate processes.
    Exec {
        /// An operation, e.g. -c "set Software\MyApp -v License -d OK".
        /// Repeatable; runs in order.
        #[arg(long, short = 'c', value_name = "OP")]
        cmd: Vec<String>,

        /// Read operations from a file, one per line; `#` starts a comment.
        #[arg(long, value_name = "FILE")]
        script: Option<PathBuf>,

        /// Keep going after a failing operation.
        #[arg(long)]
        keep_going: bool,
    },
}

/// Exit codes, stable across releases so scripts can branch on them.
pub mod exit {
    pub const OK: i32 = 0;
    pub const USAGE: i32 = 2;
    pub const PARSE: i32 = 3;
    pub const ACCESS_DENIED: i32 = 4;
    pub const PARTIAL: i32 = 5;
    pub const REDIRECT_REFUSED: i32 = 6;
    pub const IO: i32 = 7;
    pub const NOT_FOUND: i32 = 8;
}
