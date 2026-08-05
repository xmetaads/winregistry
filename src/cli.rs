//! Command-line surface. AzCopy-style: one verb, terse flags, machine-readable
//! output behind `--output json`, and exit codes a pipeline can branch on.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Build provenance, shown by `regx --version`.
///
/// An operator who finds this executable on a machine can tell which source
/// produced it without trusting the file name.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncommit:  ",
    env!("REGX_COMMIT"),
    "\ndate:    ",
    env!("REGX_COMMIT_DATE"),
    "\ntarget:  ",
    env!("REGX_TARGET"),
    "\nlicence: MIT",
    "\nsource:  https://github.com/xmetaads/winregistry",
);

#[derive(Parser, Debug)]
#[command(
    name = "regx",
    version,
    long_version = LONG_VERSION,
    about = "Portable, non-admin Windows Registry and Shell automation CLI",
    long_about = "regx reads, converts and merges registry data, applies it to \
                  HKEY_CURRENT_USER, resolves Windows Shell Known Folders, and manages native \
                  .lnk shortcuts. It never requests elevation: the executable is manifested \
                  asInvoker, so it never raises a UAC prompt.",
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

    /// Append a tamper-evident record of every registry change to this file.
    /// Also settable as REGX_AUDIT_LOG so it can be enforced machine-wide.
    #[arg(long, global = true, value_name = "FILE", env = "REGX_AUDIT_LOG")]
    pub audit_log: Option<PathBuf>,

    /// Record the SHA-256 of each value instead of the value itself. Registry
    /// data holds licence keys and tokens; without this the log becomes a
    /// secret in its own right.
    #[arg(long, global = true, env = "REGX_AUDIT_REDACT")]
    pub audit_redact: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum ShortcutStyle {
    /// Open the target normally.
    Normal,
    /// Start minimized without activating a popup window.
    Hidden,
    /// Start minimized without activating a popup window.
    Minimized,
}

/// Registry-data serialization used by `convert`.
#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum DataFormat {
    Reg,
    Json,
    Csv,
    Pol,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum MergeConflictPolicy {
    /// Keep the later key/value state and report the override.
    LastWins,
    /// Refuse output on different value data or key create/delete state.
    Error,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum SearchField {
    Key,
    Name,
    Type,
    Data,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum SearchMode {
    Substring,
    Glob,
    Regex,
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
    /// Registry commands keep per-view reads, artifacts, undo, and rollback
    /// separate instead of silently choosing one view.
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
pub enum CompletionShell {
    Bash,
    Elvish,
    Fish,
    #[value(name = "powershell")]
    PowerShell,
    Zsh,
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
    /// Force the input format: reg, pol, admx, gpp, inf, json, csv, ini.
    #[arg(long, value_name = "FORMAT")]
    pub from: Option<String>,

    /// Root hive for Registry.pol paths, which store no hive of their own.
    /// Inferred from a Machine\ or User\ path component when possible.
    #[arg(long, value_name = "HIVE")]
    pub pol_root: Option<String>,

    /// Read only this [AddReg]/[DelReg] section of an INF.
    #[arg(long, value_name = "SECTION")]
    pub inf_section: Option<String>,

    /// Select a four-hex-digit INF [Strings.LanguageID] locale.
    /// Defaults to the undecorated [Strings] section.
    #[arg(long, value_name = "LANGID")]
    pub inf_language: Option<String>,

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

#[derive(Args, Debug, Default, Clone)]
pub struct ValueFilterOpts {
    /// Include value names matching this glob; repeat to OR patterns. Use @ for the default value.
    #[arg(long = "value", value_name = "GLOB")]
    pub include: Vec<String>,

    /// Exclude value names matching this glob; repeat to OR patterns.
    #[arg(long = "exclude-value", value_name = "GLOB")]
    pub exclude: Vec<String>,
}

#[derive(Args, Debug, Default, Clone)]
pub struct KeyFilterOpts {
    /// Include key paths matching this glob; repeat to OR patterns.
    #[arg(long = "include", value_name = "GLOB")]
    pub include_keys: Vec<String>,

    /// Exclude key paths matching this glob; repeat to OR patterns.
    #[arg(long = "exclude", value_name = "GLOB")]
    pub exclude_keys: Vec<String>,
}

#[derive(Args, Debug, Default, Clone)]
pub struct DiffValueFilterOpts {
    /// Include value names matching this glob; repeat to OR patterns. Use @ for the default value.
    #[arg(long = "value", value_name = "GLOB")]
    pub include_values: Vec<String>,

    /// Exclude value names matching this glob; repeat to OR patterns.
    #[arg(long = "exclude-value", value_name = "GLOB")]
    pub exclude_values: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create, inspect, delete, or batch-apply native Windows Shell shortcuts.
    ///
    /// Path-bearing fields resolve shell:Startup, shell:Desktop, and
    /// shell:Programs through SHGetKnownFolderPath. Shortcut files are handled
    /// through IShellLinkW/IPersistFile; no external shell is invoked.
    Lnk {
        #[command(subcommand)]
        op: LnkOp,
    },

    /// Merge one or more input files into the live registry.
    ///
    /// Accepts .reg, Registry.pol, ADMX/ADML, Group Policy Preferences XML,
    /// .inf, .json, .csv and .ini; the format is detected per file. See
    /// `regx formats`.
    Import {
        /// Input files. Use `-` once for stdin or `pipe:NAME` for a Windows named
        /// pipe; stream imports require -y.
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,

        #[command(flatten)]
        input: InputOpts,

        #[command(flatten)]
        redirect: RedirectOpts,

        #[command(flatten)]
        values: ValueFilterOpts,

        /// How to handle conflicting key state or value data.
        #[arg(long, value_enum, default_value_t = MergeConflictPolicy::LastWins)]
        conflicts: MergeConflictPolicy,

        /// Write an undo snapshot here before applying (default: %TEMP%).
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,

        /// Do not write an undo snapshot. Not recommended.
        #[arg(long, conflicts_with = "backup")]
        no_backup: bool,
    },

    /// Revert a previous mutation from its undo snapshot.
    ///
    /// A redo snapshot is written before applying, so the undo itself remains
    /// reversible. With `--view both`, FILE may be the bundle base or either
    /// generated `.32.reg` / `.64.reg` member.
    Undo {
        /// Undo snapshot or paired snapshot bundle.
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Write the redo snapshot here (default: beside FILE).
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Export a key to REG, JSON, CSV, or Registry.pol.
    Export {
        #[arg(value_name = "KEY")]
        key: String,

        /// Read HKLM or HKU from this remote Windows computer.
        #[arg(long, value_name = "COMPUTER")]
        computer: Option<String>,

        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,

        /// Output registry-data format.
        #[arg(long, value_enum, default_value_t = DataFormat::Reg)]
        to: DataFormat,

        /// Rebase the exported key and descendants under this destination key.
        #[arg(long, value_name = "KEY")]
        root_as: Option<String>,

        /// Include subkeys.
        #[arg(long, short = 'r', default_value_t = true, hide = true)]
        recursive: bool,

        /// Export only this key, not its descendants.
        #[arg(long)]
        no_recursive: bool,

        /// Emit the legacy ANSI REGEDIT4 dialect.
        #[arg(long)]
        reg4: bool,

        #[command(flatten)]
        keys: KeyFilterOpts,

        #[command(flatten)]
        values: ValueFilterOpts,
    },

    /// Read any supported format and write it out as .reg. Never touches the
    /// registry, so it is the safe way to inspect a Registry.pol or an INF.
    Convert {
        /// Input file, `-` for stdin, or `pipe:NAME` for a Windows named pipe.
        #[arg(value_name = "FILE")]
        file: PathBuf,

        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,

        #[command(flatten)]
        input: InputOpts,

        #[command(flatten)]
        redirect: RedirectOpts,

        /// Output registry-data format: reg, json, csv, or binary Registry.pol.
        #[arg(long, value_enum, default_value_t = DataFormat::Reg)]
        to: DataFormat,

        /// How to handle conflicting key state or value data.
        #[arg(long, value_enum, default_value_t = MergeConflictPolicy::LastWins)]
        conflicts: MergeConflictPolicy,

        /// Emit the legacy ANSI REGEDIT4 dialect.
        #[arg(long)]
        reg4: bool,
    },

    /// Combine several registry-data files into one output, last write wins.
    ///
    /// Each input may use any format accepted by `regx formats`; semantic
    /// losses fail closed before output.
    Merge {
        /// Input files. Use `-` once for stdin; `pipe:NAME` reads a Windows named pipe.
        #[arg(required = true, num_args = 2.., value_name = "FILE")]
        files: Vec<PathBuf>,

        #[command(flatten)]
        input: InputOpts,

        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,

        /// Output registry-data format: reg, json, csv, or binary Registry.pol.
        #[arg(long, value_enum, default_value_t = DataFormat::Reg)]
        to: DataFormat,

        /// How to handle conflicting key state or value data.
        #[arg(long, value_enum, default_value_t = MergeConflictPolicy::LastWins)]
        conflicts: MergeConflictPolicy,

        /// Emit the legacy ANSI REGEDIT4 dialect.
        #[arg(long)]
        reg4: bool,
    },

    /// Compare two sources of registry data and emit the patch between them.
    ///
    /// Each side is either a file in any supported format or a live registry
    /// key path, so file-vs-file, file-vs-live and live-vs-live all work.
    /// The patch turns A into B: a drift report is also the fix.
    Diff {
        /// Baseline: a file, `-` for stdin, `pipe:NAME`, or a live registry key.
        #[arg(value_name = "A")]
        a: String,

        /// Read side A as HKLM/HKU from this remote Windows computer.
        #[arg(long, value_name = "COMPUTER")]
        computer_a: Option<String>,

        /// Comparison target, same forms as A. Only one side may be stdin.
        #[arg(value_name = "B")]
        b: String,

        /// Read side B as HKLM/HKU from this remote Windows computer.
        #[arg(long, value_name = "COMPUTER")]
        computer_b: Option<String>,

        /// Rebase side A before comparison, as FROM=TO absolute registry keys.
        #[arg(long, value_name = "FROM=TO")]
        map_a: Option<String>,

        /// Rebase side B before comparison, as FROM=TO absolute registry keys.
        #[arg(long, value_name = "FROM=TO")]
        map_b: Option<String>,

        #[command(flatten)]
        input: InputOpts,

        /// Write the difference as an applicable registry-data patch.
        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,

        /// Registry-data format for the patch written by --out.
        #[arg(long, value_enum, default_value_t = DataFormat::Reg, requires = "out")]
        to: DataFormat,

        /// Exit 5 when the two sides differ, for use as a drift gate.
        #[arg(long)]
        exit_code: bool,

        /// Compare only key paths matching this glob; repeat to OR patterns.
        #[arg(long, value_name = "PATTERN")]
        include: Vec<String>,

        /// Omit key paths matching this glob; repeat to OR patterns.
        #[arg(long, value_name = "PATTERN")]
        exclude: Vec<String>,

        #[command(flatten)]
        values: DiffValueFilterOpts,

        /// Emit counts without individual changes; patch output remains complete.
        #[arg(long)]
        summary_only: bool,
    },

    /// Search keys and values in a file, stream, or the live registry.
    Search {
        /// File, `-` for stdin, `pipe:NAME`, or a live key like HKCU\Software.
        #[arg(value_name = "SOURCE")]
        source: String,

        /// Pattern to find; substring by default, or select glob/regex.
        #[arg(value_name = "QUERY")]
        query: String,

        /// Treat SOURCE as HKLM/HKU on this remote Windows computer.
        #[arg(long, value_name = "COMPUTER")]
        computer: Option<String>,

        /// How QUERY is interpreted; include/exclude patterns are always globs.
        #[arg(long = "match", value_enum, default_value_t = SearchMode::Substring)]
        mode: SearchMode,

        /// Match case exactly instead of using case-insensitive matching.
        #[arg(long)]
        case_sensitive: bool,

        #[command(flatten)]
        input: InputOpts,

        /// Restrict matching to one or more fields; defaults to all fields.
        #[arg(long, value_enum, value_name = "FIELD")]
        field: Vec<SearchField>,

        /// Search only key paths matching this glob; repeat to OR patterns.
        #[arg(long, value_name = "PATTERN")]
        include: Vec<String>,

        /// Omit key paths matching this glob; repeat to OR patterns.
        #[arg(long, value_name = "PATTERN")]
        exclude: Vec<String>,

        #[command(flatten)]
        values: DiffValueFilterOpts,

        /// Stop after this many matches.
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
    },

    /// Wait for live registry changes without polling.
    Watch {
        #[arg(value_name = "KEY")]
        key: String,

        /// Watch only the key itself, not its descendants.
        #[arg(long)]
        no_recursive: bool,

        /// Stop after this many change notifications.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
        count: u32,

        /// Stop after this many seconds without a change; zero waits forever.
        #[arg(long, default_value_t = 0)]
        timeout: u32,
    },

    /// Resolve an import or sync into exact mutations without writing anything.
    Plan {
        /// Input files. Use `-` for stdin or `pipe:NAME` for a Windows named pipe.
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,

        #[command(flatten)]
        input: InputOpts,

        #[command(flatten)]
        redirect: RedirectOpts,

        /// How to handle conflicting key state or value data.
        #[arg(long, value_enum, default_value_t = MergeConflictPolicy::LastWins)]
        conflicts: MergeConflictPolicy,

        /// Include deletes for live values absent from the declared keys.
        #[arg(long)]
        prune: bool,

        /// Include recursive deletes for live subtrees absent from the declared tree.
        #[arg(long, requires = "prune")]
        prune_keys: bool,

        /// Save a digest-bound artifact that `apply-plan` can verify and apply.
        #[arg(long, value_name = "FILE", conflicts_with = "dry_run")]
        save: Option<PathBuf>,
    },

    /// Apply a saved plan only if its sources and live state still match.
    ApplyPlan {
        #[arg(value_name = "PLAN")]
        plan: PathBuf,

        /// Write the rollback snapshot here instead of beside the plan.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Apply a versioned JSON batch atomically with per-operation outcomes.
    Batch {
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,

        #[command(flatten)]
        redirect: RedirectOpts,

        /// How to handle conflicts introduced inside an operation by redirection.
        #[arg(long, value_enum, default_value_t = MergeConflictPolicy::LastWins)]
        conflicts: MergeConflictPolicy,

        /// Base path for the shared undo bundle.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Copy a live registry subtree to another key.
    Copy {
        #[arg(value_name = "SOURCE")]
        source: String,

        /// Read SOURCE from HKLM/HKU on this computer; destination remains local.
        #[arg(long, value_name = "COMPUTER")]
        source_computer: Option<String>,

        #[arg(value_name = "DEST")]
        dest: String,

        /// Merge into an existing destination instead of refusing it.
        #[arg(long)]
        overwrite: bool,

        /// Write the undo snapshot here instead of the temporary directory.
        #[arg(long, value_name = "FILE", conflicts_with = "save_plan")]
        backup: Option<PathBuf>,

        /// Save a digest-bound collision preview instead of changing the registry.
        #[arg(long, value_name = "FILE", conflicts_with = "dry_run")]
        save_plan: Option<PathBuf>,
    },

    /// Move or rename a live registry subtree.
    Move {
        #[arg(value_name = "SOURCE")]
        source: String,

        #[arg(value_name = "DEST")]
        dest: String,

        /// Merge into an existing destination instead of refusing it.
        #[arg(long)]
        overwrite: bool,

        /// Write the undo snapshot here instead of the temporary directory.
        #[arg(long, value_name = "FILE", conflicts_with = "save_plan")]
        backup: Option<PathBuf>,

        /// Save a digest-bound collision preview instead of changing the registry.
        #[arg(long, value_name = "FILE", conflicts_with = "dry_run")]
        save_plan: Option<PathBuf>,
    },

    /// Copy one live registry value without copying its containing subtree.
    CopyValue {
        #[arg(value_name = "SOURCE_KEY")]
        source: String,

        /// Source value name. Use @ for the unnamed default value.
        #[arg(value_name = "SOURCE_VALUE")]
        source_value: String,

        /// Read SOURCE_KEY from HKLM/HKU on this computer; destination remains local.
        #[arg(long, value_name = "COMPUTER")]
        source_computer: Option<String>,

        #[arg(value_name = "DEST_KEY")]
        dest: String,

        /// Destination value name; defaults to SOURCE_VALUE. Use @ for the default value.
        #[arg(long, value_name = "NAME")]
        dest_value: Option<String>,

        /// Replace an existing destination value instead of refusing it.
        #[arg(long)]
        overwrite: bool,

        /// Write the undo snapshot here instead of the temporary directory.
        #[arg(long, value_name = "FILE", conflicts_with = "save_plan")]
        backup: Option<PathBuf>,

        /// Save a digest-bound value collision preview instead of changing the registry.
        #[arg(long, value_name = "FILE", conflicts_with = "dry_run")]
        save_plan: Option<PathBuf>,
    },

    /// Move or rename one live registry value.
    MoveValue {
        #[arg(value_name = "SOURCE_KEY")]
        source: String,

        /// Source value name. Use @ for the unnamed default value.
        #[arg(value_name = "SOURCE_VALUE")]
        source_value: String,

        #[arg(value_name = "DEST_KEY")]
        dest: String,

        /// Destination value name; defaults to SOURCE_VALUE. Use @ for the default value.
        #[arg(long, value_name = "NAME")]
        dest_value: Option<String>,

        /// Replace an existing destination value instead of refusing it.
        #[arg(long)]
        overwrite: bool,

        /// Write the undo snapshot here instead of the temporary directory.
        #[arg(long, value_name = "FILE", conflicts_with = "save_plan")]
        backup: Option<PathBuf>,

        /// Save a digest-bound value collision preview instead of changing the registry.
        #[arg(long, value_name = "FILE", conflicts_with = "dry_run")]
        save_plan: Option<PathBuf>,
    },

    /// Apply a saved copy/move preview only while source and destination still match.
    ApplyCopyPlan {
        #[arg(value_name = "PLAN")]
        plan: PathBuf,

        /// Write the rollback snapshot here instead of beside the plan.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Back up a live subtree into a native application-hive file.
    Backup {
        #[arg(value_name = "KEY")]
        key: String,

        /// Read KEY as HKLM/HKU from this remote Windows computer.
        #[arg(long, value_name = "COMPUTER")]
        computer: Option<String>,

        #[arg(value_name = "HIVEFILE")]
        file: PathBuf,
    },

    /// Restore an application-hive backup into a live registry key.
    Restore {
        #[arg(value_name = "HIVEFILE")]
        file: PathBuf,

        #[arg(value_name = "DEST")]
        dest: String,

        /// Merge into an existing destination instead of refusing it.
        #[arg(long)]
        overwrite: bool,

        /// Write the live-registry undo snapshot here.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Read values from the live registry.
    Query {
        #[arg(value_name = "KEY")]
        key: String,

        /// Read HKLM or HKU from this remote Windows computer.
        #[arg(long, value_name = "COMPUTER")]
        computer: Option<String>,

        /// Read a single value instead of the whole key.
        #[arg(long, short = 'v', value_name = "NAME")]
        value: Option<String>,

        #[arg(long, short = 'r')]
        recursive: bool,
    },

    /// List immediate subkeys without reading their values.
    Ls {
        #[arg(value_name = "KEY")]
        key: String,

        /// Read HKLM or HKU from this remote Windows computer.
        #[arg(long, value_name = "COMPUTER")]
        computer: Option<String>,

        /// List every descendant instead of only immediate children.
        #[arg(long, short = 'r')]
        recursive: bool,

        #[command(flatten)]
        keys: KeyFilterOpts,

        /// Stop after this many matching keys.
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
    },

    /// Summarize keys, values, types, depth, and payload bytes without printing data.
    Stats {
        /// File, `-` for stdin, `pipe:NAME`, or a live key like HKCU\Software.
        #[arg(value_name = "SOURCE")]
        source: String,

        /// Treat SOURCE as HKLM/HKU on this remote Windows computer.
        #[arg(long, value_name = "COMPUTER")]
        computer: Option<String>,

        /// Rebase a live SOURCE subtree here before scoping and measuring.
        #[arg(long, value_name = "KEY")]
        root_as: Option<String>,

        #[command(flatten)]
        keys: KeyFilterOpts,

        #[command(flatten)]
        values: ValueFilterOpts,

        #[command(flatten)]
        input: InputOpts,
    },

    /// Compute a stable SHA-256 of exact registry state without printing values.
    Fingerprint {
        /// File, `-` for stdin, `pipe:NAME`, or a live key like HKCU\Software.
        #[arg(value_name = "SOURCE")]
        source: String,

        /// Treat SOURCE as HKLM/HKU on this remote Windows computer.
        #[arg(long, value_name = "COMPUTER")]
        computer: Option<String>,

        /// Rebase a live SOURCE subtree here before scoping and hashing.
        #[arg(long, value_name = "KEY")]
        root_as: Option<String>,

        /// Require this SHA-256 for a file or one selected registry view.
        #[arg(long, value_name = "SHA256")]
        expect: Option<String>,

        /// Require this SHA-256 for the 32-bit member of --view both.
        #[arg(long, value_name = "SHA256")]
        expect_32: Option<String>,

        /// Require this SHA-256 for the 64-bit member of --view both.
        #[arg(long, value_name = "SHA256")]
        expect_64: Option<String>,

        #[command(flatten)]
        keys: KeyFilterOpts,

        #[command(flatten)]
        values: ValueFilterOpts,

        #[command(flatten)]
        input: InputOpts,
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

        /// Write the undo snapshot here instead of the temporary directory.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
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

        /// Write the undo snapshot here instead of the temporary directory.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Inspect owner, inheritance, security descriptor, and effective access.
    Permissions {
        #[arg(value_name = "KEY")]
        key: String,

        /// Read KEY as HKLM/HKU from this remote Windows computer.
        #[arg(long, value_name = "COMPUTER")]
        computer: Option<String>,

        /// Compare this key's descriptor and effective access with another key.
        #[arg(long, value_name = "KEY")]
        compare: Option<String>,

        /// Read --compare as HKLM/HKU from this remote Windows computer.
        #[arg(long, value_name = "COMPUTER", requires = "compare")]
        compare_computer: Option<String>,

        /// Exit 5 when compared permissions differ.
        #[arg(long, requires = "compare")]
        exit_code: bool,
    },

    /// Apply an input file idempotently, optionally removing anything not declared.
    Sync {
        /// Input file, `-` for stdin, or `pipe:NAME` (streams require -y unless
        /// --dry-run).
        #[arg(value_name = "FILE")]
        file: PathBuf,

        #[command(flatten)]
        input: InputOpts,

        #[command(flatten)]
        redirect: RedirectOpts,

        /// How to handle conflicting key state or value data.
        #[arg(long, value_enum, default_value_t = MergeConflictPolicy::LastWins)]
        conflicts: MergeConflictPolicy,

        /// Delete live values under the declared keys that the file does not list.
        #[arg(long)]
        prune: bool,

        /// Recursively delete live subtrees not represented below declared keys.
        #[arg(long, requires = "prune")]
        prune_keys: bool,

        /// Write an undo snapshot here before applying (default: beside FILE).
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,

        /// Do not write an undo snapshot. Not recommended.
        #[arg(long, conflicts_with = "backup")]
        no_backup: bool,
    },

    /// Parse and lint .reg files. Exits non-zero on syntax errors.
    ///
    /// Use `inspect` to validate any supported registry-data format. `--fix`
    /// accepts exactly one .reg input so a later file cannot leave an earlier
    /// one partially repaired.
    Validate {
        /// Input files. Use `-` for stdin or `pipe:NAME`; --fix on a stream
        /// requires --out.
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

        /// Probe HKLM/HKU on this remote Windows computer without changing it.
        #[arg(long, value_name = "COMPUTER")]
        computer: Option<String>,
    },

    /// List the input formats regx can read, and how each is detected.
    Formats,

    /// Generate a shell completion script on standard output.
    Completions {
        #[arg(value_enum)]
        shell: CompletionShell,
    },

    /// Verify that an audit log has not been edited or had records removed.
    ///
    /// Each record carries the hash of the one before it, so an alteration
    /// anywhere breaks the chain from that point and is reported by line.
    Audit {
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Verify subsequent rotated segments in chronological order.
        #[arg(long, value_name = "FILE", num_args = 1.., conflicts_with = "rotate_to")]
        chain: Vec<PathBuf>,

        /// Archive FILE here and start a cryptographically linked new segment.
        #[arg(
            long,
            value_name = "ARCHIVE",
            conflicts_with_all = ["chain", "write_anchor", "verify_anchor"]
        )]
        rotate_to: Option<PathBuf>,

        /// Atomically write a detached digest/tail anchor after verification.
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["chain", "rotate_to", "verify_anchor"]
        )]
        write_anchor: Option<PathBuf>,

        /// Require FILE to match a previously detached audit anchor.
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["chain", "rotate_to", "write_anchor"]
        )]
        verify_anchor: Option<PathBuf>,

        /// Authenticate a v2 detached anchor with 32+ raw secret bytes from FILE.
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["chain", "rotate_to"]
        )]
        anchor_key: Option<PathBuf>,

        /// Print each record's key and outcome as well as the verdict.
        #[arg(long, short = 'v')]
        verbose: bool,
    },

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
        /// Input files. Use `-` for stdin or `pipe:NAME` for a Windows named pipe.
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

#[derive(Subcommand, Debug)]
pub enum LnkOp {
    /// Create or replace a native `.lnk` shortcut.
    Create {
        /// Existing executable or file launched by the shortcut.
        #[arg(long, value_name = "FILE")]
        target: PathBuf,

        /// Destination `.lnk`, including shell:Startup/Desktop/Programs paths.
        #[arg(
            id = "lnk_output",
            long = "shortcut-output",
            short = 'o',
            value_name = "FILE"
        )]
        output: PathBuf,

        /// Existing working directory for the launched target.
        #[arg(long, value_name = "DIR")]
        workdir: Option<PathBuf>,

        /// Arguments passed directly to the target (never through a shell).
        #[arg(long, value_name = "TEXT", allow_hyphen_values = true)]
        args: Option<String>,

        /// Shortcut description visible in Windows Shell properties.
        #[arg(long, value_name = "TEXT")]
        description: Option<String>,

        /// Icon as PATH or PATH,INDEX.
        #[arg(long, value_name = "PATH[,INDEX]")]
        icon: Option<String>,

        /// Window presentation requested from Windows Shell.
        #[arg(long, value_enum, default_value_t = ShortcutStyle::Normal)]
        style: ShortcutStyle,
    },

    /// Inspect a native `.lnk` without launching it.
    Inspect {
        /// Shortcut path, including a supported shell: Known Folder token.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },

    /// Delete a native `.lnk` after parsing and confirming it.
    Delete {
        /// Shortcut path, including a supported shell: Known Folder token.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },

    /// Apply [SHORTCUT] and [DELETE_SHORTCUT] blocks from a manifest.
    Apply {
        /// UTF-8/UTF-16 manifest, `-` for stdin, or `pipe:NAME` for Windows IPC.
        #[arg(value_name = "FILE")]
        file: PathBuf,
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
        #[command(flatten)]
        keys: KeyFilterOpts,
        /// Stop after this many matching keys.
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
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

    /// Summarize a subtree without printing value payloads.
    Stats {
        #[arg(value_name = "SUBKEY", default_value = "")]
        subkey: String,

        /// Rebase the mounted hive root here before scoping and measuring.
        #[arg(long, value_name = "KEY")]
        root_as: Option<String>,

        #[command(flatten)]
        keys: KeyFilterOpts,

        #[command(flatten)]
        values: ValueFilterOpts,
    },

    /// Compute a stable SHA-256 of a subtree without printing value payloads.
    Fingerprint {
        #[arg(value_name = "SUBKEY", default_value = "")]
        subkey: String,

        /// Require this SHA-256; drift exits with code 5.
        #[arg(long, value_name = "SHA256")]
        expect: Option<String>,

        /// Rebase the mounted hive root here before scoping and hashing.
        #[arg(long, value_name = "KEY")]
        root_as: Option<String>,

        #[command(flatten)]
        keys: KeyFilterOpts,

        #[command(flatten)]
        values: ValueFilterOpts,
    },

    /// Test whether a subkey can be read or changed without modifying it.
    Probe {
        #[arg(value_name = "SUBKEY", default_value = "")]
        subkey: String,
    },

    /// Inspect owner, inheritance, SDDL, and effective access for a subkey.
    Permissions {
        #[arg(value_name = "SUBKEY", default_value = "")]
        subkey: String,
    },

    /// Search keys and values below a subkey.
    Search {
        #[arg(value_name = "SUBKEY")]
        subkey: String,
        /// Pattern to find; substring by default, or select glob/regex.
        #[arg(value_name = "QUERY")]
        query: String,
        /// How QUERY is interpreted; include/exclude patterns are always globs.
        #[arg(long = "match", value_enum, default_value_t = SearchMode::Substring)]
        mode: SearchMode,
        /// Match case exactly instead of using case-insensitive matching.
        #[arg(long)]
        case_sensitive: bool,
        /// Restrict matching to one or more fields; defaults to all fields.
        #[arg(long, value_enum, value_name = "FIELD")]
        field: Vec<SearchField>,
        /// Search only key paths matching this glob; repeat to OR patterns.
        #[arg(long, value_name = "PATTERN")]
        include: Vec<String>,
        /// Omit key paths matching this glob; repeat to OR patterns.
        #[arg(long, value_name = "PATTERN")]
        exclude: Vec<String>,
        #[command(flatten)]
        values: DiffValueFilterOpts,
        /// Stop after this many matches.
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
    },

    /// Compare a subtree with any supported registry-data file.
    Diff {
        #[arg(value_name = "SUBKEY")]
        subkey: String,
        #[arg(value_name = "FILE")]
        input: PathBuf,
        #[command(flatten)]
        input_opts: InputOpts,
        /// Drop this leading path from every desired key before comparison.
        #[arg(long, value_name = "PREFIX")]
        strip_root: Option<String>,
        /// Write a registry-data patch that turns the hive subtree into the desired file.
        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,
        /// Registry-data format for the patch written by --out.
        #[arg(long, value_enum, default_value_t = DataFormat::Reg, requires = "out")]
        to: DataFormat,
        /// Exit 5 when drift is present.
        #[arg(long)]
        exit_code: bool,
        /// Compare only key paths matching this glob; repeat to OR patterns.
        #[arg(long, value_name = "PATTERN")]
        include: Vec<String>,
        /// Omit key paths matching this glob; repeat to OR patterns.
        #[arg(long, value_name = "PATTERN")]
        exclude: Vec<String>,
        #[command(flatten)]
        values: DiffValueFilterOpts,
        /// Emit counts without individual changes; patch output remains complete.
        #[arg(long)]
        summary_only: bool,
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
        /// Persist the inverse to this .reg file.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Delete a subkey or a single value.
    Delete {
        #[arg(value_name = "SUBKEY")]
        subkey: String,
        #[arg(long, short = 'v', value_name = "NAME")]
        value: Option<String>,
        #[arg(long, short = 'r')]
        recursive: bool,
        /// Persist the inverse to this .reg file.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Copy a complete subtree to another subkey in this hive.
    Copy {
        #[arg(value_name = "SOURCE_SUBKEY")]
        source: String,
        #[arg(value_name = "DEST_SUBKEY")]
        dest: String,
        /// Merge into an existing destination. Without this flag, any existing
        /// destination is refused before a write.
        #[arg(long)]
        overwrite: bool,
        /// Persist the inverse to this .reg file.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Move or rename a complete subtree in this hive.
    Move {
        #[arg(value_name = "SOURCE_SUBKEY")]
        source: String,
        #[arg(value_name = "DEST_SUBKEY")]
        dest: String,
        /// Merge into an existing destination. Without this flag, any existing
        /// destination is refused before a write.
        #[arg(long)]
        overwrite: bool,
        /// Persist the inverse to this .reg file.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Copy one value between subkeys in this hive.
    CopyValue {
        #[arg(value_name = "SOURCE_SUBKEY")]
        source: String,
        #[arg(value_name = "SOURCE_VALUE")]
        source_value: String,
        #[arg(value_name = "DEST_SUBKEY")]
        dest: String,
        #[arg(long, value_name = "NAME")]
        dest_value: Option<String>,
        #[arg(long)]
        overwrite: bool,
        /// Persist the inverse to this .reg file.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Move or rename one value between subkeys in this hive.
    MoveValue {
        #[arg(value_name = "SOURCE_SUBKEY")]
        source: String,
        #[arg(value_name = "SOURCE_VALUE")]
        source_value: String,
        #[arg(value_name = "DEST_SUBKEY")]
        dest: String,
        #[arg(long, value_name = "NAME")]
        dest_value: Option<String>,
        #[arg(long)]
        overwrite: bool,
        /// Persist the inverse to this .reg file.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Merge any supported registry-data file into the hive.
    Import {
        #[arg(value_name = "FILE")]
        input: PathBuf,
        #[command(flatten)]
        input_opts: InputOpts,
        /// Drop this leading path from every key before applying, e.g.
        /// --strip-root "HKEY_CURRENT_USER".
        #[arg(long, value_name = "PREFIX")]
        strip_root: Option<String>,
        /// How to handle conflicts after stripping the input root.
        #[arg(long, value_enum, default_value_t = MergeConflictPolicy::LastWins)]
        conflicts: MergeConflictPolicy,
        /// Persist the inverse here instead of beside the input.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Revert a previous offline-hive mutation from its undo snapshot.
    ///
    /// The snapshot's HKCU mount label is removed automatically. A redo
    /// snapshot is persisted before applying so this operation is reversible.
    Undo {
        #[arg(value_name = "FILE")]
        input: PathBuf,
        /// Persist the redo snapshot here instead of beside the input.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Reconcile any supported registry-data file into the hive.
    Sync {
        #[arg(value_name = "FILE")]
        input: PathBuf,
        #[command(flatten)]
        input_opts: InputOpts,
        /// Drop this leading path from every key before applying, e.g.
        /// --strip-root "HKEY_CURRENT_USER".
        #[arg(long, value_name = "PREFIX")]
        strip_root: Option<String>,
        /// How to handle conflicts after stripping the input root.
        #[arg(long, value_enum, default_value_t = MergeConflictPolicy::LastWins)]
        conflicts: MergeConflictPolicy,
        /// Delete values under declared keys that the file does not list.
        #[arg(long)]
        prune: bool,
        /// Recursively delete subtrees not represented below declared keys.
        #[arg(long, requires = "prune")]
        prune_keys: bool,
        /// Persist the inverse here instead of beside the input.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Apply a versioned JSON batch atomically under this hive mount.
    Batch {
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,
        /// Drop this leading path from every operation key before applying.
        #[arg(long, value_name = "PREFIX")]
        strip_root: Option<String>,
        /// Persist the shared inverse to this .reg file.
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
    },

    /// Export part of the hive to REG, JSON, CSV, or Registry.pol.
    Export {
        #[arg(value_name = "SUBKEY", default_value = "")]
        subkey: String,
        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,
        /// Output registry-data format.
        #[arg(long, value_enum, default_value_t = DataFormat::Reg)]
        to: DataFormat,
        /// Export only this key, not its descendants.
        #[arg(long)]
        no_recursive: bool,
        #[command(flatten)]
        values: ValueFilterOpts,
        /// Root key assigned to exported paths. An application hive has no
        /// permanent registry root, so every portable format needs one.
        #[arg(long, value_name = "LABEL", default_value = "HKEY_CURRENT_USER")]
        root_as: String,
        #[command(flatten)]
        keys: KeyFilterOpts,
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
