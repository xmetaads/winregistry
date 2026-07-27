# regx

A portable, single-file Windows Registry CLI for **standard users**. Manifested
`asInvoker`, so it never raises a UAC prompt and never elevates. Static-linked
CRT, no installer, no runtime dependency.

```
cargo build --release      # -> target\release\regx.exe
cargo test                 # 40 tests, including live-registry round trips
```

## Repository layout

| Path | What it is |
|---|---|
| `src/` | The `regx` CLI (Rust, MSVC toolchain) |
| `app.manifest`, `build.rs` | `asInvoker` manifest, embedded into the PE at link time |
| `website/` | Static site for **winregistry.org** — no build step ([README](website/README.md)) |
| `vercel.json`, `.vercelignore` | Vercel deployment config: output directory, clean URLs, security headers |
| `dev-server.py` | Local preview that reproduces Vercel's routing — `python dev-server.py` |
| `design-system/` | Generated design system the site is built against |

`.claude/skills/` is intentionally not committed: it holds ~7 MB of vendored
[ui-ux-pro-max](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) data
used only when designing site pages. Reinstall it with
`npx ui-ux-pro-max-cli init --ai claude` if you need it.

---

## Commands

| Command | What it does |
|---|---|
| `import <FILE...>` | Merge input files into the live registry (writes an undo snapshot first) |
| `export <KEY>` | Export a key to `.reg` |
| `convert <FILE>` | Read any supported format and write `.reg`. Never touches the registry |
| `inspect <FILE...>` | Report a file's format and contents without applying it |
| `discover [EXE_OR_DIR]` | Find an application's companion config files the way the application would, and flag the risky rungs |
| `formats` | List the input formats and how each is detected |
| `merge <FILE...>` | Combine `.reg` files, last write wins |
| `query <KEY>` | Read values |
| `set <KEY>` | Write one value |
| `delete <KEY>` | Delete a key or a value |
| `sync <FILE>` | Apply a `.reg` idempotently, `--prune` removes undeclared values |
| `validate <FILE...>` | Lint; `--fix` repairs what is safely repairable |
| `probe <KEY>` | Can this user *actually* write here? |
| `hive <HIVEFILE> <OP>` | Offline hive work via `RegLoadAppKey` — **no admin** |
| `--self-check` | What AppLocker / SRP / WDAC / the token do to this binary |

Global flags: `--dry-run`, `-y/--yes`, `--output text|json`, `--view 64|32|both`,
`--log-level`, `--no-color`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | CLI usage error |
| 3 | `.reg` parse error |
| 4 | access denied |
| 5 | partial success (something was skipped) |
| 6 | redirection refused |
| 7 | file I/O error |
| 8 | key or value not found |

---

## Input formats

`.reg` is only one shape registry data arrives in. Every reader funnels into the
same internal model, so redirection, coalescing, undo snapshots and apply work
on all of them unchanged.

| Format | Typical file | Notes |
|---|---|---|
| `reg` | `.reg` | regedit's own text format, UTF-16 or ANSI `REGEDIT4` |
| `pol` | `Registry.pol` | **Group Policy PReg binary.** Honours `**del.`, `**delvals.`, `**DeleteValues`, `**DeleteKeys`, `**soft.` |
| `admx` | `.admx` + `.adml` | **Policy template.** Emits the concrete `enabledValue`/`disabledValue`; `<elements>` are reported, never invented |
| `gpp` | `Registry.xml` | **Group Policy Preferences.** Actions `C`/`R`/`U`/`D`, `<Collection>` traversed, disabled items skipped |
| `inf` | `.inf` | `[AddReg]` / `[DelReg]` sections with `[Strings]` token substitution |
| `json` | `.json` | compact `{path: {name: value}}` or explicit `{"keys": [...]}` |
| `csv` | `.csv`, `.tsv` | header naming `key, name, type, data` in any order |
| `ini` | `.ini`, `.cfg` | `[HKEY_...]` sections, optional `:type` suffix per name |
| `hive` | `NTUSER.DAT` | detected and redirected to `regx hive` |

The format is detected from **content first, extension second** — a
`Registry.pol` renamed to `.txt` is still a PReg file, and a `.reg` that is
really JSON is a mistake worth catching before it reaches the registry. Override
with `--from`.

```bash
regx inspect "C:\Windows\System32\GroupPolicy\Machine\Registry.pol"
```

A `Registry.pol` stores no hive of its own: the same bytes mean HKLM under
`Machine\` and HKCU under `User\`. `regx` infers it from the path and falls back
to `--pol-root`.

---

## Companion-file discovery

Enterprise executables find their own configuration by anchoring on
`GetModuleFileNameW(NULL)` — the real path of the running module, used rather
than `argv[0]` because a parent process controls `argv[0]` and can point it
anywhere. Strip the extension, append `.ini`, and that is the classic sidecar;
.NET reaches `MyApp.exe.config` the same way. Around that, products layer a
search order.

`regx discover` reproduces that search, reports which rung each hit came from,
and flags the rungs that are load-bearing security bugs.

```bash
regx discover "C:\Program Files\Acme\updater.exe" --strict
```

| Rank | Origin | |
|---|---|---|
| 1 | explicit path | |
| 2 | environment variable | `<STEM>_CONFIG`, `<STEM>_HOME`, `<STEM>_INI` |
| 3 | beside the executable | the sidecar, plus the `.exe.<ext>` convention |
| 4–6 | `%LOCALAPPDATA%`, `%APPDATA%`, `%PROGRAMDATA%` | under `\<stem>\` |
| 7 | registry pointer | `Software\<stem>` `ConfigPath` (`--registry-pointer`) |
| 8 | Group Policy caches | `Registry.pol`, `PolicyDefinitions` (`--policy`) |
| 9 | **current directory** | reported as a risk, never trusted |
| 10 | **`%WINDIR%`** | where `GetPrivateProfileString` silently resolves a bare file name |

Risks reported per hit: sourced from the working directory; sitting in a
directory this user can write to while the executable's own directory is
protected; reached through a reparse point; resolving outside the anchor;
on a network path; or matching only after 8.3 short-name expansion.

Directory writability is **asked of the OS**, not inferred from the path: the
directory is opened for `FILE_ADD_FILE`, which is an access check with no side
effect — the same principle as `regx probe`.

---

## Smart Redirection

Rewrites `HKLM` / `HKCR` paths to `HKCU` so a standard user can apply a `.reg`
written for machine scope. Every mapping carries a **confidence** and a reason;
`--min-confidence` (default `medium`) is the gate.

| Source | Confidence | Why |
|---|---|---|
| `HKCR\*`, `HKLM\SOFTWARE\Classes\*` | **high** | HKCR is a merged view; the per-user branch wins |
| `HKLM\...\CurrentVersion\Run`, `Explorer` | **high** | Windows reads the per-user copy too |
| `HKLM\SOFTWARE\<Vendor>\<App>` | **medium** | Only works if the app falls back to HKCU |
| `HKLM\SOFTWARE\Policies\*` | **low** | SYSTEM services read HKLM only, **and Group Policy refresh wipes `HKCU\Software\Policies` every ~90 min** |
| `HKLM\SYSTEM`, `HARDWARE`, `SAM`, `SECURITY` | **refuse** | No per-user equivalent exists |
| `*\UserChoice` | **refuse** | Protected by a per-SID hash since Windows 8; file associations cannot be set from a `.reg` |

`SOFTWARE\WOW6432Node\X` is normalised to `SOFTWARE\X` before classification, so
32-bit and 64-bit exports of the same app collapse onto one destination. That
collapse is why every redirect run is followed by a **coalesce** pass
(case-insensitive, last write wins) — without it, redirection emits duplicate key
blocks.

---

## Offline Hive Engine (`regx hive`)

`RegLoadKey` — what `reg load` and regedit's *Load Hive* use — requires
`SeRestorePrivilege`, which a standard user's token does not hold.
**`RegLoadAppKeyW` does not.** It mounts the hive into a private slot visible
only to the calling process, so there is no global namespace entry to protect and
no privilege to check.

### Why there is no separate `mount` / `unmount`

The handle is **process-scoped**: closing it — including at process exit —
unloads the hive. So this cannot work:

```
regx hive mount NTUSER.DAT --as my_hive   # process 1 exits -> hive unloaded
regx hive set my_hive\Software\App ...    # process 2: nothing is mounted
regx hive unmount my_hive                 # process 3: nothing to unmount
```

There is no supported workaround: the handle cannot be published to the registry
namespace (that is exactly what the privilege check guards), and inheriting it
would require a resident daemon, which defeats "portable, no install".

Mount / operate / unmount therefore happens inside one process:

```bash
regx hive "C:\path\MyApp.hive" --create exec -c "set Software\MyApp -v License -d OK" -c "set Software\MyApp -v Seats -t REG_DWORD -d 25" -c "query Software\MyApp -r"
```

`--script FILE` reads the same operations one per line (`#` comments). Single
operations need no `exec`:

```bash
regx hive "C:\path\MyApp.hive" export Software -o offline.reg --root-as "HKEY_USERS\OFFLINE"
```

### What a standard user can realistically open

Write access to the *file* is still required, and a hive already mounted by the
OS is held exclusively. Realistic targets: a logged-off secondary profile, a
**copy** of a hive, an application's private hive, or a hive on a mounted backup
or VHD. A logged-on user's `NTUSER.DAT` fails with `ERROR_SHARING_VIOLATION` by
design; `regx hive <file> info` reports this before you commit to a write.

---

## `validate --fix`

Repairs the damage `.reg` files pick up from forums, chat clients and blog code
blocks. Safe repairs are applied silently; **lossy** ones are applied but labelled.

| Defect | Repair | Class |
|---|---|---|
| `hex(1)/hex(2)/hex(6)` missing NUL terminator | append `00,00` | safe |
| `hex(7)` missing double NUL | append until double-NUL terminated | safe |
| Trailing whitespace after a `\` continuation | removed (regedit stops folding there and drops the rest of the payload) | safe |
| Control characters in a key path or value name | stripped | safe |
| Empty path components (`A\\\\B`) | collapsed | safe |
| Duplicate key blocks | coalesced, last write wins | safe / lossy if values conflict |
| Odd-length UTF-16 payload | padded with one NUL byte | **lossy** |
| `hex(4)` / `hex(b)` of the wrong length | **not** repaired — reported | — |

`--fix` refuses to run on a file with *syntax* errors: repairing those means
guessing the author's intent, not fixing a known defect.

---

## Undo engine

`import` and `sync` compute the inverse of the pending change **before** writing
anything and save it as an ordinary `.reg` file (`<input>.undo.reg`, or
`--backup FILE`). The registry offers no transaction, so this is the compensation.

- `[-KEY]` that exists → the whole subtree is exported, so undo recreates it
- key exists, value exists → current data recorded
- key exists, value absent → `"name"=-` recorded
- key does not exist → `[-TOPMOST_MISSING_ANCESTOR]`, not `[-KEY]` — deleting only
  the leaf would leave the intermediate keys we are about to create behind

Restores are ordered before removals. If any key could not be read, the undo file
is reported as **INCOMPLETE** rather than silently trusted.

---

## Getting past AppLocker / SRP / WDAC

UAC is not the real obstacle in a locked-down enterprise; application control is.
An unsigned `.exe` under `%TEMP%`, `Downloads` or `%APPDATA%` is precisely the
shape the default rule sets deny. `regx --self-check` reads the relevant policy
keys (all readable by a standard user) and reports what applies here.

**In order of what actually works:**

1. **Sign the binary.** A publisher rule follows the file anywhere; a path rule
   does not. An **EV code-signing certificate** additionally gives immediate
   SmartScreen reputation — a standard OV certificate has to accumulate it, so
   early downloads still see the "unrecognised app" interstitial.
   In a managed environment, a certificate from the organisation's **internal CA**
   is usually faster to obtain and is already trusted domain-wide; AppLocker
   publisher rules accept it.

   ```bash
   signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a target\release\regx.exe
   ```

   Always timestamp (`/tr`): without it, signatures stop validating when the
   certificate expires.

2. **Run from a path the policy already allows** — typically `%ProgramFiles%` or
   an IT-managed share — rather than from `Downloads`.

3. **Clear the Mark-of-the-Web** on a downloaded copy (`Unblock-File`), which is
   what triggers the SmartScreen interstitial. `--self-check` reads the
   `Zone.Identifier` stream and reports `ZoneId`.

**WDAC is different from the other two:** it ignores file location entirely. If a
user-mode code-integrity policy is deployed, only a signature or an explicit hash
rule will let the binary run — points 2 and 3 do not help. `--self-check`
distinguishes this case and deliberately does *not* warn merely because
`CodeIntegrity\CiPolicies\Active` is populated: stock Windows 11 ships
driver-blocklist policies there by default, and warning on their presence would
cry wolf on nearly every machine.

---

## Design notes

- **Byte-exact round-trip.** Values that cannot be losslessly modelled stay raw
  `hex(N)` bytes. A `REG_SZ` is only written as a quoted string when it is clean
  UTF-16 — even length, single trailing NUL, no embedded NUL, no control
  characters — because a raw newline in a `.reg` file corrupts the next line.
- **Escapes.** `.reg` has exactly two: `\\` and `\"`. There is no `\n` or `\t`.
- **Encoding.** `Version 5.00` is UTF-16LE with BOM; `REGEDIT4` is ANSI in the
  machine's codepage, decoded via `MultiByteToWideChar(CP_ACP)` so behaviour
  matches regedit.
- **WOW64 is always explicit.** Every open/create passes an explicit
  `KEY_WOW64_*` bit, so behaviour never depends on how the binary was built.
- **Registry virtualization does not apply.** With an explicit manifest, LUAFV is
  off — an HKLM write returns `ACCESS_DENIED` rather than being silently
  redirected to `VirtualStore`. That honest error is what Smart Redirection reacts to.
- **Export never aborts on a denied subkey.** Partial export of your own hive is
  normal (GP-locked policy keys, `Protected` subtrees); skips are listed.
