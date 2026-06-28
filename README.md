# ACL-Graph+

A recursive directory scanner for Windows that determines the **effective access
rights** of the executing user and renders them as an interactive, zoomable and
searchable HTML node graph. Focus: quickly see **where you can write** and
**which config files contain secrets** — for pentesters (hijack vectors) and
admins (misconfigurations).

Pure PowerShell, no dependencies. Runs on Windows 10 / Server 2016 and later.

---

## Quick start

```powershell
# Simplest invocation: scan the current directory, report next to the script
.\Get-AclGraph.ps1

# Scan a specific path, set the output file
.\Get-AclGraph.ps1 -Path 'C:\inetpub' -OutFile report.html
```

Then open the generated HTML file in a browser. No server is required — the file
is self-contained (HTML + CSS + JS in a single file).

> **Tip:** On the first run against large drives, set `-Depth` or pick a
> subfolder as `-Path`. Every file costs one `Get-Acl` call, so a full `C:\`
> scan can take a long time.

---

## What the report shows

When opened, only the **findings** and the paths leading to them are expanded —
everything else stays collapsed so that even large trees remain readable.

| Display | Meaning |
|---|---|
| Blue node | Directory |
| Yellow node | Writable (writable by you) |
| Red node (2px border) | **Finding**: writable **and** in a sensitive path (hijack vector) |
| Key badge `🔑 N` | File contains N potential secrets in its content |
| Grey, dashed box | Default/system folder, unchanged (collapsed) |
| Badge "n.gescannt" | Content not checked for secrets (e.g. too large) |
| `… N weitere` | Bundled, uninteresting files — click to expand them |

The rights abbreviation below each name: `R` read, `W` write, `X` execute,
`D` delete, `P` change permissions (WRITE_DAC), `O` take ownership (TAKE_OWNERSHIP),
`FULL` full control.

---

## Using it in the browser

**Navigation**
- Mouse wheel = zoom, drag with the mouse = pan.
- `+` / `−` / "Alles" at the top = zoom in/out or fit the whole graph.
- Compass cross at the bottom right: the blue dot shows where in the tree the
  center of your viewport sits; the box next to it reports `x`, `y` and zoom (`z`).
  **Click the cross = back to the overview.**

**Expanding**
- Click a directory = open the detail panel **and** expand/collapse its children.
  The clicked node stays at its on-screen position while doing so.
- "Pfade entfalten" = expand everything · "Nur Funde" = back to the findings.
- Click `… N weitere` = reveal the bundled files.

**Filter** (field at the top right)
- `config` → only nodes whose name contains "config".
- `config -test` → contains "config", but **not** "test".
- `-backup` → everything **except** "backup".
- Multiple terms can be combined with spaces: `config -backup -test`.
- The search also looks inside **collapsed** areas and expands matches;
  clearing the field restores the initial state.

**Default folders**
- Unchanged system folders are grey and collapsed. The checkbox
  "Default-Ordner einblenden" brings them into view when needed.

**Viewing secrets**
- Click a file with a key badge → the detail panel shows the match with one line
  of context before/after and a line number. The secret value is **masked**
  (dots); the "einblenden" button reveals it, "verdecken" hides it again.

> **⚠ Important:** If the report contains secrets, the cleartext (masked) lives
> in the HTML. **Open the file locally only, do not share it.** A red warning
> bar in the report points this out.

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Path` | string | current directory | Root directory of the scan. |
| `-OutFile` | string | `.\aclgraph.html` | Target file for the HTML report. |
| `-Depth` | int | `0` (unlimited) | Maximum recursion depth. `0` = no limit. |
| `-Skip` | string[] | empty | Regex patterns for folders/names that are **not entered** during the scan. |
| `-ScanExtensions` | string[] | empty | **Additional** file extensions (without dot) for the secret content scan. |
| `-SecretRegex` | string[] | empty | **Additional** custom regex patterns for secret detection. |
| `-MaxScanMB` | int | `5` | Files larger than this value (MB) are skipped during the content scan and marked. |
| `-DefaultDirs` | string[] | Windows system folders | Regex patterns treated as "default/standard folders". |
| `-ExcludeReparse` | switch | on | Do **not** follow reparse points (symlinks/junctions). |

### Default values in detail

**Secret-scan extensions (always active):**
`config`, `env`, `ini`, `json`, `xml`, `ps1`, `bat`, `yaml`, `yml`
— `-ScanExtensions` adds to this list.

**Secret patterns (always active):**
Password · ConnectionString · API key · AWS key (`AKIA…`) · Private key
(`-----BEGIN … PRIVATE KEY-----`) · Token/Bearer
— `-SecretRegex` adds to this list.

**Default folders (standard):**
`C:\Windows`, `WinSxS`, `System32`, `SysWOW64`, `Microsoft.NET`, `assembly`,
`Installer`, `Common Files`. These are shown grey & collapsed only when their
subtree contains **no** finding, **no** secret and **no** writable file —
otherwise they stay normally visible.

---

## Examples

```powershell
# Inspect a web server directory, name the report
.\Get-AclGraph.ps1 -Path 'C:\inetpub' -OutFile inetpub-acl.html

# Whole drive, but limit depth and skip junk folders
.\Get-AclGraph.ps1 -Path C:\ -Depth 4 -Skip 'WinSxS','node_modules','\.git$'

# Custom config extension and a stricter size limit for the secret scan
.\Get-AclGraph.ps1 -Path 'D:\apps' -ScanExtensions 'conf','properties' -MaxScanMB 2

# Add a custom secret pattern (internal token format)
.\Get-AclGraph.ps1 -Path 'C:\svc' -SecretRegex 'INTERNAL_TOKEN\s*=\s*\S+'

# Multiple skip patterns + custom default-folder definition
.\Get-AclGraph.ps1 -Path C:\ -Skip 'temp','logs','cache' `
    -DefaultDirs '\\Windows\\','\\Program Files\\Common Files\\'
```

---

## Console output

During the run the script reports:

- the user the scan runs as, and the root,
- the active skip list (if set),
- the number of scanned nodes,
- how many entries were skipped via the skip list,
- how many unique SIDs were resolved,
- how many files are suspected of containing secrets,
- a **red warning** if the report contains cleartext secrets.

---

## How "effective rights" are computed

For each item the script reads the ACL and resolves the rights against **all SIDs
from your access token** (your own SID + all groups). `Deny` entries win over
`Allow`. The result is therefore: *what you are actually allowed to do on this
object* — not a raw listing of all ACEs.

To keep this fast, the ACLs are read in **SID form** during the scan (no name
lookup per file). Every unique SID is then translated into a name exactly **once**
at the end, instead of repeatedly per ACE — which saves a great deal of time in
domain environments where name resolution can trigger a network lookup.

**Limits:** The resolution covers normal allow/deny ACEs, but not every special
case of Windows authorization (e.g. conditional ACEs / claims, or privileges like
`SeBackupPrivilege` that bypass ACLs). For misconfiguration hunting this is enough
in nearly all cases; forensic accuracy would require additional `AuthZ` API checks.

The secret scan is deliberately pragmatic: the regexes catch the common cases
well, but are not exhaustive. Add very specific formats via `-SecretRegex`; with
minified/base64-heavy files individual false positives are possible.

---

## Security note

The HTML report can contain **cleartext secrets** (masked, revealable on click).
Treat the file like a secret: open it locally, do not share it via email or chat,
and delete it after use.
