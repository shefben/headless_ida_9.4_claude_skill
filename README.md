# Claude IDA Headless Reverse-Engineering Skill (IDA 9.4)

A Claude skill for evidence-driven, token-bounded reverse engineering with **IDA Pro 9.4**, `idalib`, `ida-domain 0.5.x`, IDAPython, and Hex-Rays.

The skill is intended primarily as a **global Claude skill** installed at `~/.claude/skills/ida-headless-analysis`, although it can also be installed per project.

> **Branch status:** `main` contains the v2 analysis baseline plus the current cross-platform installer/discovery fixes. The `feature/intelligence-speed-v2` branch contains the v3 intelligence/speed expansion: persistent workers, semantic indexing, microcode slicing/taint, C++ recovery, version matching, evidence/project SQLite, autonomous investigation frontier, transactional findings, and project-isolated state.

## Core analysis features

The baseline skill provides:

- mandatory `auto_analysis=True` for every IDA database open;
- mandatory `ida_auto.auto_wait()` before analysis queries;
- mandatory successful `ida_hexrays.init_hexrays_plugin()` before decompiler work;
- fast exact-string search by encoded bytes (ASCII/UTF-8/UTF-16LE) instead of enumerating the entire Strings list;
- ida-domain 0.5 import access with lower-level fallbacks where required;
- structured C-tree fact extraction with `ida_ctree.py`;
- structured microcode extraction with selectable maturity using `ida_dataflow.py`;
- bounded static call/path tracing with `ida_path.py`;
- bounded source/sink candidate-path analysis with `ida_sourcesink.py`;
- post-decompilation harvesting of IDA 9.4 string discoveries;
- persistent `.ida-re/` evidence/cache data and token/output budgets;
- IDA 9.4 platform guidance for Swift, Rust, Go, Objective-C/DSC, Hexagon/MBN, ARM, RISC-V, TriCore and more;
- Domain API first with IDAPython/SDK fallbacks for unwrapped functionality.

The v3 feature branch expands this with single-session worker/batch execution, function ranking and semantic search, canonical function packets, microcode value slicing, indirect-call/vtable analysis, C++/structure recovery, dispatch reconstruction, cross-version matching, FLIRT discovery, semantic API knowledge, multi-binary project graphs, SQLite evidence graphs, contradiction tracking, specialist investigators, and cost-aware autonomous analysis.

## Requirements

- IDA Pro **9.4 recommended**. IDA 9.1-9.3 are accepted as fallback/testing configurations.
- Python **3.13.x**.
- `ida-domain >=0.5.0,<0.6.0`.
- A working Hex-Rays decompiler for the target architecture.

## Installation

Clone or extract the repository. The setup scripts resolve their own location, so they can be launched without relying on the current shell directory.

### Windows / PowerShell

Automatic discovery:

```powershell
.\setup.ps1
```

Explicit paths:

```powershell
.\setup.ps1 -IdaPath "F:\idapro_9.4" -PythonPath "C:\Python313\python.exe"
```

Parameters:

| Parameter | Meaning |
| --- | --- |
| `-IdaPath <path>` | Explicit IDA installation directory. The directory must contain a valid IDA executable. |
| `-PythonPath <path>` | Explicit Python executable. It must report Python 3.13.x. |

PowerShell discovery checks environment values, sibling directories of discovered IDA installations, Windows uninstall registry entries, common installation locations, filesystem-drive roots, and common `Tools`/`Apps`/`Programs`/`Software` directories. IDA 9.4 is ranked first, and a single discovered 9.4 installation is selected automatically.

Windows IDA paths are canonicalized before they are exported. Trailing directory backslashes are removed so `idapro` cannot generate an invalid Python raw string ending in `\`.

### Linux / macOS / Bash

Automatic discovery:

```bash
chmod +x setup.sh
./setup.sh
```

Explicit paths:

```bash
./setup.sh --ida-path /opt/ida-9.4 --python-path /usr/bin/python3.13
```

For parity with the PowerShell parameter names, Bash also accepts:

```bash
./setup.sh --IdaPath "$HOME/tools/ida-9.4" --PythonPath /usr/bin/python3.13
./setup.sh -IdaPath "$HOME/tools/ida-9.4" -PythonPath /usr/bin/python3.13
```

Parameters:

| Parameter | Aliases | Meaning |
| --- | --- | --- |
| `--ida-path <path>` | `--IdaPath`, `-IdaPath` | Explicit IDA installation directory. |
| `--python-path <path>` | `--PythonPath`, `-PythonPath` | Explicit Python 3.13 executable. |
| `--help` | `-h` | Show installer help. |

Bash discovery checks environment variables, `PATH`, sibling directories of discovered installs, and shallow scans of common locations such as `/opt`, `/usr/local`, `/Applications`, `~/tools`, `~/Applications`, and `~/.local`. It prefers a uniquely discovered IDA 9.4 installation.

## What the setup scripts do

Both installers:

1. cleanly replace the global skill directory at `~/.claude/skills/ida-headless-analysis`, preventing files removed by a newer version from surviving an update;
2. discover or validate IDA and Python;
3. prefer IDA 9.4 when it is available;
4. require Python 3.13.x;
5. replace `%IDA_PATH%` and `%PYTHON_BIN_PATH%` only in known text files;
6. export `IDADIR` and `IDAPYTHON_DYNLOAD_BASE` for setup verification;
7. install/upgrade `ida-domain>=0.5.0,<0.6.0` and repository requirements;
8. verify that `ida_domain` and `idapro` import successfully.

## Global vs per-project installation

The default setup scripts install globally to:

```text
~/.claude/skills/ida-headless-analysis
```

A project may instead carry its own copy of `ida-headless-analysis` in that project's Claude skills location. On the v3 feature branch, analysis databases and caches are additionally namespaced by project identity so a global skill cannot mix unrelated reversing projects.

The v3 project identity can be pinned explicitly with:

```bash
export IDA_RE_PROJECT_ID="my-project"
export IDA_RE_PROJECT_ROOT="/path/to/project"
```

PowerShell equivalents:

```powershell
$env:IDA_RE_PROJECT_ID = "my-project"
$env:IDA_RE_PROJECT_ROOT = "F:\Development\MyProject"
```

## Validation

After setup:

```bash
python ~/.claude/skills/ida-headless-analysis/scripts/validate_skill.py
```

On Windows, use the Python interpreter selected during setup if `python` does not resolve to the same installation:

```powershell
C:\Python313\python.exe "$HOME\.claude\skills\ida-headless-analysis\scripts\validate_skill.py"
```

For the full v3 analysis architecture and helper list, see the `feature/intelligence-speed-v2` branch and its `ida-headless-analysis/SKILL.md`.
