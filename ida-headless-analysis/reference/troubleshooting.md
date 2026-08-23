# Troubleshooting (IDA 9.4)

## Python / environment

```powershell
$env:IDADIR = "%IDA_PATH%"
%PYTHON_BIN_PATH% ...
```

If ida-domain is below 0.5.0, run `setup.ps1`.

## Database lock

The dedicated headless IDA installation avoids GUI/headless collisions, but stale locks can still
occur after a crash. Confirm no process has the database open before deleting IDA sidecar files.

## Hex-Rays fails

The wrapper requires `ida_auto.auto_wait()` followed by successful
`ida_hexrays.init_hexrays_plugin()`. If initialization fails, stop. If one function fails after
initialization, use the raw fallback to capture `hexrays_failure_t` details.

## First / cached analysis

Large binaries can take substantial time on first analysis. Save/reuse the resulting IDB/I64, but
the wrapper still explicitly sets `auto_analysis=True` and calls `auto_wait()` on every open so
newly queued analysis is never skipped.

## Exact string search performance

Use `ida_query.py BIN string "literal"`. This scans encoded bytes by segment and stops at the hit
budget. IDA 9.4 decompiler-recovered strings are useful discovery seeds, not a reason to enumerate
the global Strings list for known literals.

## Domain 0.5 errors

Pseudocode/microcode functions may raise specific Domain exceptions. Preserve the exception class,
address/reason where available, and fall back to raw Hex-Rays/disassembly when the failure is local
to one function rather than masking it with an empty result.

## Validator

```powershell
%PYTHON_BIN_PATH% scripts\validate_skill.py
```
