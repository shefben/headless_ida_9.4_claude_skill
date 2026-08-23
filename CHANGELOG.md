# Changelog

## 2.0.0-ida9.4

- Retargeted default environment from IDA 9.3 headless to `F:\IDA Professional 9.4`.
- Kept and revalidated mandatory `auto_analysis=True`, `ida_auto.auto_wait()`, and successful
  `ida_hexrays.init_hexrays_plugin()` for every binary/session.
- Preserved the original high-performance exact-string technique: encoded byte search remains the
  primary path for known literals, rather than global Strings-list enumeration.
- Added post-decompilation harvesting of bounded Hex-Rays string seeds, complementing byte search.
- Replaced normal import enumeration with ida-domain 0.5 `db.imports.get_all_imports()`; retained a
  low-level fallback.
- Added `ida_ctree.py` for structured C-tree extraction of calls, arguments, constants, strings,
  objects, member offsets, assignments, loops and returns.
- Reworked `ida_dataflow.py` around structured `MicroBlockArray`/instruction/operand traversal.
- Added explicit microcode maturity selection (`generated`, `preoptimized`, `calls`, `locopt`,
  `glbopt1..3`, `lvars`).
- Added `ida_path.py`, a bounded headless Pathfinder-style call/code-reference path finder.
- Added `ida_sourcesink.py` for compact candidate source/sink path discovery.
- Added IDA 9.4 progressive references for Swift, Rust, Go, Objective-C/DSC, Hexagon/MBN,
  MCore/C-Sky, ARM, RISC-V, TriCore and V850.
- Added compilation-unit/language fields to the evidence schema without fabricating unsupported
  data when scripting access is unavailable.
- Updated setup, README, troubleshooting and workflow guidance for IDA 9.4/Domain 0.5.

## 1.x baseline

- Refactored the original API cheat sheet into an evidence-driven RE protocol.
- Added shared mandatory IDA/Hex-Rays session wrapper, persistent evidence state, bounded call
  graphs/function slices, type-recovery feedback loop, and token budgets.
