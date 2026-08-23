# Changelog

## 3.0.0-ida9.4

- Added `ida_batch.py` for multi-step analysis inside one IDA/Hex-Rays session.
- Added `ida_worker.py` persistent JSONL worker to eliminate repeated idalib/database startup.
- Added bounded read-only-by-default `ida_eval.py` for specialized Claude-generated IDA queries.
- Added cost-aware investigation planning and a persistent priority/cost investigation frontier.
- Added function-interest ranking, canonical function packets, semantic fingerprints and SQLite FTS5 retrieval.
- Added IDA 9.4 indexer-aware search with bounded fallback behavior.
- Added structured microcode def/use analysis with forward/backward value slicing.
- Added indirect-call/vtable candidate resolution for C++ and callback-heavy binaries.
- Added C++ RTTI/vtable discovery, repeated-member-offset structure recovery and type verification helpers.
- Added switch/dispatch recovery for protocol/state-machine handler mapping.
- Added cross-version function matching using exact fingerprints plus semantic similarity.
- Added read-only FLIRT/signature-file discovery; application remains an explicit transactional mutation.
- Added compilation-unit probes, source-module clustering and Swift/Rust/Go/Objective-C/MSVC runtime hints.
- Added obfuscation prioritization, stack-string construction candidates and semantic constant recognition.
- Added semantic API effects for buffer input/output/copy/crypto/process behavior.
- Added multi-binary project SQLite state for EXE/DLL/shared-library/plugin investigations.
- Added SQLite evidence graph with entities, claims, provenance, confidence and automatic contradiction surfacing.
- Added global/per-project installation-safe state namespacing: `.ida-re/projects/<project-id>/binaries/<binary-id>/`.
- Project IDs are derived from the resolved project root plus a SHA-256 suffix, with `IDA_RE_PROJECT_ID` and `IDA_RE_PROJECT_ROOT` overrides.
- Project/evidence SQLite databases now persist identity metadata and reject conflicting project reuse instead of silently mixing state.
- Reworked `ida_apply_findings.py` into plan/apply/verify/rollback workflow with rollback manifests.
- Added specialist protocol/C++/crypto/filesystem/rendering/version-diff investigator recipes.
- Rewrote `SKILL.md` so Claude prefers worker/batch execution, semantic retrieval, canonical packets, evidence reuse and bounded proof-oriented escalation.

## 2.0.0-ida9.4

- Retargeted default environment to IDA Professional 9.4.
- Kept and revalidated mandatory `auto_analysis=True`, `ida_auto.auto_wait()`, and successful `ida_hexrays.init_hexrays_plugin()` for every binary/session.
- Preserved the original high-performance exact-string technique: encoded byte search remains the primary path for known literals, rather than global Strings-list enumeration.
- Added post-decompilation harvesting of bounded Hex-Rays string seeds, complementing byte search.
- Replaced normal import enumeration with ida-domain 0.5 `db.imports.get_all_imports()`; retained a low-level fallback.
- Added `ida_ctree.py` for structured C-tree extraction of calls, arguments, constants, strings, objects, member offsets, assignments, loops and returns.
- Reworked `ida_dataflow.py` around structured `MicroBlockArray`/instruction/operand traversal.
- Added explicit microcode maturity selection (`generated`, `preoptimized`, `calls`, `locopt`, `glbopt1..3`, `lvars`).
- Added `ida_path.py`, a bounded headless Pathfinder-style call/code-reference path finder.
- Added `ida_sourcesink.py` for compact candidate source/sink path discovery.
- Added IDA 9.4 progressive references for Swift, Rust, Go, Objective-C/DSC, Hexagon/MBN, MCore/C-Sky, ARM, RISC-V, TriCore and V850.
- Added compilation-unit/language fields to the evidence schema without fabricating unsupported data when scripting access is unavailable.
- Updated setup, README, troubleshooting and workflow guidance for IDA 9.4/Domain 0.5.

## 1.x baseline

- Refactored the original API cheat sheet into an evidence-driven RE protocol.
- Added shared mandatory IDA/Hex-Rays session wrapper, persistent evidence state, bounded call graphs/function slices, type-recovery feedback loop, and token budgets.
