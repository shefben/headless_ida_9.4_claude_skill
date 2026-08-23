---
name: ida-headless-analysis
description: Reverse engineer EXE, DLL, ELF, Mach-O, firmware and other binaries headlessly with IDA Pro 9.4/idalib using mandatory auto-analysis + Hex-Rays, single-session execution, semantic retrieval, project-isolated evidence graphs, structured C-tree/microcode, taint/slicing, C++ recovery, version matching, and token-bounded autonomous investigation.
---

# IDA 9.4 Headless Reverse Engineering

## Mandatory invariants

Every binary MUST enter IDA through `scripts/_ida_session.py:open_database()` directly or through a helper that uses it. The wrapper sets `IDADIR`, opens with `IdaCommandOptions(auto_analysis=True, ...)`, waits for `ida_auto.auto_wait()`, initializes Hex-Rays with `ida_hexrays.init_hexrays_plugin()`, aborts if Hex-Rays fails, and closes cleanly. Never use `auto_analysis=False`. Never decompile before analysis completes. Never substitute loading a Hex-Rays plugin binary for `init_hexrays_plugin()`.

## Global/per-project installation and state isolation

This skill is designed to work when installed globally or inside a project. Persistent analysis state MUST NEVER be keyed only by binary filename, binary hash, or the skill installation directory.

The shared state helpers resolve a deterministic project identity in this order:
1. `IDA_RE_PROJECT_ID` explicit stable identifier, when supplied;
2. `IDA_RE_PROJECT_ROOT` explicit project root, when supplied;
3. enclosing Git worktree of the agent's current working directory;
4. enclosing Git worktree of the target binary;
5. current working directory.

Without an explicit ID, the project identifier is `<project-directory-name>-<12-char SHA256(project-root-path)>`. This prevents two unrelated projects with the same directory name from colliding. If a project is moved and must retain its previous identity, set `IDA_RE_PROJECT_ID` explicitly.

All persistent state uses:

```text
.ida-re/projects/<project-id>/
  project.json
  project.sqlite
  binaries/<binary-sha256-prefix>/
    manifest.json
    semantic.sqlite
    frontier.sqlite
    evidence.sqlite
    functions/
    queries/
    findings.jsonl
    hypotheses.jsonl
    unresolved.jsonl
```

Every binary-level database is therefore isolated by BOTH project identity and binary content hash. SQLite databases record their project/binary identity internally when practical and MUST reject an incompatible existing identity rather than silently mixing projects.

Never store project state relative to the global skill installation directory. State belongs to the active working project. Use `IDA_RE_PROJECT_ID` for stable identity across multiple checkouts/paths when desired.

## Default operating model

For more than one query, prefer one IDA session instead of repeatedly opening the database:
1. `ida_worker.py` for interactive investigations with many queries.
2. `ida_batch.py` when the required sequence is known in advance.
3. Individual helpers for one-off commands.
4. `ida_eval.py` only when the canned helpers cannot express a specialized read-only query.

Do not spawn multiple workers against the same writable IDB. Keep generated analysis code read-only unless a database mutation is explicitly intended.

## Intelligence-first escalation ladder

Use the cheapest evidence that can answer the question and stop when it does:

`cache/evidence graph -> semantic search/indexer -> triage -> rank -> exact byte string/constant -> canonical function packet -> xrefs/callers/callees -> C-tree -> CFG -> pseudocode -> microcode -> taint/slice -> type/class recovery -> assembly verification`

Before an expensive query, know what it should prove or disprove. `ida_advanced.py plan` can produce a cost-aware investigation order. Prefer information gain per unit cost over dumping pseudocode.

## Exact-string rule

For a known literal, ALWAYS search encoded bytes first. `ida_query.py string` scans mapped segments with `db.bytes.find_bytes_between()` using ASCII/UTF-8 and UTF-16LE. Do not enumerate the global IDA Strings list for an exact literal. Use `strings --regex/--contains` only for discovery when the exact literal is unknown. Strings recovered during decompilation are new seeds, not a replacement for byte-backed search.

## Semantic ranking and retrieval

For an unknown binary or subsystem:

```powershell
%PYTHON_BIN_PATH% scripts\ida_intel.py BIN rank --limit 40
%PYTHON_BIN_PATH% scripts\ida_intel.py BIN index
%PYTHON_BIN_PATH% scripts\ida_intel.py BIN search "login packet authentication"
%PYTHON_BIN_PATH% scripts\ida_advanced.py BIN index-search "network manager"
```

`rank` scores functions using complexity, graph connectivity, API categories and size. `index` builds the project/binary-scoped `semantic.sqlite` with FTS5 summaries and fingerprints. Use semantic retrieval before scanning thousands of functions. `index-search` prefers IDA 9.4's `ida_indexer` when available and falls back safely.

## Canonical function packets

Every important function should get a compact canonical packet rather than repeated ad-hoc queries:

```powershell
%PYTHON_BIN_PATH% scripts\ida_intel.py BIN packet 0x140012340
%PYTHON_BIN_PATH% scripts\ida_advanced.py BIN summary 0x140012340
```

Packets contain graph/complexity facts, calls, strings, constants, member offsets, semantic tags and a stable semantic fingerprint. Reuse them across later reasoning, version matching and project analysis.

## Structured Hex-Rays evidence

Do not request full pseudocode merely to learn calls, constants, strings, objects, assignments, member offsets, loops or returns. Use `ida_ctree.py`/canonical packets first. Use structured microcode via `ida_dataflow.py` when C-tree evidence is insufficient.

Microcode maturity guidance: `generated`/`preoptimized` for machine-near provenance; `calls` for call/argument questions; `locopt` for ordinary local data flow; `glbopt1..3` for increasingly optimized semantics; `lvars` for local-variable/type questions.

Text pseudocode and textual microcode are human-reading fallbacks, not default machine evidence.

## Real value-flow questions

A call path is not a data-flow proof. For “where did this value come from?” or “where can this input reach?” use:

```powershell
%PYTHON_BIN_PATH% scripts\ida_taint.py BIN FUNC reg:rax --direction backward
%PYTHON_BIN_PATH% scripts\ida_taint.py BIN FUNC stk:-32 --direction forward
```

The taint/slice engine builds bounded microcode def/use relationships across registers, stack variables and globals. Memory aliasing is approximate and must be described as such. Use `ida_advanced.py summary` semantic API effects to understand buffer reads/writes and transformations across calls. For important interprocedural paths, cache function summaries and traverse summaries before regenerating microcode.

## Indirect calls, C++ and structures

Direct xrefs are insufficient for C++ applications. Use:

```powershell
%PYTHON_BIN_PATH% scripts\ida_indirect.py BIN vtables
%PYTHON_BIN_PATH% scripts\ida_indirect.py BIN resolve FUNC
%PYTHON_BIN_PATH% scripts\ida_intel.py BIN cpp
%PYTHON_BIN_PATH% scripts\ida_intel.py BIN struct FUNC
```

Resolve vtables, callback/function-pointer tables and candidate indirect targets when evidence exists. Never turn an unresolved indirect call into a concrete edge merely because one target looks plausible. Aggregate repeated `this+offset` accesses across constructors/destructors/methods before naming fields. Conflicting widths are evidence against a proposed type and should be sent through `ida_advanced.py verify`.

## Dispatch/protocol recovery

For protocol handlers, state machines and callback dispatchers:

```powershell
%PYTHON_BIN_PATH% scripts\ida_intel.py BIN dispatch FUNC
```

Combine switch metadata, constants, registration APIs, indirect-call candidates and canonical packets. Build opcode-to-handler mappings incrementally and verify handler argument flow before assigning packet types.

## Cross-version matching

Build semantic indexes for both binaries, then:

```powershell
%PYTHON_BIN_PATH% scripts\ida_diff.py OLD NEW --min-confidence 0.72
```

Match exact semantic fingerprints first, then weighted semantic similarity for unmatched functions. Propagate names/types only for high-confidence mappings and verify them in the new version. Do not treat address proximity as identity.

## Signature recognition

Use `ida_signatures.py` to discover relevant FLIRT/signature files before wasting analysis on library/runtime code. Signature application is a database mutation and must follow the transactional/high-confidence mutation policy rather than being silently applied during discovery.

## IDA 9.4 compilation units and runtimes

Use:

```powershell
%PYTHON_BIN_PATH% scripts\ida_advanced.py BIN compilation-units
%PYTHON_BIN_PATH% scripts\ida_advanced.py BIN runtime
%PYTHON_BIN_PATH% scripts\ida_intel.py BIN modules
```

Prefer actual IDA compilation-unit/debug metadata when exposed. Only fall back to heuristic namespace/module clustering when true compilation units are unavailable. Preserve Swift calling conventions, Rust/Go metadata, Objective-C selectors/classes, MSVC RTTI/exception metadata and processor-specific analysis.

## Obfuscation and transformed strings

Use `ida_intel.py deobfuscate FUNC` to prioritize functions with flattening/opaque-predicate-like complexity and `ida_advanced.py stack-strings FUNC` to identify sequential local-buffer stores. These are candidate indicators, not automatic proof. Derived/transformed strings must carry provenance distinct from literal strings.

## Semantic constants and API knowledge

Use `ida_advanced.py constants FUNC` to annotate recognized OS/protocol/file/crypto constants. Function summaries attach semantic effects to known APIs such as input buffers, output buffers, length arguments, copies and process-execution calls. Prefer these roles over raw function-name matching when tracing values.

## Multi-binary projects

The project graph has a project-scoped default location, so callers should normally omit a database path:

```powershell
%PYTHON_BIN_PATH% scripts\ida_project.py add game.exe
%PYTHON_BIN_PATH% scripts\ida_project.py add network.dll
%PYTHON_BIN_PATH% scripts\ida_project.py query "PacketManager"
%PYTHON_BIN_PATH% scripts\ida_project.py info
```

The default is `.ida-re/projects/<project-id>/project.sqlite`. Use `--db PATH` only for an intentional custom database. The database stores its `project_id` and rejects use from a conflicting project identity. Link binaries through imports/exports, shared semantic fingerprints, names, strings and protocol artifacts.

## Evidence graph and contradictions

JSONL remains a portable log, but the project/binary-scoped `evidence.sqlite` is preferred working memory:

```powershell
%PYTHON_BIN_PATH% scripts\ida_evidence.py BIN claim-add function 0x140012340 purpose PacketDecode --confidence 0.9 --source ctree
%PYTHON_BIN_PATH% scripts\ida_evidence.py BIN query Packet
%PYTHON_BIN_PATH% scripts\ida_evidence.py BIN conflicts
%PYTHON_BIN_PATH% scripts\ida_evidence.py BIN info
```

Evidence databases record `project_id`, `project_root`, and `binary_id` internally and reject identity mismatches. Claims must record provenance/confidence. Resolve contradictions rather than quietly retaining whichever guess was encountered first.

## Autonomous investigators and frontier

Use specialist recipes for protocol, C++ class, crypto, filesystem, rendering and version-diff investigations:

```powershell
%PYTHON_BIN_PATH% scripts\ida_advanced.py BIN investigator protocol "recover login packet flow"
%PYTHON_BIN_PATH% scripts\ida_advanced.py BIN frontier-add "who initializes global X" --priority 8 --cost 2
%PYTHON_BIN_PATH% scripts\ida_advanced.py BIN frontier-next
```

The frontier orders unresolved questions by expected utility (`priority / cost`). Store answered questions as evidence before moving outward.

## Transactional database mutation

Names/types/comments are hypotheses until verified. `ida_apply_findings.py` defaults to `--mode plan` and records current state plus proposed changes. Apply only high-confidence findings, redecompile affected functions, verify the result, and roll back bad semantic changes.

## Batch/worker examples

```powershell
%PYTHON_BIN_PATH% scripts\ida_batch.py BIN plan.json
%PYTHON_BIN_PATH% scripts\ida_worker.py BIN
```

Send one JSON request per line to the worker, e.g. `{"op":"string","text":"Connection failed"}` or `{"op":"ctree","target":"0x140012340"}`. Use `{"op":"quit"}` to close. Prefer worker mode during long investigations because repeatedly opening IDA is needless overhead.

## Universal generated analysis

When no helper can express the required query, Claude may create a short temporary script and run:

```powershell
%PYTHON_BIN_PATH% scripts\ida_eval.py BIN temporary_analysis.py
```

Generated analysis must be bounded, purpose-specific and read-only by default. `--allow-write` is exceptional and follows the same high-confidence mutation rules.

## Default output budgets

Unless explicitly requested otherwise: search/string hits 30; callers/callees 20 each; call graph depth 2/80 nodes; path depth 12/8 paths/5000 explored nodes; C-tree 80 items/category; pseudocode 180 lines/function; disassembly 80 lines; structured microcode 120 events; taint slices 200 events; rank results 40. Never dump all functions, strings, xrefs or whole-program pseudocode.

## Preferred one-off helpers

```powershell
%PYTHON_BIN_PATH% scripts\ida_query.py BIN triage
%PYTHON_BIN_PATH% scripts\ida_query.py BIN string "literal"
%PYTHON_BIN_PATH% scripts\ida_ctree.py BIN FUNC
%PYTHON_BIN_PATH% scripts\ida_dataflow.py BIN FUNC --maturity locopt
%PYTHON_BIN_PATH% scripts\ida_path.py BIN SourceFunc TargetFunc --shortest
%PYTHON_BIN_PATH% scripts\ida_sourcesink.py BIN network_input process_execution
%PYTHON_BIN_PATH% scripts\ida_function_slice.py BIN FUNC
%PYTHON_BIN_PATH% scripts\ida_callgraph.py BIN FUNC --depth 2
%PYTHON_BIN_PATH% scripts\ida_query.py BIN pseudocode FUNC
%PYTHON_BIN_PATH% scripts\ida_query.py BIN disasm FUNC
```

## API policy

Prefer IDA Domain API. Use IDAPython/SDK where Domain lacks an operation, for lower-level verification, or for IDA 9.4 facilities not yet wrapped. Guard APIs that vary across ida-domain/IDA 9.4 point releases and provide bounded fallbacks rather than crashing the investigation.

## Reference loading

Load only what the task requires: `reference/ida94.md`, `domain-api.md`, `hexrays.md`, `workflows.md`, `type-recovery.md`, `platforms.md`, `apple-dsc.md`, or `troubleshooting.md`.

## Critical anti-patterns

- `auto_analysis=False` or decompiling before `auto_wait()`/Hex-Rays initialization.
- Enumerating every IDA string for an exact known literal.
- Reopening IDA for every step when batch/worker mode is applicable.
- Dumping pseudocode when a canonical packet/C-tree fact answers the question.
- Treating static call paths as runtime or value-flow proof.
- Treating pseudocode as machine truth.
- Treating unresolved indirect calls as concrete edges.
- Repeating queries already represented in canonical packets/evidence.sqlite.
- Applying low-confidence names/types/comments.
- Ignoring contradictions after new evidence appears.
- Reusing a SQLite database across conflicting project identities.
- Writing project state into the global skill-install directory.
- Unbounded graph, microcode, pseudocode or generated-code output.
