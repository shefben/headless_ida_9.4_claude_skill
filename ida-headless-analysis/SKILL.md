---
name: ida-headless-analysis
description: Reverse engineer EXE, DLL, ELF, Mach-O, firmware and other binaries headlessly with IDA Pro 9.4/idalib using an evidence-driven, token-bounded workflow, mandatory auto-analysis + Hex-Rays, structured C-tree/microcode extraction, persistent findings, path analysis, and type recovery.
---

# IDA 9.4 Headless Reverse Engineering

## Environment

- IDA: `%IDA_PATH%`
- Python: `%PYTHON_BIN_PATH%`
- ida-domain: `>=0.5.0,<0.6.0`
- Set `IDADIR=%IDA_PATH%`.

## Mandatory Session Invariants

**Every binary MUST be opened through `scripts/_ida_session.py:open_database()`.**

The wrapper always:
1. sets `IDADIR`;
2. uses `IdaCommandOptions(auto_analysis=True, ...)` for new and cached DBs;
3. calls `ida_auto.auto_wait()`;
4. calls `ida_hexrays.init_hexrays_plugin()`;
5. aborts if Hex-Rays initialization fails;
6. closes cleanly via a context manager.

Never use ad-hoc `Database.open()` in analysis helpers. Never set `auto_analysis=False`.
Never substitute `ida_loader.load_plugin("hexx64")` for Hex-Rays initialization.
Any project-specific wrapper is allowed only if it enforces the same invariants.

## Analysis Strategy

Use this escalation ladder and stop as soon as evidence answers the question:

`cache -> triage -> seed -> exact strings/constants -> xrefs -> callers/callees -> C-tree facts -> pseudocode -> CFG/assembly -> microcode -> type recovery -> verification`

Before an expensive query, know what it should prove or disprove. Prefer targeted evidence over
whole-binary exploration. Check `.ida-re/` before rediscovering established facts.

Treat function names, prototypes, structs, compiler artifacts, decompiler output, and inferred
language/runtime metadata as hypotheses until independently supported.

## Fast Exact-String Rule

For a known literal string, **search encoded bytes first**. Do not enumerate the full IDA Strings
list. `ida_query.py string` scans mapped segments with `db.bytes.find_bytes_between()` using
ASCII/UTF-8 and UTF-16LE by default, then annotates hits with xrefs/functions.

IDA 9.4 may add strings recovered during decompilation to the Strings list. Harvest those as new
analysis seeds after decompilation, but do not replace byte-backed exact search with global string
enumeration.

```powershell
%PYTHON_BIN_PATH% scripts\ida_query.py BIN string "Connection failed"
%PYTHON_BIN_PATH% scripts\ida_query.py BIN strings --regex "packet|opcode"
```

## Prefer Structured Decompiler Evidence

Do not request full pseudocode merely to learn calls, constants, strings, member offsets, objects,
assignments, loops, or returns. Use `ida_ctree.py` first. It traverses Domain API 0.5 C-tree
objects and produces compact JSON evidence.

Use `ida_dataflow.py` for structured microcode. Select the maturity that fits the question:

- `generated` / `preoptimized`: machine-near provenance and transformations;
- `calls`: call/argument questions;
- `locopt`: normal local data-flow questions (default);
- `glbopt1..3`: increasingly optimized semantics;
- `lvars`: local-variable/type-oriented questions.

Textual pseudocode/microcode is a fallback for human reading, not the default evidence format.

## Path / Source-Sink Analysis

Use `ida_path.py` for bounded shortest/all call paths between functions or imports. Use
`ida_sourcesink.py` to test built-in source/sink groups (network input, file input, process
execution, unsafe memory, crypto) without dumping the full call graph.

Paths are hypotheses about reachable call-reference chains, not proof of runtime reachability.
Verify important paths against conditions/data flow.

## Decompiler Skepticism

Hex-Rays pseudocode is evidence, not machine truth. Verify important conclusions involving casts,
signedness, field offsets, virtual/indirect calls, switches, pointer arithmetic, aliases,
optimization/inlining, calling conventions, or malformed control flow against instructions, xrefs,
CFG, callers, operands, C-tree, or microcode.

## Token / Output Budget

Defaults unless the user explicitly requests more:

- searches / string hits: 30;
- callers/callees: 20 each;
- call graph: depth 2, 80 nodes;
- path search: depth 12, 8 paths, 5,000 explored nodes;
- C-tree facts: 80 items/category;
- pseudocode: 180 lines/function;
- disassembly: 80 lines;
- microcode structured events: 120.

Never emit all functions, strings, xrefs, whole-program pseudocode, or large microcode dumps.
Save oversized raw results under `.ida-re/<binary-id>/queries/` and return a compact summary/path.

## Persistent State / Evidence

Store project state under:

```text
.ida-re/<binary-id>/
  manifest.json
  functions/
  queries/
  findings.jsonl
  hypotheses.jsonl
  unresolved.jsonl
```

Important function records should contain address/name, purpose, confidence, prototype/arguments,
important callers/callees, strings/constants, state/field accesses, compilation unit when
available, language/runtime hints, evidence, contradictions, unresolved questions, and provenance.
Do not preserve giant pseudocode dumps as memory.

## Preferred Helpers

```powershell
%PYTHON_BIN_PATH% scripts\ida_query.py BIN triage
%PYTHON_BIN_PATH% scripts\ida_query.py BIN string "literal"
%PYTHON_BIN_PATH% scripts\ida_ctree.py BIN 0x140012340
%PYTHON_BIN_PATH% scripts\ida_dataflow.py BIN 0x140012340 --maturity locopt
%PYTHON_BIN_PATH% scripts\ida_path.py BIN SourceFunc TargetFunc --shortest
%PYTHON_BIN_PATH% scripts\ida_sourcesink.py BIN network_input process_execution
%PYTHON_BIN_PATH% scripts\ida_function_slice.py BIN 0x140012340
%PYTHON_BIN_PATH% scripts\ida_callgraph.py BIN 0x140012340 --depth 2
%PYTHON_BIN_PATH% scripts\ida_query.py BIN pseudocode 0x140012340
%PYTHON_BIN_PATH% scripts\ida_query.py BIN disasm 0x140012340
```

Use `ida_apply_findings.py` only for high-confidence semantic conclusions.

## IDA 9.4 Platform Awareness

During triage, preserve IDA's recovered language/runtime/platform evidence. In particular do not
flatten away Swift calling-convention semantics, Rust/Go metadata, Objective-C selectors, or
processor-specific analysis. Load `reference/ida94.md`, `reference/platforms.md`, or
`reference/apple-dsc.md` only when relevant.

IDA 9.4 can reconstruct compilation-unit groupings from multiple debug/object formats and Go.
When that information is accessible, use it to cluster functions by likely original source module.
Do not invent a compilation unit when IDA does not expose one to the active scripting API.

## Type Recovery

Infer types/prototypes from multiple accesses and call sites, record confidence, apply only
high-confidence facts, redecompile affected functions, and verify that the result improves
consistently. Preserve strong IDA 9.4 language/runtime type information rather than overwriting it
with weaker guesses.

## API Policy

Prefer IDA Domain API. Use IDAPython/SDK when Domain API lacks the operation, lower-level
verification is needed, or IDA 9.4-specific facilities are not yet wrapped. Domain API and
IDAPython are designed to coexist.

## Reference Loading

Load only what the current task needs:

- `reference/ida94.md` — IDA 9.4 behavior relevant to headless reversing
- `reference/domain-api.md` — Domain/SDK and byte-search patterns
- `reference/hexrays.md` — C-tree, decompiler, microcode, maturity selection
- `reference/workflows.md` — investigation recipes
- `reference/type-recovery.md` — prototypes/structures/naming
- `reference/platforms.md` — Swift/Rust/Go/Hexagon/RISC-V/etc.
- `reference/apple-dsc.md` — IDA 9.4 Dyld Shared Cache workflow
- `reference/troubleshooting.md` — setup, locks, failures

## Critical Anti-Patterns

- `auto_analysis=False` in a decompilation workflow.
- Decompiling before `ida_auto.auto_wait()` or successful `ida_hexrays.init_hexrays_plugin()`.
- Enumerating all strings when exact byte search suffices.
- Parsing textual pseudocode/microcode when structured C-tree/microcode can answer the question.
- Whole-binary dumps for targeted questions.
- Treating a Pathfinder/call path as proof the path executes at runtime.
- Treating pseudocode as authoritative semantics.
- Repeating findings already cached.
- Renaming/retyping low-confidence hypotheses.
- Unbounded call graphs or output.
