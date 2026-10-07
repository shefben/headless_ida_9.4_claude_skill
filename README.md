# Claude IDA Headless Reverse-Engineering Skill v4.0.0 (IDA 9.4)

This bundle targets IDA Pro 9.4 + ida-domain 0.5.x and provides a proof-oriented headless reverse-engineering workflow for Claude-style coding agents. It keeps IDA/Hex-Rays as the native-analysis authority while adding deterministic provenance, explicit uncertainty, fail-closed completion, reconstruction verification, controlled runtime comparison, and optional artifact preprocessors.

Major features:

- mandatory `auto_analysis=True`, `ida_auto.auto_wait()`, and successful `ida_hexrays.init_hexrays_plugin()` on every IDA session;
- preserve-first IDB/i64 lock diagnostics instead of destructive database deletion;
- exact byte-backed ASCII/UTF-8/UTF-16LE string search;
- structured C-tree and bounded structured Hex-Rays microcode extraction;
- local taint/slicing plus bounded interprocedural value/call graphs;
- typed call edges: `direct`, `resolved-indirect`, `candidate`, `unresolved`;
- canonical function packets, semantic fingerprints, ranking and FTS5 retrieval;
- profile-bound semantic indexes and exact immutable query snapshots;
- deterministic Evidence envelopes with content-derived `ev_<sha256>` IDs;
- separate evidence confidence (`observed`, `derived`, `inferred`) and authority classes;
- revisioned residual unknowns with contradiction/support evidence and stale-write protection;
- fail-closed completion ledgers;
- reconstruction obligation ledgers with original/candidate case coverage and verifier authority;
- controlled process capture and first-divergence comparison;
- historical-source inventory isolated from current-binary evidence;
- package/APK/firmware inventory plus optional explicitly supplied JADX/Binwalk/Unblob adapters;
- tool-effect contracts for autonomous planning and mutation/runtime awareness;
- pure-Python conformance tests plus static package validation;
- project-isolated state under `.ida-re/projects/<project-id>/binaries/<binary-id>/`;
- worker/batch modes to avoid repeatedly reopening idalib during long investigations.

## Installation

1. Extract this bundle to a temporary directory.
2. Open a terminal in the extracted directory.
3. Run the setup script for your platform:
   - Windows: `./setup.ps1`
   - Linux: `chmod +x setup.sh && ./setup.sh`

The setup script copies `ida-headless-analysis` into your Claude skills directory, resolves IDA/Python paths, and installs the required Python dependencies.

After installation, validate the package with:

```bash
python ~/.claude/skills/ida-headless-analysis/scripts/validate_skill.py
```

The validator also executes the pure-Python evidence/unknown/completion/reconstruction conformance suite. It does not require opening an IDA target.

## New v4 proof/verification helpers

```text
scripts/ida_profile.py        analysis-profile commitment
scripts/ida_cache.py          exact profile-bound query snapshot cache
scripts/ida_evidence.py       evidence / unknown / completion / obligation registry
scripts/ida_value_trace.py    bounded interprocedural microcode value graph
scripts/ida_capture.py        controlled process capture and comparison
scripts/ida_reference.py      historical-source inventory
scripts/ida_artifact.py       package/APK/firmware inventory + optional adapters
scripts/ida_capabilities.py   tool-effect contracts
scripts/conformance_test.py   pure-Python semantic conformance checks
```

See `ida-headless-analysis/SKILL.md` and the progressive reference files for the operating rules and workflows.
