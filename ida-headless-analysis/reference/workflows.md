# Reverse-Engineering Workflows

Load only the workflow relevant to the current task.

## Unknown binary triage

1. `ida_query.py BIN triage`
2. classify architecture/subsystems from imports, exports, segments;
3. use exact byte-backed string searches for known anchors;
4. use bounded string-list discovery only when anchors are unknown;
5. rank subsystem seeds;
6. follow xrefs only for the question at hand;
7. create function slices for important candidates;
8. store findings.

Do not enumerate every function.

## Find implementation behind a known string

1. `ida_query.py BIN string "literal"` (byte-backed ASCII/UTF-16LE search);
2. inspect returned xref/function context;
3. identify containing/calling functions;
4. inspect callers/callees;
5. targeted pseudocode;
6. verify important behavior in assembly if needed.

Do not begin by rebuilding or dumping the global IDA Strings list.

## Discover unknown strings by theme

1. use `strings --contains` or `strings --regex` with a narrow expression;
2. cap results;
3. take promising literals and rerun them through exact `string` byte search to get direct hits;
4. follow xrefs/functions.

## Recover a protocol/packet handler

1. locate message IDs, error strings, registration tables, socket/serialization imports;
2. identify dispatch function;
3. inspect switch/table/xrefs;
4. map handlers one at a time;
5. infer packet structure from repeated field offsets;
6. apply only stable types;
7. redecompile and verify;
8. save packet/function evidence.

## Recover a C++ class/vtable

1. identify vtable/RTTI/constructors if present;
2. collect methods touching the same `this` offsets;
3. group offsets by width/use;
4. separate base/derived behavior;
5. identify virtual slots from indirect call patterns;
6. hypothesize structure;
7. test on constructors, destructor, and multiple methods;
8. apply type only when consistent.

## Compare two binary versions

1. triage both;
2. anchor on exports, byte-searched strings, known functions, constants, CFG shape;
3. map high-confidence correspondences;
4. inspect only changed/unmatched regions;
5. store mappings/evidence;
6. propagate names/types only after validation.

## Trace a field

Question: "What is field +0x38?"

1. find reads/writes of the offset in candidate methods;
2. classify access widths and operations;
3. inspect initialization/constructor;
4. inspect call arguments derived from it;
5. inspect comparisons/constants;
6. check related offsets for structure boundaries;
7. assign a semantic name only after multiple uses agree.

## Decompiler disagreement

1. inspect function boundaries;
2. inspect CFG;
3. inspect exact instructions;
4. verify operand size/signedness;
5. check calling convention/prototype;
6. inspect microcode if value propagation remains unclear;
7. correct types/prototype;
8. redecompile;
9. compare before/after.


## IDA 9.4 structured function analysis

1. resolve the seed function;
2. run `ida_ctree.py` for calls/constants/strings/member offsets/returns;
3. if value propagation is unclear, run `ida_dataflow.py` at `locopt`;
4. compare `generated`/`preoptimized` vs `locopt` when optimization may hide provenance;
5. request full pseudocode only when relationships cannot be represented compactly;
6. verify critical conclusions against instructions/CFG.

## Find a path from A to B

1. `ida_path.py BIN A B --shortest`;
2. inspect the shortest static call-reference chain;
3. remove irrelevant wrappers with `--exclude-regex` if needed;
4. use `--all-paths` only when alternatives matter;
5. inspect branch conditions and data flow along promising paths;
6. never describe a static path as guaranteed runtime reachability.

## Source-to-sink candidate flow

1. `ida_sourcesink.py BIN network_input process_execution` (or another built-in group pair);
2. take the shortest few candidate paths only;
3. inspect C-tree call arguments at each edge;
4. use microcode at `calls`/`locopt` maturity for argument propagation;
5. only claim a value flow after the actual data dependence is supported.

## Investigate a feature with evidence closure

1. Write a bounded checklist of questions before expanding the graph.
2. Reuse exact snapshots/evidence whose binary SHA-256 and analysis-profile digest match.
3. Start with the smallest useful artifact/function inventory and semantic seeds.
4. Follow typed call edges and compact function packets before pseudocode dumps.
5. Record each material observation as Evidence with authority/confidence/limitations.
6. Create residual unknowns for ambiguity, contradictions, budget truncation, or missing authority.
7. Use runtime capture only when static evidence cannot answer the required question.
8. Build a completion ledger for the original checklist; do not declare completion unless all required claims pass.

## Compare application/binary versions conservatively

1. Build semantic indexes for both versions under matching analysis-profile digests.
2. Exact fingerprint matches first, weighted similarity only for unmatched functions.
3. Keep added/removed/unmatched regions explicit rather than forcing a correspondence.
4. Record static differences as candidates, not proof of changed runtime behavior.
5. If behavior matters, run matched controlled scenarios and compare by dimension.
6. Preserve truncation/unsupported dimensions as unknown.

## Verify a reconstruction

1. Convert required behaviors into stable reconstruction obligations.
2. Give every required obligation one implementation owner and owner digest.
3. Add parser/schema/domain types where structured input is involved.
4. Capture required original cases: positive, negative, malformed, plus cancellation/teardown where relevant.
5. Capture the same cases for the reconstruction.
6. Resolve or explicitly block every residual unknown referenced by the obligation.
7. Run a verifier with authority comparable to the original observation.
8. Close only when `obligation-evaluate` reports `ready`.

## Trace a crash

1. Record exact target digest/build, inputs, exit/crash symptom, and environment.
2. Search error strings/imports/exceptions and identify candidate static routes.
3. Inspect relevant C-tree/microcode, branch conditions, and types.
4. Record competing hypotheses as residual unknowns.
5. If safe and necessary, run one bounded controlled scenario reproducing the crash.
6. Correlate runtime symptom with static evidence without claiming causality from proximity alone.
7. Completion must distinguish root cause proved, contributing factor, and unresolved alternatives.

## Audit residual unknowns

1. `ida_evidence.py BIN unknown-list`.
2. Prioritize contradicted, critical/high severity, and dependency-blocking unknowns.
3. For each, inspect `required_authority`, `required_confidence`, and environment.
4. Choose the cheapest probe that can actually satisfy those requirements.
5. Update with the current expected revision; stale updates must be reread and reconciled.
6. Do not resolve with a lower-authority observation than the unknown requires.

## Prepare bounded process capture

1. Declare exact command, cwd, environment overrides, timeout, stdin and snapshot paths.
2. Do not broaden execution beyond the declared scenario.
3. Capture original and reconstruction separately.
4. Treat stdout/stderr/filesystem truncation as unknown.
5. Compare dimensions independently and inspect the first divergence.
6. Record the comparison as controlled-replay Evidence and link it to the relevant obligation/unknown.
