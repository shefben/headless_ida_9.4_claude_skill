# Runtime, Artifact, Historical-Source, and Optional Front-End Evidence

## Package/artifact inspection

Use `ida_artifact.py BIN inspect` before deep native analysis when container context matters. ZIP/APK
inventory is execution-free and reports bounded member metadata, encryption flags and native-library
presence. Artifact inventory does not establish runtime behavior.

Optional external preprocessors are explicit:

```text
python scripts/ida_artifact.py firmware.bin external binwalk
python scripts/ida_artifact.py firmware.bin external unblob --out-dir extracted
python scripts/ida_artifact.py app.apk external jadx --out-dir jadx-out
```

Provide tools separately with `IDA_RE_BINWALK`, `IDA_RE_UNBLOB`, `IDA_RE_JADX`, or
`JADX_HEADLESS_JAR`/`JAVA_BIN`. Their results enter evidence as `external-service`. They are not a
replacement for IDA/Hex-Rays proof and must be corroborated for native semantic claims.

For NativeAOT, stripped managed/native hybrids, or another analyzer's metadata, import the tool's
output as external evidence and retain exact artifact/provider/version identity. Do not claim CIL or
original source when the image is native code.

## Historical source

Use:

```text
python scripts/ida_reference.py BIN /path/to/older/source
```

The source tree is hashed and inventoried as `historical-reference`. It may explain names, formats,
algorithms or architecture, but does not prove the current binary implements the same behavior.
Current-binary evidence must remain independently addressable.

## Typed call edges

`ida_indirect.py BIN resolve FUNC` emits every inspected callsite with one of:

- `direct`: IDA code reference identifies the target;
- `resolved-indirect`: exactly one evidence-backed pointer target was recovered;
- `candidate`: multiple plausible indirect targets remain;
- `unresolved`: no supported target is known.

Only `direct` and `resolved-indirect` edges are concrete traversal edges. Candidate edges should
become frontier/unknown work, not silently chosen because one name looks attractive.

## Bounded interprocedural value graph

Use:

```text
python scripts/ida_value_trace.py BIN FUNC --max-depth 3 --max-functions 16
```

The graph joins local Hex-Rays microcode def/use edges with only concrete typed call edges.
Function/call/node/edge/depth budgets are explicit. Budget exhaustion, ambiguous calls, unavailable
microcode, aliasing and missing cross-function argument/return bindings remain listed as unknowns.

This graph is stronger than a call path but is still decompiler-derived. For a critical field,
argument, length or pointer, verify the final claim against C-tree/microcode and instructions.

## Tool-effect contracts

`ida_capabilities.py` exposes whether an operation is read-only, destructive, idempotent/open-world,
and which side effects/prerequisites apply. Autonomous planning should inspect this before choosing
runtime capture, database mutation, generated evaluation, or external extraction.

Mutation and process execution must never be disguised as ordinary inspection.
