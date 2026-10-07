# Evidence, Unknowns, Completion, and Cache Discipline

## Evidence envelopes

Every material observation should be recorded with `ida_evidence.py observe-add`. The record is
content-addressed as `ev_<sha256>` from the binary digest, provider/profile identity, operation,
parameters, normalized result, confidence, authority, limitations, locations, and linked evidence.
The local filesystem path is stored for navigation but excluded from semantic identity.

Confidence is categorical:

- `observed`: directly returned by the declared analysis/capture operation;
- `derived`: mechanically composed from observations;
- `inferred`: analyst/agent interpretation.

Authority is separate from confidence:

- `shipped-artifact`: bytes/metadata/decompiler facts from the current target;
- `controlled-replay`: bounded runtime/process capture of a declared scenario;
- `historical-reference`: old source, symbols, earlier versions, documentation, or analogous builds;
- `external-service`: optional external preprocessors such as JADX/Binwalk/Unblob;
- `analyst-inference`: hypotheses, classifications, or design interpretation.

Never promote historical-reference, external-service, or analyst-inference to shipped-artifact.
Never describe static evidence as runtime execution.

## Analysis profile commitment

`open_database()` automatically persists `analysis_profile.json`. `ida_profile.py BIN` emits it
explicitly. The digest includes IDA, Hex-Rays and ida-domain versions plus architecture/bitness and
mandatory analysis settings. Semantic indexes and exact snapshots must match this digest.

If a cache/profile mismatch occurs, rebuild. Do not silently use old results after an IDA/Hex-Rays
upgrade or materially different analysis profile.

## Exact query snapshots

Use `ida_cache.py` for expensive immutable results:

```text
python scripts/ida_cache.py BIN get operation params.json
python scripts/ida_cache.py BIN put operation params.json result.json
```

The key is exactly:

`binary SHA-256 + analysis-profile digest + operation + canonical parameters`.

A miss is not an error. A profile mismatch is not a cache hit. Mutation-dependent or cursor/stateful
operations should not be treated as immutable snapshots.

## Revisioned residual unknowns

An unresolved question is a first-class record, not a sentence buried in notes. Create one with:

```text
python scripts/ida_evidence.py BIN unknown-add unknown.json
```

Store required authority/confidence/environment, supporting and contradicting Evidence IDs,
recommended probes, severity, and dependencies. Updates require `expected_revision`; stale writes
fail instead of silently overwriting newer work.

Only qualifying evidence may resolve an unknown. A `verified` resolution requires evidence IDs.
Contradicted unknowns require contradicting evidence. Supporting and contradicting sets may not
contain the same Evidence ID.

## Fail-closed completion ledger

For each question the investigation promised to answer, produce exactly one completion record:
`pass`, `fail`, `unsupported`, `truncated`, or `unknown`, with Evidence IDs. Build the ledger with:

```text
python scripts/ida_evidence.py BIN completion-build records.json
```

`complete=true` only when every required record is `pass`. Missing, unsupported, truncated, failed,
or unknown work never aggregates into success.

## Contradictions

The legacy claim graph still surfaces incompatible active claims. Do not delete one merely to make
the report tidy. Preserve both, attach evidence, create/mark a residual unknown, and run a probe with
the authority needed to discriminate between them.
