# Type and Structure Recovery

## Confidence model

- 0.50: plausible hypothesis;
- 0.70: supported by multiple local observations;
- 0.85: supported across functions/callers;
- 0.90+: safe candidate for IDB mutation;
- 0.98+: exceptionally strong, e.g. RTTI/debug/export/source corroboration.

Default `ida_apply_findings.py` threshold is 0.90.

## Structure fields

For each offset record:

- offset;
- access width;
- read/write;
- arithmetic/comparison use;
- functions using it;
- constants associated with it;
- whether it is dereferenced;
- whether constructor/destructor touches it.

Do not infer a struct layout from one decompiled function.

## Function prototypes

Cross-check caller setup, return-value use, register/stack convention, callee accesses,
sibling/virtual methods, and imported API expectations.

Incorrect prototypes can poison decompilation far beyond one function.

## Feedback loop

1. make a typed hypothesis;
2. save evidence;
3. apply at high confidence;
4. redecompile multiple affected functions;
5. ensure the change reduces casts/ambiguity consistently;
6. if it makes neighboring functions worse, reconsider it.

## Names

Prefer semantic, role-based names such as `Packet_Dispatch`, `Connection_SetTimeout`, or
`Player_GetHealth`.

Avoid names that overstate certainty. `DecryptAES` is bad if evidence only proves that a buffer is
transformed; use `Buffer_Transform` until the algorithm is established.
