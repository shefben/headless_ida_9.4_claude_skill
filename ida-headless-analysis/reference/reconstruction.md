# Reconstruction Obligations and Verification

Reverse engineering for reimplementation is not complete when pseudocode looks plausible. Convert
required behavior into reconstruction obligations and close them with comparable evidence.

## Obligation structure

A required obligation should contain:

- stable `obligation_id` and version;
- behavior-oriented title;
- unique implementation owner: `module_path`, `symbol`, `owner_sha256`;
- parser/schema/domain type when the behavior parses structured data;
- required case kinds such as `positive`, `negative`, `malformed`, `cancellation`, `teardown`;
- authenticated original-case Evidence IDs;
- authenticated reconstruction-case Evidence IDs;
- residual unknown IDs;
- contradictions and unavailable authority;
- one passing verifier with the required authority.

Load/evaluate with:

```text
python scripts/ida_evidence.py BIN obligation-add obligation.json
python scripts/ida_evidence.py BIN obligation-evaluate obligation.id
python scripts/ida_evidence.py BIN obligation-list
```

The evaluator fails closed. A required obligation is `ready` only when ownership, required types,
all required original/reconstruction cases, unknown closure, contradiction state, and verifier
authority are satisfied. Missing proof yields `open`; explicit verifier failure or contradiction
yields `failed`.

## Controlled original-vs-reconstruction comparison

Create explicit process scenarios for the shipped implementation and reconstruction:

```text
python scripts/ida_capture.py capture authority.json --subject BIN
python scripts/ida_capture.py capture candidate.json --subject BIN
python scripts/ida_capture.py compare authority.capture.json candidate.capture.json --subject BIN
```

A scenario declares the exact command, working directory, environment overrides, timeout, stdin and
filesystem snapshot paths. The helper runs with the caller's permissions and is not a sandbox.
Network behavior is not captured by this helper.

Comparison evaluates each observed dimension separately and identifies the first divergence.
Truncated dimensions become `unknown`, never `equal`. `equivalent_within_declared_dimensions=true`
means only that the finite declared comparison passed. It is not whole-program equivalence.

## Recommended case policy

Protocol/parser/storage/ABI obligations normally require at least positive, negative and malformed
cases. Stateful startup/shutdown behavior should add teardown. Concurrency/cancellation behavior
should add cancellation. Security-sensitive parsers should include boundary-length and truncated
inputs. Do not generate cases from imagination when the original behavior can be captured.
