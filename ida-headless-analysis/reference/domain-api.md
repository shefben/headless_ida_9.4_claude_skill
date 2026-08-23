# IDA Domain API Reference (0.5.x)

Load this file only when API syntax is needed.

## Database lifecycle

All headless sessions use `scripts/_ida_session.py:open_database()`. The wrapper explicitly uses
`IdaCommandOptions(auto_analysis=True, ...)`, waits for `ida_auto.auto_wait()`, and initializes
Hex-Rays. Reopening a cached I64 never disables analysis.

## Important modules

| Property | Use |
|---|---|
| `db.bytes` | bytes, cstrings, exact binary searches |
| `db.imports` | import modules/symbols (`get_all_imports`) |
| `db.entries` | exported/named entry points |
| `db.functions` | functions, callers/callees, disassembly, locals |
| `db.instructions` / `db.operands` | instruction-level verification |
| `db.segments` | mapped ranges |
| `db.strings` | discovery/fuzzy string-list searches |
| `db.types` | declarations and types |
| `db.xrefs` | references |
| `db.pseudocode` | structured Hex-Rays C-tree |
| `db.microcode` | structured Hex-Rays microcode |

## Exact literal strings: byte search first

For a known string literal, encode bytes and search mapped segments directly. The shipped
`ida_query.py string` command does this with ASCII/UTF-8 and UTF-16LE and stops at the hit budget.
Use `db.strings.get_all()` only for discovery when the literal is not known exactly.

## Imports

Prefer:

```python
for imp in db.imports.get_all_imports():
    print(imp.module_name, imp.name, hex(int(imp.address)), imp.ordinal)
```

Do not reimplement import callbacks unless Domain API is unavailable.

## Pseudocode

```python
fn = db.pseudocode.decompile(ea)
for expr in fn.walk_expressions():
    if expr.is_number:
        print(expr.number.unsigned_value)
```

Use `find_calls`, `find_strings`, `find_assignments`, `find_objects`, `find_loops`, and variable
reference helpers when those directly answer the question.

## Microcode

```python
from ida_domain.microcode import MicroMaturity
mba = db.microcode.generate(func, MicroMaturity.LOCOPT)
for insn in mba.instructions():
    for op in insn.operands():
        ...
```

## SDK fallback policy

Use low-level IDAPython/SDK for functionality not wrapped by Domain API, processor/loader-specific
operations, exact callsites, database-indexer use, compilation-unit access where exposed only in
SDK, or IDA 9.4 DSC facilities. Domain API and SDK objects can coexist.
