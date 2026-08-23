# Hex-Rays / C-tree / Microcode (IDA 9.4 + ida-domain 0.5)

## Mandatory initialization

Every helper enters through `_ida_session.open_database()`, which guarantees:

```python
IdaCommandOptions(auto_analysis=True, ...)
ida_auto.auto_wait()
assert ida_hexrays.init_hexrays_plugin()
```

Do not replace initialization with `ida_loader.load_plugin("hexx64")`.

## C-tree first

Use `db.pseudocode.decompile(ea)` and walk `PseudocodeFunction` objects. Prefer structured queries
for calls, constants, strings, objects, member offsets, assignments, variables, loops, and returns.

```powershell
%PYTHON_BIN_PATH% scripts\ida_ctree.py BIN 0xFUNC
```

Only request full pseudocode when semantic relationships remain unclear.

## Microcode maturity selection

Use `db.microcode.generate(func, MicroMaturity.X)` and inspect `MicroBlockArray.instructions()` plus
`MicroInstruction.operands()`.

Choose maturity intentionally:

- `ZERO` / `GENERATED`: lowest/near-generated representation;
- `PREOPTIMIZED`: after early cleanup;
- `LOCOPT`: locally optimized, good general default;
- `CALLS`: useful for recovered call information/arguments;
- `GLBOPT1/2/3`: progressively more global optimization;
- `LVARS`: local-variable/type-oriented final form.

Earlier maturity can preserve provenance hidden by optimization. Later maturity can simplify
semantic questions. Compare stages when a conclusion depends on optimization.

`MicroOperand` can expose numbers, strings, global addresses, registers, stack offsets, nested
instructions, and `call_info`. `MicroCallInfo` can expose callee, arguments, calling convention,
and return type.

```powershell
%PYTHON_BIN_PATH% scripts\ida_dataflow.py BIN 0xFUNC --maturity calls
%PYTHON_BIN_PATH% scripts\ida_dataflow.py BIN 0xFUNC --maturity generated --match "0x17"
```

Textual `db.microcode.get_text()` is a fallback for human inspection, not the default analysis API.

## Decompiler string harvesting

After decompilation, collect bounded `find_strings()` results as new seeds. Keep the primary exact
known-string search byte-backed because it avoids enumerating the entire Strings list.

## Verification

When a conclusion depends on signedness, pointer arithmetic, field offsets, indirect calls,
optimized control flow, compiler artifacts, or language-specific calling conventions, verify with
at least one independent source: disassembly, CFG, xrefs, callers, C-tree, operands, or microcode.
