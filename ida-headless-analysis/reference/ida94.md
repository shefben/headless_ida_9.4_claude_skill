# IDA 9.4 Headless-Relevant Changes

Load this only when a task benefits from IDA 9.4-specific behavior.

## Domain API 0.5

IDA 9.4 ships alongside ida-domain 0.5.0, which adds first-class `db.pseudocode`, `db.microcode`,
and `db.imports` facilities. Prefer structured objects to regex over textual pseudocode/microcode.
Domain API complements IDAPython; use SDK fallbacks for unwrapped 9.4 features.

## Decompiler-discovered strings

IDA 9.4 can surface strings found during decompilation into IDA's string knowledge. Treat these as
new investigation seeds after decompilation. This does not replace the skill's exact byte-search
rule for known literals.

## Compilation units

IDA 9.4 can reconstruct source compilation-unit grouping from formats including COFF, PDB, DWARF,
OMF, TDS, PSX and Go. When scripting access is available for the loaded format, preserve this
information in evidence packets and use it to cluster functions by likely original source module.
Never manufacture a unit name from neighboring function names alone.

## Pathfinder concept

The GUI Pathfinder answers how execution references can connect locations. `scripts/ida_path.py`
provides a token-bounded headless analogue over call/code references. Static paths are leads, not
proof all conditions are simultaneously satisfiable.

## Database indexer

IDA 9.4 exposes the database indexer used by Jump Anywhere. Do not enable/use it for operations
already cheaper through direct APIs:

- known literal -> byte search;
- known symbol -> name/import API;
- known EA -> direct query;
- broad interactive/semantic database lookup -> indexer may be useful through an SDK fallback.

## Performance improvements

9.4 improves large DWARF/name-heavy loading and frame analysis. Let auto-analysis finish. Do not
turn analysis off merely because a cached database exists.

## Loaders/processors

9.4 adds Qualcomm Hexagon/QDSP6 plus Qualcomm MBN support, MCore/C-Sky V1, and expands several
processor families. Let IDA's loader/processor analysis establish architecture semantics before
applying generic assumptions.
