"""Static validator for the IDA 9.4 skill package; does not require IDA."""
from __future__ import annotations

from pathlib import Path
import ast
import json

ROOT = Path(__file__).resolve().parents[1]


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    raise SystemExit(1)


skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
session = (ROOT / "scripts" / "_ida_session.py").read_text(encoding="utf-8")
query = (ROOT / "scripts" / "ida_query.py").read_text(encoding="utf-8")
dataflow = (ROOT / "scripts" / "ida_dataflow.py").read_text(encoding="utf-8")
ctree = (ROOT / "scripts" / "ida_ctree.py").read_text(encoding="utf-8")
path = (ROOT / "scripts" / "ida_path.py").read_text(encoding="utf-8")

for token in (
    "IDA Professional 9.4_headless", "auto_analysis=True", "ida_auto.auto_wait()",
    "ida_hexrays.init_hexrays_plugin()", "Fast Exact-String Rule", "Token / Output Budget",
    "Prefer Structured Decompiler Evidence", "Path / Source-Sink Analysis",
):
    if token not in skill:
        fail(f"SKILL.md missing required policy: {token}")

if "9.3_headless" in skill or "9.3_headless" in session:
    fail("stale IDA 9.3 headless path remains in mandatory files")

for token in ("auto_analysis=True", "_wait_for_auto_analysis()", "_initialize_hexrays()", "with Database.open("):
    if token not in session:
        fail(f"_ida_session.py missing invariant implementation: {token}")

for token in ("find_bytes_between", "utf-16le", 'mode": "byte-search', "_xref_context", "get_all_imports"):
    if token not in query:
        fail(f"ida_query.py missing required 9.4/fast-search feature: {token}")

for token in ("db.pseudocode.decompile", "walk_expressions", "find_strings", "member_offset"):
    if token not in ctree:
        fail(f"ida_ctree.py missing structured C-tree feature: {token}")

for token in ("db.microcode.generate", "MicroMaturity", "mba.instructions()", "insn.operands()", "call_info"):
    if token not in dataflow:
        fail(f"ida_dataflow.py missing structured microcode feature: {token}")

for token in ("find_paths", "max_depth", "max_nodes", "Static reference path"):
    if token not in path:
        fail(f"ida_path.py missing bounded path feature: {token}")

for required in ("reference/ida94.md", "reference/platforms.md", "reference/apple-dsc.md", "scripts/ida_sourcesink.py"):
    if not (ROOT / required).exists():
        fail(f"missing required file: {required}")

# Ensure all Python parses.
for py in (ROOT / "scripts").glob("*.py"):
    try:
        ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
    except SyntaxError as exc:
        fail(f"syntax error in {py.name}: {exc}")

# All live IDA helpers must route through mandatory session wrapper.
exceptions = {"_ida_session.py", "_common.py", "validate_skill.py", "ida_state.py"}
for py in (ROOT / "scripts").glob("*.py"):
    if py.name in exceptions:
        continue
    text = py.read_text(encoding="utf-8")
    if "from _ida_session import open_database" not in text:
        fail(f"{py.name} does not import mandatory open_database wrapper")
    if "Database.open(" in text:
        fail(f"{py.name} calls Database.open() directly")

# Schema must remain valid JSON and include new evidence fields.
schema = json.loads((ROOT / "schemas" / "evidence-packet.schema.json").read_text(encoding="utf-8"))
for field in ("compilation_unit", "language_runtime", "ctree_facts", "microcode_facts"):
    if field not in schema.get("properties", {}):
        fail(f"evidence schema missing {field}")

print("PASS: IDA 9.4 paths, byte-string search, mandatory auto-analysis/Hex-Rays, structured C-tree/microcode, and bounded path helpers validated")
