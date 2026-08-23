"""Controlled universal IDA analysis escape hatch.

Executes Claude-generated Python inside the mandatory IDA session. Read-only by default. The code
receives `db`, `binary`, and `state_root`. Output must be written with print(). Dangerous database
mutation helpers are rejected unless --allow-write is explicitly supplied.
"""
from __future__ import annotations
import argparse, json, re
from pathlib import Path
from _ida_session import open_database
from _common import ensure_state
import ida_query

BLOCKED = [
    r"\bida_name\.set_name\b", r"\bida_bytes\.set_cmt\b", r"\bapply_declaration\b",
    r"\bpatch_(?:byte|word|dword|qword|bytes)\b", r"\bdel_(?:items|func)\b",
    r"\bset_(?:name|cmt|type)\b", r"\bcreate_(?:insn|data|func)\b",
]

def validate(code: str, allow_write: bool) -> None:
    if len(code) > 100_000: raise ValueError("generated analysis code exceeds 100KB")
    if not allow_write:
        for pat in BLOCKED:
            if re.search(pat, code): raise PermissionError(f"write-like API blocked in read-only eval: {pat}")


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); ap.add_argument("script")
    ap.add_argument("--allow-write",action="store_true")
    a=ap.parse_args(); code=Path(a.script).read_text(encoding="utf-8"); validate(code,a.allow_write)
    with open_database(a.binary,save_on_close=a.allow_write) as db:
        root=ensure_state(a.binary,ida_query._metadata(db)); scope={"db":db,"binary":a.binary,"state_root":root,"__name__":"__ida_eval__"}
        exec(compile(code,str(Path(a.script)),"exec"),scope,scope)
    return 0
if __name__=="__main__": raise SystemExit(main())
