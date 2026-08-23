"""Structured, token-bounded Hex-Rays microcode evidence extractor.

This is not formal taint analysis. It extracts calls, constants, globals, strings, registers,
stack references and matching instructions from ida-domain MicroBlockArray objects without
feeding the whole textual microcode listing to Claude.
"""
from __future__ import annotations

import argparse
import json
import re

from _ida_session import open_database
from _common import ensure_state, safe_text
import ida_query


def maturity_from_name(name: str):
    from ida_domain.microcode import MicroMaturity
    return {
        "zero": MicroMaturity.ZERO,
        "generated": MicroMaturity.GENERATED,
        "preoptimized": MicroMaturity.PREOPTIMIZED,
        "locopt": MicroMaturity.LOCOPT,
        "calls": MicroMaturity.CALLS,
        "glbopt1": MicroMaturity.GLBOPT1,
        "glbopt2": MicroMaturity.GLBOPT2,
        "glbopt3": MicroMaturity.GLBOPT3,
        "lvars": MicroMaturity.LVARS,
    }[name]


def op_record(op):
    rec = {"type": safe_text(getattr(getattr(op, "type", None), "name", getattr(op, "type", ""))),
           "size": int(getattr(op, "size", 0))}
    if getattr(op, "is_number", False):
        rec.update({"kind": "number", "value": getattr(op, "value", None),
                    "unsigned": getattr(op, "unsigned_value", None), "signed": getattr(op, "signed_value", None)})
    elif getattr(op, "is_global_address", False):
        v = getattr(op, "global_address", None)
        rec.update({"kind": "global", "ea": hex(int(v)) if v is not None else None})
    elif getattr(op, "is_string", False):
        rec.update({"kind": "string", "value": safe_text(getattr(op, "string_value", ""))[:1000]})
    elif getattr(op, "is_register", False):
        rec.update({"kind": "register", "name": safe_text(getattr(op, "register_name", ""))})
    elif getattr(op, "is_stack_variable", False):
        rec.update({"kind": "stack", "offset": getattr(op, "stack_offset", None)})
    elif getattr(op, "is_helper", False):
        rec.update({"kind": "helper", "name": safe_text(getattr(op, "helper_name", ""))})
    else:
        try:
            rec.update({"kind": "other", "text": safe_text(op.to_text())[:300]})
        except Exception:
            rec.update({"kind": "other"})
    ci = getattr(op, "call_info", None)
    if ci is not None:
        try:
            import ida_idaapi
            bad = int(ida_idaapi.BADADDR)
        except Exception:
            bad = -1
        callee = int(getattr(ci, "callee", bad))
        rec["call_info"] = {
            "callee": None if callee == bad else hex(callee),
            "calling_convention": int(getattr(ci, "calling_convention", 0)),
            "arg_count": int(getattr(ci, "arg_count", 0)),
            "return_type": safe_text(getattr(ci, "return_type", "")),
            "args": [safe_text(getattr(a, "to_text", lambda: a)())[:300] for a in list(getattr(ci, "args", []))[:16]],
        }
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("target")
    ap.add_argument("--maturity", choices=("zero", "generated", "preoptimized", "locopt", "calls", "glbopt1", "glbopt2", "glbopt3", "lvars"), default="locopt")
    ap.add_argument("--match", help="optional regex over compact instruction/operand text")
    ap.add_argument("--max-events", type=int, default=120)
    args = ap.parse_args()
    if args.max_events < 1:
        raise SystemExit("--max-events must be >= 1")

    with open_database(args.binary) as db:
        root = ensure_state(args.binary, ida_query._metadata(db))
        ea = ida_query._resolve_function(db, args.target)
        f = db.functions.get_at(ea)
        if not f:
            raise ValueError(f"No function at 0x{ea:x}")

        mba = db.microcode.generate(f, maturity_from_name(args.maturity))
        rx = re.compile(args.match, re.I) if args.match else None
        events, total = [], 0
        summary = {"calls": 0, "constants": 0, "globals": 0, "strings": 0, "stack_refs": 0}

        for insn in mba.instructions():
            ea_i = int(getattr(insn, "ea", 0))
            try:
                opcode = safe_text(getattr(getattr(insn, "opcode", None), "name", getattr(insn, "opcode", "")))
            except Exception:
                opcode = ""
            operands = [op_record(op) for op in insn.operands()]
            is_call = bool(insn.is_call())
            if is_call:
                summary["calls"] += 1
            for op in operands:
                if op.get("kind") == "number": summary["constants"] += 1
                elif op.get("kind") == "global": summary["globals"] += 1
                elif op.get("kind") == "string": summary["strings"] += 1
                elif op.get("kind") == "stack": summary["stack_refs"] += 1
            event = {"ea": hex(ea_i), "opcode": opcode, "is_call": is_call, "operands": operands}
            hay = json.dumps(event, ensure_ascii=False, default=str)
            if rx and not rx.search(hay):
                continue
            total += 1
            if len(events) < args.max_events:
                events.append(event)

        payload = {
            "ea": hex(ea), "name": ida_query._function_name(db, ea),
            "maturity": args.maturity, "match": args.match,
            "summary": summary, "events": events, "matching_events": total,
            "truncated": total > len(events),
            "note": "Structured Domain microcode. Change maturity before escalating to raw microcode text.",
        }
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", args.match or "all")[:40]
        out = root / "queries" / f"micro_struct_{ea:x}_{args.maturity}_{safe}.json"
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
        print(json.dumps({"saved": str(out), "summary": summary, "matching_events": total,
                          "returned_events": len(events), "truncated": payload["truncated"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
