"""Extract compact structured facts from Hex-Rays C-tree using ida-domain >=0.5.

Use this before asking Claude to consume full pseudocode.
"""
from __future__ import annotations

import argparse
import json

from _ida_session import open_database
from _common import ensure_state, safe_text
import ida_query


def _ea(value) -> str | None:
    try:
        v = int(value)
        return hex(v) if v >= 0 else None
    except Exception:
        return None


def _expr_text(expr, max_len=300) -> str:
    try:
        return safe_text(expr.to_text())[:max_len]
    except Exception:
        try:
            return safe_text(expr.raw_expr)[:max_len]
        except Exception:
            return ""


def _arg_text(arg) -> str:
    try:
        return _expr_text(arg.expression)
    except Exception:
        return safe_text(arg)[:300]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("target")
    ap.add_argument("--max-items", type=int, default=80)
    args = ap.parse_args()
    if args.max_items < 1:
        raise SystemExit("--max-items must be >= 1")

    with open_database(args.binary) as db:
        root = ensure_state(args.binary, ida_query._metadata(db))
        ea = ida_query._resolve_function(db, args.target)
        fn = db.pseudocode.decompile(ea)

        payload = {
            "ea": hex(ea),
            "name": ida_query._function_name(db, ea),
            "arguments": [], "calls": [], "constants": [], "strings": [],
            "objects": [], "member_offsets": [], "assignments": [], "returns": [],
            "loops": 0, "truncated_categories": [],
        }

        for a in list(getattr(fn, "arguments", []))[:args.max_items]:
            payload["arguments"].append({
                "name": safe_text(getattr(a, "name", "")),
                "size": int(getattr(a, "size", 0)),
                "type": safe_text(getattr(a, "type_str", getattr(a, "type", ""))),
            })

        seen = {k: set() for k in ("calls", "constants", "strings", "objects", "member_offsets")}
        for expr in fn.walk_expressions():
            ex_ea = _ea(getattr(expr, "ea", -1))

            if getattr(expr, "is_call", False):
                callee = getattr(expr, "x", None)
                callee_ea = _ea(getattr(callee, "obj_ea", -1)) if callee is not None else None
                callee_name = safe_text(getattr(callee, "obj_name", "")) if callee is not None else ""
                if not callee_name and callee is not None:
                    callee_name = safe_text(getattr(callee, "helper_name", "")) or _expr_text(callee)
                key = (ex_ea, callee_ea, callee_name)
                if key not in seen["calls"]:
                    seen["calls"].add(key)
                    if len(payload["calls"]) < args.max_items:
                        call_args = []
                        try:
                            for ca in expr.call_args:
                                call_args.append(_arg_text(ca))
                                if len(call_args) >= 16:
                                    break
                        except Exception:
                            pass
                        payload["calls"].append({
                            "ea": ex_ea, "target_ea": callee_ea,
                            "target": callee_name, "args": call_args,
                        })
                    elif "calls" not in payload["truncated_categories"]:
                        payload["truncated_categories"].append("calls")

            if getattr(expr, "is_number", False) and getattr(expr, "number", None) is not None:
                num = expr.number
                try:
                    u = int(num.unsigned_value)
                    s = int(num.value)
                except Exception:
                    continue
                key = (ex_ea, u)
                if key not in seen["constants"]:
                    seen["constants"].add(key)
                    if len(payload["constants"]) < args.max_items:
                        payload["constants"].append({"ea": ex_ea, "unsigned": hex(u), "signed": s})
                    elif "constants" not in payload["truncated_categories"]:
                        payload["truncated_categories"].append("constants")

            if getattr(expr, "is_string", False):
                value = safe_text(getattr(expr, "string", ""))
                key = (ex_ea, value)
                if value and key not in seen["strings"]:
                    seen["strings"].add(key)
                    if len(payload["strings"]) < args.max_items:
                        payload["strings"].append({"ea": ex_ea, "value": value[:1000]})
                    elif "strings" not in payload["truncated_categories"]:
                        payload["truncated_categories"].append("strings")

            if getattr(expr, "is_object", False):
                obj_ea = _ea(getattr(expr, "obj_ea", -1))
                name = safe_text(getattr(expr, "obj_name", ""))
                key = (obj_ea, name)
                if key not in seen["objects"]:
                    seen["objects"].add(key)
                    if len(payload["objects"]) < args.max_items:
                        payload["objects"].append({"ea": ex_ea, "object_ea": obj_ea, "name": name})

            off = getattr(expr, "member_offset", None)
            if off is not None:
                key = (ex_ea, int(off))
                if key not in seen["member_offsets"]:
                    seen["member_offsets"].add(key)
                    if len(payload["member_offsets"]) < args.max_items:
                        payload["member_offsets"].append({
                            "ea": ex_ea, "offset": hex(int(off)),
                            "access_size": getattr(expr, "ptr_size", None), "expr": _expr_text(expr),
                        })

        try:
            assigns = fn.find_assignments()
            payload["assignments"] = [
                {"ea": _ea(getattr(x, "ea", -1)), "expr": _expr_text(x)}
                for x in assigns[:args.max_items]
            ]
            if len(assigns) > args.max_items:
                payload["truncated_categories"].append("assignments")
        except Exception:
            pass

        try:
            returns = fn.find_return_instructions()
            payload["returns"] = [
                {"ea": _ea(getattr(x, "ea", -1)), "text": safe_text(x.to_text())[:300]}
                for x in returns[:args.max_items]
            ]
        except Exception:
            pass

        try:
            payload["loops"] = len(fn.find_loops())
        except Exception:
            pass

        # In IDA 9.4, strings discovered during decompilation can become useful new global seeds.
        decomp_seeds = []
        try:
            for expr in fn.find_strings()[:30]:
                value = safe_text(getattr(expr, "string", ""))
                if value:
                    decomp_seeds.append({"ea": _ea(getattr(expr, "ea", -1)), "value": value[:1000]})
        except Exception:
            decomp_seeds = payload["strings"][:30]
        payload["decompiler_string_seeds"] = decomp_seeds
        payload["note"] = "Structured C-tree evidence. Request full pseudocode only when these facts are insufficient."

        out = root / "queries" / f"ctree_{ea:x}.json"
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
        print(json.dumps({
            "saved": str(out), "ea": hex(ea), "calls": len(payload["calls"]),
            "constants": len(payload["constants"]), "strings": len(payload["strings"]),
            "member_offsets": len(payload["member_offsets"]),
            "truncated_categories": payload["truncated_categories"],
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
