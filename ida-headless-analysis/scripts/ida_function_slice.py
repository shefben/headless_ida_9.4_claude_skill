"""Create a compact, persistent evidence slice for one function."""
from __future__ import annotations

import argparse
import json

from _ida_session import open_database
from _common import ensure_state, safe_text
import ida_query


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("target")
    ap.add_argument("--include-pseudocode", action="store_true")
    ap.add_argument("--pseudocode-lines", type=int, default=120)
    args = ap.parse_args()

    with open_database(args.binary) as db:
        root = ensure_state(args.binary, ida_query._metadata(db))
        ea = ida_query._resolve_function(db, args.target)
        packet = ida_query._function_summary(db, ea, 30)
        packet["binary_id"] = root.name

        # Pull bounded string references from the function without globally enumerating strings.
        string_refs = []
        try:
            import idautils, ida_funcs, ida_bytes
            f = ida_funcs.get_func(ea)
            seen = set()
            for head in idautils.Heads(f.start_ea, f.end_ea):
                for ref in idautils.DataRefsFrom(head):
                    if ref in seen:
                        continue
                    raw = ida_bytes.get_strlit_contents(ref, -1, 0)
                    if raw:
                        seen.add(ref)
                        string_refs.append({
                            "ea": hex(int(ref)),
                            "value": safe_text(raw)[:500],
                            "ref_from": hex(int(head)),
                        })
                        if len(string_refs) >= 20:
                            break
                if len(string_refs) >= 20:
                    break
        except Exception:
            pass
        packet["string_refs"] = string_refs

        # IDA 9.4 / Domain 0.5: harvest decompiler-visible strings as additional bounded seeds.
        try:
            fn = db.pseudocode.decompile(ea)
            decomp_strings = []
            seen_ds = set()
            for expr in fn.find_strings():
                value = safe_text(getattr(expr, "string", ""))
                key = (int(getattr(expr, "ea", 0)), value)
                if value and key not in seen_ds:
                    seen_ds.add(key)
                    decomp_strings.append({"ea": hex(key[0]), "value": value[:500]})
                    if len(decomp_strings) >= 20:
                        break
            packet["decompiler_string_seeds"] = decomp_strings
        except Exception:
            packet["decompiler_string_seeds"] = []

        if args.include_pseudocode:
            packet["pseudocode"] = ida_query._pseudocode(db, ea, args.pseudocode_lines)

        out = root / "functions" / f"{ea:x}.json"
        out.write_text(json.dumps(packet, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({
            "saved": str(out),
            "ea": hex(ea),
            "name": packet.get("name"),
            "pseudocode_included": args.include_pseudocode,
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
