"""Apply high-confidence semantic findings to IDA.

Input JSON example:
{
  "functions": [
    {
      "ea": "0x140012340",
      "name": "Packet_Decode",
      "comment": "Decodes incoming packet.",
      "prototype": "int __fastcall Packet_Decode(Packet *p);",
      "confidence": 0.95
    }
  ]
}
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from _ida_session import open_database
from _common import ensure_state
import ida_query


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("findings_json")
    ap.add_argument("--min-confidence", type=float, default=0.90)
    args = ap.parse_args()

    payload = json.loads(Path(args.findings_json).read_text(encoding="utf-8"))
    applied, skipped = [], []

    with open_database(args.binary, save_on_close=True) as db:
        root = ensure_state(args.binary, ida_query._metadata(db))
        import ida_name, ida_bytes

        for item in payload.get("functions", []):
            conf = float(item.get("confidence", 0))
            if conf < args.min_confidence:
                skipped.append({"ea": item.get("ea"), "reason": "low_confidence", "confidence": conf})
                continue

            ea = int(str(item["ea"]), 0)
            changes = []

            if item.get("name"):
                if ida_name.set_name(ea, item["name"], ida_name.SN_FORCE):
                    changes.append("name")
                else:
                    skipped.append({"ea": hex(ea), "reason": f"name_failed:{item['name']}"})

            if item.get("comment") and ida_bytes.set_cmt(ea, item["comment"], False):
                changes.append("comment")

            if item.get("prototype"):
                f = db.functions.get_at(ea)
                if f and hasattr(db.functions, "apply_declaration"):
                    try:
                        if db.functions.apply_declaration(f, item["prototype"]):
                            changes.append("prototype")
                        else:
                            skipped.append({"ea": hex(ea), "reason": "prototype_apply_failed"})
                    except Exception as exc:
                        skipped.append({"ea": hex(ea), "reason": f"prototype_apply_error:{exc}"})
                else:
                    skipped.append({"ea": hex(ea), "reason": "prototype_api_unavailable"})

            applied.append({"ea": hex(ea), "confidence": conf, "changes": changes})

        log = root / "queries" / "applied_findings.json"
        log.write_text(json.dumps({
            "source": str(Path(args.findings_json).resolve()),
            "min_confidence": args.min_confidence,
            "applied": applied,
            "skipped": skipped,
        }, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({"applied": applied, "skipped": skipped}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
