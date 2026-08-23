"""Manage compact persistent reverse-engineering state without loading all history."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

from _common import ensure_state, append_jsonl


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as f:
        return sum(1 for _ in f)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("path")
    sub.add_parser("summary")

    h = sub.add_parser("hypothesis-add")
    h.add_argument("text")
    h.add_argument("--confidence", type=float, default=0.5)
    h.add_argument("--ea")

    u = sub.add_parser("unresolved-add")
    u.add_argument("text")
    u.add_argument("--ea")

    f = sub.add_parser("finding-add")
    f.add_argument("json_file")

    args = ap.parse_args()
    root = ensure_state(args.binary)

    if args.command == "path":
        print(root)
        return 0
    if args.command == "summary":
        print(json.dumps({
            "root": str(root),
            "function_packets": len(list((root / "functions").glob("*.json"))),
            "query_artifacts": len(list((root / "queries").glob("*.json"))),
            "findings": count_lines(root / "findings.jsonl"),
            "hypotheses": count_lines(root / "hypotheses.jsonl"),
            "unresolved": count_lines(root / "unresolved.jsonl"),
        }, indent=2))
        return 0
    if args.command == "hypothesis-add":
        append_jsonl(root / "hypotheses.jsonl", {
            "time": now(), "text": args.text, "confidence": args.confidence, "ea": args.ea,
        })
        return 0
    if args.command == "unresolved-add":
        append_jsonl(root / "unresolved.jsonl", {"time": now(), "text": args.text, "ea": args.ea})
        return 0
    if args.command == "finding-add":
        obj = json.loads(Path(args.json_file).read_text(encoding="utf-8"))
        obj.setdefault("time", now())
        append_jsonl(root / "findings.jsonl", obj)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
