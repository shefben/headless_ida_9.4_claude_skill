"""Emit and persist the exact IDA/Hex-Rays analysis profile for a binary."""
from __future__ import annotations
import argparse, json
from _ida_session import open_database
from _common import ensure_state
from _provenance import save_analysis_profile
import ida_query


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    args = ap.parse_args()
    with open_database(args.binary, save_on_close=False) as db:
        root = ensure_state(args.binary, ida_query._metadata(db))
        profile = save_analysis_profile(root, db)
        print(json.dumps({"saved": str(root / "analysis_profile.json"), "profile": profile}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
