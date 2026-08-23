"""Discover available IDA signature files and report likely matches.

This helper is read-only. Signature application remains an explicit high-confidence database
mutation and should be done through the transactional findings workflow.
"""
from __future__ import annotations
import argparse, json
from _ida_session import open_database
from _common import ensure_state, safe_text
import ida_query

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); ap.add_argument("--contains",default=""); a=ap.parse_args()
    with open_database(a.binary) as db:
        root=ensure_state(a.binary,ida_query._metadata(db)); rows=[]; api=getattr(db,"signature_files",None)
        if api is not None:
            try:
                items=list(api.get_all()) if hasattr(api,"get_all") else []
                for s in items:
                    name=safe_text(getattr(s,"name",s))
                    if a.contains.lower() in name.lower(): rows.append({"name":name})
            except Exception as exc: rows=[{"error":f"{type(exc).__name__}: {exc}"}]
        else: rows=[{"warning":"signature_files API is unavailable in this ida-domain build"}]
        out=root/"queries"/"signatures.json"; out.write_text(json.dumps(rows,indent=2)+"\n",encoding="utf-8"); print(json.dumps({"saved":str(out),"items":len(rows)},indent=2))
    return 0
if __name__=="__main__": raise SystemExit(main())
