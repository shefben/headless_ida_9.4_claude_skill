"""Persistent single-binary IDA worker.

Opens one mandatory auto-analyzed/Hex-Rays database and accepts JSON objects on stdin, one per
line. Responses are one-line JSON. Use {"op":"quit"} to terminate. This eliminates repeated
idalib/database startup during interactive Claude investigations.
"""
from __future__ import annotations
import argparse, json, sys
from _ida_session import open_database
from _common import ensure_state
import ida_query, ida_batch


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); a=ap.parse_args()
    with open_database(a.binary) as db:
        ensure_state(a.binary, ida_query._metadata(db))
        print(json.dumps({"ready":True,"binary":a.binary}),flush=True)
        for line in sys.stdin:
            try:
                req=json.loads(line); op=req.get("op")
                if op=="quit": print(json.dumps({"bye":True}),flush=True); break
                result=ida_batch.execute_step(db,req)
                print(json.dumps({"ok":True,"id":req.get("id"),"result":result},ensure_ascii=False,default=str),flush=True)
            except Exception as exc:
                print(json.dumps({"ok":False,"error":f"{type(exc).__name__}: {exc}"}),flush=True)
    return 0
if __name__=="__main__": raise SystemExit(main())
