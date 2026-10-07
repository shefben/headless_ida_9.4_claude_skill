"""Exact immutable query snapshot cache keyed by binary, analysis profile, operation, and parameters."""
from __future__ import annotations
import argparse, json, sqlite3, time
from pathlib import Path
from _common import state_root, binary_sha256, analysis_epoch
from _provenance import canonical_json, load_analysis_profile, semantic_id

SCHEMA='''CREATE TABLE IF NOT EXISTS entries(query_id TEXT PRIMARY KEY,binary_sha256 TEXT NOT NULL,analysis_profile_digest TEXT NOT NULL,operation TEXT NOT NULL,parameters_json TEXT NOT NULL,result_json TEXT NOT NULL,created REAL NOT NULL);'''

def open_cache(binary):
    root=state_root(binary); root.mkdir(parents=True,exist_ok=True); profile=load_analysis_profile(root)
    if not profile: raise RuntimeError("analysis profile missing; open the binary with any IDA helper or run ida_profile.py first")
    path=root/"snapshot.sqlite"; con=sqlite3.connect(path); con.execute(SCHEMA); con.row_factory=sqlite3.Row
    return path,con,profile

def qid(binary,profile,operation,parameters):
    return semantic_id("query",{"target_sha256":binary_sha256(binary),"analysis_profile_digest":profile["digest"],"analysis_epoch":analysis_epoch(binary),"operation":operation,"parameters":parameters})

def parse(v):
    p=Path(v)
    if p.exists() and p.is_file(): return json.loads(p.read_text(encoding="utf-8"))
    return json.loads(v)

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); sub=ap.add_subparsers(dest="cmd",required=True)
    g=sub.add_parser("get"); g.add_argument("operation"); g.add_argument("parameters")
    p=sub.add_parser("put"); p.add_argument("operation"); p.add_argument("parameters"); p.add_argument("result")
    sub.add_parser("info")
    a=ap.parse_args(); path,con,profile=open_cache(a.binary)
    if a.cmd=="info": result={"database":str(path),"analysis_profile_digest":profile["digest"],"analysis_epoch":analysis_epoch(a.binary),"entries":con.execute("SELECT COUNT(*) FROM entries").fetchone()[0]}
    else:
        params=parse(a.parameters); ident=qid(a.binary,profile,a.operation,params)
        if a.cmd=="get":
            row=con.execute("SELECT result_json FROM entries WHERE query_id=? AND binary_sha256=? AND analysis_profile_digest=?",(ident,binary_sha256(a.binary),profile["digest"])).fetchone(); result={"hit":row is not None,"query_id":ident,"result":None if row is None else json.loads(row[0])}
        else:
            val=parse(a.result); con.execute("INSERT OR REPLACE INTO entries VALUES(?,?,?,?,?,?,?)",(ident,binary_sha256(a.binary),profile["digest"],a.operation,canonical_json(params),canonical_json(val),time.time())); con.commit(); result={"stored":True,"query_id":ident}
    con.close(); print(json.dumps(result,indent=2,ensure_ascii=False)); return 0
if __name__=="__main__": raise SystemExit(main())
