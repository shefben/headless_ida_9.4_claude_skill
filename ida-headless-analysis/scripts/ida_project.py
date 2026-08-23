"""Build/query a multi-binary reverse-engineering project graph.

Links executables, DLLs/shared libraries, plugins, exports/imports, shared strings and semantic
fingerprints so Claude can reason across an application instead of treating every binary as an
island.
"""
from __future__ import annotations
import argparse, json, sqlite3
from pathlib import Path
from _common import state_root, binary_id

SCHEMA='''
CREATE TABLE IF NOT EXISTS binaries(id TEXT PRIMARY KEY,path TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS symbols(binary_id TEXT,kind TEXT,name TEXT,ea TEXT,PRIMARY KEY(binary_id,kind,name,ea));
CREATE TABLE IF NOT EXISTS links(src_binary TEXT,relation TEXT,dst_binary TEXT,detail TEXT,confidence REAL,PRIMARY KEY(src_binary,relation,dst_binary,detail));
'''
def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("project_db"); sub=ap.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("add"); a.add_argument("binary"); q=sub.add_parser("query"); q.add_argument("text",nargs="?",default=""); args=ap.parse_args()
    p=Path(args.project_db); p.parent.mkdir(parents=True,exist_ok=True); con=sqlite3.connect(p); con.executescript(SCHEMA); con.row_factory=sqlite3.Row
    if args.cmd=="add":
        bid=binary_id(args.binary); con.execute("INSERT OR REPLACE INTO binaries VALUES(?,?)",(bid,str(Path(args.binary).resolve())))
        sdb=state_root(args.binary)/"semantic.sqlite"
        if sdb.exists():
            src=sqlite3.connect(sdb); src.row_factory=sqlite3.Row
            for r in src.execute("SELECT ea,name,summary,fingerprint FROM functions"):
                con.execute("INSERT OR IGNORE INTO symbols VALUES(?,?,?,?)",(bid,"function",r["name"],r["ea"]))
            src.close()
        con.commit(); result={"binary_id":bid,"path":args.binary}
    else:
        like=f"%{args.text}%"; result={"binaries":[dict(r) for r in con.execute("SELECT * FROM binaries WHERE path LIKE ?",(like,))],"symbols":[dict(r) for r in con.execute("SELECT * FROM symbols WHERE name LIKE ? LIMIT 200",(like,))],"links":[dict(r) for r in con.execute("SELECT * FROM links WHERE detail LIKE ? OR relation LIKE ? LIMIT 200",(like,like))]}
    con.close(); print(json.dumps({"project_db":str(p),"result":result},indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
