"""Build/query a multi-binary reverse-engineering project graph.

The skill may be installed globally or per-project. Project state is therefore always namespaced by
an explicit/deterministic project identity. By default this script uses
`.ida-re/projects/<project-id>/project.sqlite`; `--db` can override that location.
"""
from __future__ import annotations
import argparse, json, sqlite3
from pathlib import Path
from _common import state_root, binary_id, project_id, project_root, project_database_path

SCHEMA='''
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS binaries(id TEXT PRIMARY KEY,path TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS symbols(binary_id TEXT,kind TEXT,name TEXT,ea TEXT,PRIMARY KEY(binary_id,kind,name,ea));
CREATE TABLE IF NOT EXISTS links(src_binary TEXT,relation TEXT,dst_binary TEXT,detail TEXT,confidence REAL,PRIMARY KEY(src_binary,relation,dst_binary,detail));
'''

def _open(db_path: Path, binary_hint: str | None):
    db_path.parent.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(db_path); con.executescript(SCHEMA); con.row_factory=sqlite3.Row
    pid=project_id(binary_hint); proot=str(project_root(binary_hint))
    existing=con.execute("SELECT value FROM metadata WHERE key='project_id'").fetchone()
    if existing and existing[0] != pid:
        con.close()
        raise RuntimeError(f"Project database belongs to {existing[0]!r}, current project is {pid!r}; use the correct --db or IDA_RE_PROJECT_ID")
    con.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('project_id',?)",(pid,))
    con.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('project_root',?)",(proot,))
    con.commit(); return con,pid,proot

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db",help="override project graph path; default is project-scoped .ida-re path")
    sub=ap.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("add"); a.add_argument("binary")
    q=sub.add_parser("query"); q.add_argument("text",nargs="?",default="")
    sub.add_parser("info")
    args=ap.parse_args()
    binary_hint=getattr(args,"binary",None)
    p=Path(args.db).expanduser().resolve() if args.db else project_database_path(binary_hint)
    con,pid,proot=_open(p,binary_hint)
    if args.cmd=="add":
        bid=binary_id(args.binary); con.execute("INSERT OR REPLACE INTO binaries VALUES(?,?)",(bid,str(Path(args.binary).resolve())))
        sdb=state_root(args.binary)/"semantic.sqlite"
        if sdb.exists():
            src=sqlite3.connect(sdb); src.row_factory=sqlite3.Row
            for r in src.execute("SELECT ea,name,summary,fingerprint FROM functions"):
                con.execute("INSERT OR IGNORE INTO symbols VALUES(?,?,?,?)",(bid,"function",r["name"],r["ea"]))
            src.close()
        con.commit(); result={"project_id":pid,"binary_id":bid,"path":args.binary}
    elif args.cmd=="query":
        like=f"%{args.text}%"; result={"project_id":pid,"binaries":[dict(r) for r in con.execute("SELECT * FROM binaries WHERE path LIKE ?",(like,))],"symbols":[dict(r) for r in con.execute("SELECT * FROM symbols WHERE name LIKE ? LIMIT 200",(like,))],"links":[dict(r) for r in con.execute("SELECT * FROM links WHERE detail LIKE ? OR relation LIKE ? LIMIT 200",(like,like))]}
    else:
        result={"project_id":pid,"project_root":proot,"project_db":str(p),"binaries":con.execute("SELECT COUNT(*) FROM binaries").fetchone()[0],"symbols":con.execute("SELECT COUNT(*) FROM symbols").fetchone()[0],"links":con.execute("SELECT COUNT(*) FROM links").fetchone()[0]}
    con.close(); print(json.dumps({"project_db":str(p),"result":result},indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
