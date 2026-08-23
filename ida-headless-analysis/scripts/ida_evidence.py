"""Queryable reverse-engineering evidence graph.

Stores entities, claims, relationships, provenance, confidence, contradictions, and supersession in
SQLite while keeping the existing JSONL files compatible. This is the preferred working memory for
long investigations because Claude can query facts instead of rereading history.
"""
from __future__ import annotations
import argparse, json, sqlite3, time
from pathlib import Path
from _common import state_root

SCHEMA='''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS entities(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL, label TEXT, UNIQUE(kind,key));
CREATE TABLE IF NOT EXISTS claims(id INTEGER PRIMARY KEY, entity_id INTEGER, predicate TEXT NOT NULL, value TEXT NOT NULL, confidence REAL NOT NULL, status TEXT NOT NULL DEFAULT 'active', source TEXT, created REAL NOT NULL, FOREIGN KEY(entity_id) REFERENCES entities(id));
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, claim_id INTEGER NOT NULL, kind TEXT, detail TEXT NOT NULL, source TEXT, created REAL NOT NULL, FOREIGN KEY(claim_id) REFERENCES claims(id));
CREATE TABLE IF NOT EXISTS edges(id INTEGER PRIMARY KEY, src_entity INTEGER NOT NULL, relation TEXT NOT NULL, dst_entity INTEGER NOT NULL, confidence REAL NOT NULL, source TEXT, UNIQUE(src_entity,relation,dst_entity,source));
CREATE TABLE IF NOT EXISTS conflicts(id INTEGER PRIMARY KEY, claim_a INTEGER NOT NULL, claim_b INTEGER NOT NULL, reason TEXT NOT NULL, created REAL NOT NULL);
CREATE INDEX IF NOT EXISTS claims_entity_pred ON claims(entity_id,predicate,status);
'''
def connect(binary):
    p=state_root(binary)/"evidence.sqlite"; p.parent.mkdir(parents=True,exist_ok=True); con=sqlite3.connect(p); con.executescript(SCHEMA); return p,con

def entity(con,kind,key,label=None):
    con.execute("INSERT OR IGNORE INTO entities(kind,key,label) VALUES(?,?,?)",(kind,key,label)); row=con.execute("SELECT id FROM entities WHERE kind=? AND key=?",(kind,key)).fetchone(); return int(row[0])

def add_claim(con,eid,pred,value,confidence,source):
    now=time.time(); old=con.execute("SELECT id,value,confidence FROM claims WHERE entity_id=? AND predicate=? AND status='active'",(eid,pred)).fetchall()
    cur=con.execute("INSERT INTO claims(entity_id,predicate,value,confidence,source,created) VALUES(?,?,?,?,?,?)",(eid,pred,json.dumps(value,sort_keys=True) if not isinstance(value,str) else value,confidence,source,now)); cid=cur.lastrowid
    for oid,oval,oconf in old:
        if oval != (json.dumps(value,sort_keys=True) if not isinstance(value,str) else value) and min(float(oconf),confidence)>=.65:
            con.execute("INSERT INTO conflicts(claim_a,claim_b,reason,created) VALUES(?,?,?,?)",(oid,cid,"same entity/predicate has incompatible active values",now))
    return cid

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); sub=ap.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("claim-add"); a.add_argument("kind"); a.add_argument("key"); a.add_argument("predicate"); a.add_argument("value"); a.add_argument("--confidence",type=float,default=.6); a.add_argument("--source",default="claude")
    q=sub.add_parser("query"); q.add_argument("text",nargs="?",default=""); q.add_argument("--limit",type=int,default=50)
    sub.add_parser("conflicts"); args=ap.parse_args(); path,con=connect(args.binary); con.row_factory=sqlite3.Row
    if args.cmd=="claim-add":
        eid=entity(con,args.kind,args.key); cid=add_claim(con,eid,args.predicate,args.value,args.confidence,args.source); con.commit(); result={"claim_id":cid}
    elif args.cmd=="query":
        like=f"%{args.text}%"; result=[dict(r) for r in con.execute("SELECT c.id,e.kind,e.key,e.label,c.predicate,c.value,c.confidence,c.status,c.source FROM claims c JOIN entities e ON e.id=c.entity_id WHERE e.key LIKE ? OR e.label LIKE ? OR c.predicate LIKE ? OR c.value LIKE ? ORDER BY c.confidence DESC LIMIT ?",(like,like,like,like,args.limit))]
    else:
        result=[dict(r) for r in con.execute("SELECT x.id,x.reason,a.value AS value_a,b.value AS value_b,a.confidence AS confidence_a,b.confidence AS confidence_b FROM conflicts x JOIN claims a ON a.id=x.claim_a JOIN claims b ON b.id=x.claim_b ORDER BY x.id DESC LIMIT 100")]
    con.close(); print(json.dumps({"database":str(path),"result":result},indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
