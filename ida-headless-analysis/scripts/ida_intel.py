"""High-level intelligence layer for headless IDA 9.4 analysis.

Provides cheap semantic ranking/search plus C++/struct/dispatch/module/constant/string/obfuscation
recovery primitives. Results are deliberately compact and cached under .ida-re/.
"""
from __future__ import annotations
import argparse, json, math, re, sqlite3, hashlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from _ida_session import open_database
from _common import ensure_state, safe_text
import ida_query

INTEREST_IMPORTS={
 "network":re.compile(r"recv|send|socket|connect|http|wininet|curl",re.I),
 "crypto":re.compile(r"crypt|bcrypt|ssl|tls|aes|sha|md5|evp_",re.I),
 "process":re.compile(r"createprocess|shellexecute|winexec|system$|popen",re.I),
 "file":re.compile(r"createfile|readfile|writefile|fopen|fread|fwrite",re.I),
 "memory":re.compile(r"virtualalloc|virtualprotect|memcpy|memmove|malloc|free",re.I),
}
MAGIC={0x5A4D:"MZ",0x4550:"PE",0x464c457f:"ELF",0x89504e47:"PNG",0x04034b50:"ZIP",0x1f8b:"GZIP",0xfeedfacf:"Mach-O64",0xcafebabe:"Java/Mach-O-fat",0x67452301:"MD5-IV",0x6a09e667:"SHA256-IV"}


def _fstats(db, f, limit=30):
    ea=int(f.start_ea); end=int(getattr(f,"end_ea",ea)); name=ida_query._function_name(db,ea)
    callers=ida_query._callers(db,ea,limit); callees=ida_query._callees(db,ea,limit); cfg=ida_query._cfg(db,ea,80)
    imports=[]
    for c in callees.get("items",[]):
        n=c.get("name","")
        for k,rx in INTEREST_IMPORTS.items():
            if rx.search(n): imports.append(k)
    blocks=cfg.get("total",0); edges=sum(len(x.get("succ",[])) for x in cfg.get("items",[])); cyclo=max(1,edges-blocks+2)
    return {"ea":hex(ea),"name":name,"size":max(0,end-ea),"callers":callers.get("total",0),"callees":callees.get("total",0),"blocks":blocks,"cyclomatic":cyclo,"api_categories":sorted(set(imports))}


def rank(db, limit=40, regex=None):
    rx=re.compile(regex,re.I) if regex else None; rows=[]
    for f in db.functions.get_all():
        s=_fstats(db,f,10)
        if rx and not rx.search(s["name"]): continue
        score=0.0; score+=min(s["cyclomatic"],30)*1.2; score+=min(s["callers"],20)*0.7; score+=min(s["callees"],20)*0.5
        score+=len(s["api_categories"])*8; score+=min(math.log2(max(s["size"],1)),14)
        if s["name"].startswith("sub_"): score-=2
        s["interest_score"]=round(score,2); rows.append(s)
    rows.sort(key=lambda x:x["interest_score"],reverse=True); return rows[:limit]


def ctree_facts(db, ea, limit=80):
    fn=db.pseudocode.decompile(ea); out={"calls":[],"strings":[],"constants":[],"member_offsets":[],"objects":[]}; seen=defaultdict(set)
    for e in fn.walk_expressions():
        xea=int(getattr(e,"ea",0))
        if getattr(e,"is_call",False) and len(out["calls"])<limit:
            c=getattr(e,"x",None); n=safe_text(getattr(c,"obj_name","")) or safe_text(getattr(c,"helper_name",""))
            key=(xea,n)
            if key not in seen["c"]: seen["c"].add(key); out["calls"].append({"ea":hex(xea),"target":n})
        if getattr(e,"is_string",False) and len(out["strings"])<limit:
            v=safe_text(getattr(e,"string","")); key=(xea,v)
            if v and key not in seen["s"]: seen["s"].add(key); out["strings"].append({"ea":hex(xea),"value":v[:500]})
        if getattr(e,"is_number",False) and len(out["constants"])<limit:
            try:
                v=int(e.number.unsigned_value); key=(xea,v)
                if key not in seen["n"]: seen["n"].add(key); out["constants"].append({"ea":hex(xea),"value":hex(v),"meaning":MAGIC.get(v)})
            except Exception: pass
        off=getattr(e,"member_offset",None)
        if off is not None and len(out["member_offsets"])<limit:
            out["member_offsets"].append({"ea":hex(xea),"offset":hex(int(off)),"size":getattr(e,"ptr_size",None)})
        if getattr(e,"is_object",False) and len(out["objects"])<limit:
            out["objects"].append({"ea":hex(xea),"object":safe_text(getattr(e,"obj_name","")),"object_ea":hex(int(getattr(e,"obj_ea",0)))})
    return out


def packet(db, target, limit=80):
    ea=ida_query._resolve_function(db,target); f=db.functions.get_at(ea); s=_fstats(db,f,20); facts=ctree_facts(db,ea,limit)
    text=" ".join([s["name"]]+[x["target"] for x in facts["calls"]]+[x["value"] for x in facts["strings"]])
    tags=[k for k,rx in INTEREST_IMPORTS.items() if rx.search(text)]
    return {**s,"semantic_tags":tags,"facts":facts,"fingerprint":fingerprint(s,facts)}


def fingerprint(stats,facts):
    norm={"size_bucket":stats["size"]//16,"blocks":stats["blocks"],"cyclomatic":stats["cyclomatic"],
          "calls":sorted(x["target"] for x in facts["calls"] if x["target"]),
          "strings":sorted(x["value"][:80] for x in facts["strings"]),"constants":sorted(x["value"] for x in facts["constants"])}
    return hashlib.sha256(json.dumps(norm,sort_keys=True).encode()).hexdigest()[:24]


def build_index(db, root, top=2000):
    path=root/"semantic.sqlite"; con=sqlite3.connect(path); cur=con.cursor()
    cur.executescript("CREATE TABLE IF NOT EXISTS functions(ea TEXT PRIMARY KEY,name TEXT,summary TEXT,score REAL,fingerprint TEXT); CREATE VIRTUAL TABLE IF NOT EXISTS functions_fts USING fts5(ea UNINDEXED,name,summary);")
    cur.execute("DELETE FROM functions"); cur.execute("DELETE FROM functions_fts")
    for row in rank(db,top):
        ea=int(row["ea"],0)
        try: p=packet(db,row["ea"],40)
        except Exception: p={**row,"semantic_tags":[],"facts":{"calls":[],"strings":[],"constants":[],"member_offsets":[]},"fingerprint":""}
        summary=" ".join(p.get("semantic_tags",[])+[x.get("target","") for x in p["facts"].get("calls",[])]+[x.get("value","") for x in p["facts"].get("strings",[])])[:12000]
        cur.execute("INSERT OR REPLACE INTO functions VALUES(?,?,?,?,?)",(row["ea"],row["name"],summary,row["interest_score"],p.get("fingerprint","")))
        cur.execute("INSERT INTO functions_fts VALUES(?,?,?)",(row["ea"],row["name"],summary))
    con.commit(); con.close(); return str(path)


def semantic_search(root,q,limit=20):
    path=root/"semantic.sqlite"; con=sqlite3.connect(path); con.row_factory=sqlite3.Row
    rows=con.execute("SELECT f.ea,f.name,f.score,f.fingerprint,bm25(functions_fts) AS rank FROM functions_fts JOIN functions f USING(ea) WHERE functions_fts MATCH ? ORDER BY rank LIMIT ?",(q,limit)).fetchall(); con.close(); return [dict(r) for r in rows]


def recover_struct(db,target):
    ea=ida_query._resolve_function(db,target); facts=ctree_facts(db,ea,200); grouped=defaultdict(list)
    for m in facts["member_offsets"]: grouped[m["offset"]].append(m)
    fields=[]
    for off,uses in sorted(grouped.items(),key=lambda x:int(x[0],0)):
        sizes=Counter(x.get("size") for x in uses); fields.append({"offset":off,"observations":len(uses),"sizes":dict(sizes),"confidence":min(.95,.45+.08*len(uses))})
    return {"function":hex(ea),"fields":fields}


def cpp_classes(db,limit=100):
    pats=re.compile(r"vftable|vtable|RTTI|typeinfo|ClassHierarchy|CompleteObjectLocator|`vftable'",re.I); out=[]
    try:
        for n in db.names.get_all():
            name=safe_text(getattr(n,"name",n)); ea=int(getattr(n,"address",getattr(n,"ea",0)))
            if pats.search(name): out.append({"ea":hex(ea),"name":name})
            if len(out)>=limit: break
    except Exception:
        import idautils, ida_name
        for ea,name in idautils.Names():
            if pats.search(name): out.append({"ea":hex(int(ea)),"name":name})
            if len(out)>=limit: break
    return out


def dispatch(db,target,limit=200):
    ea=ida_query._resolve_function(db,target); f=db.functions.get_at(ea); out={"ea":hex(ea),"cases":[],"indirect_calls":[]}
    try:
        import ida_nalt, idautils, ida_ua
        for head in idautils.Heads(int(f.start_ea),int(f.end_ea)):
            si=ida_nalt.get_switch_info(head)
            if si:
                out["cases"].append({"switch_ea":hex(int(head)),"ncases":int(getattr(si,"ncases",0)),"jumps":hex(int(getattr(si,"jumps",0)))})
                if len(out["cases"])>=limit: break
    except Exception: pass
    return out


def modules(db,limit=200):
    groups=defaultdict(lambda:{"functions":0,"samples":[]})
    for f in db.functions.get_all():
        ea=int(f.start_ea); n=ida_query._function_name(db,ea); key=n.split("::",1)[0] if "::" in n else (n.split("_",1)[0] if not n.startswith("sub_") else "unknown")
        groups[key]["functions"]+=1
        if len(groups[key]["samples"])<5: groups[key]["samples"].append({"ea":hex(ea),"name":n})
    return [{"module":k,**v} for k,v in sorted(groups.items(),key=lambda kv:kv[1]["functions"],reverse=True)[:limit]]


def deobfuscation_score(db,target):
    ea=ida_query._resolve_function(db,target); f=db.functions.get_at(ea); s=_fstats(db,f,20); score=0; reasons=[]
    if s["cyclomatic"]>25: score+=25; reasons.append("high cyclomatic complexity")
    if s["blocks"]>80: score+=20; reasons.append("many basic blocks")
    if s["size"]>5000: score+=10; reasons.append("very large function")
    try:
        facts=ctree_facts(db,ea,200); nums=[int(x["value"],0) for x in facts["constants"]]
        if len(nums)>80: score+=15; reasons.append("constant-heavy")
    except Exception: pass
    return {"ea":hex(ea),"score":min(score,100),"reasons":reasons,"stats":s}


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); sub=ap.add_subparsers(dest="cmd",required=True)
    r=sub.add_parser("rank"); r.add_argument("--limit",type=int,default=40); r.add_argument("--regex")
    p=sub.add_parser("packet"); p.add_argument("target")
    sub.add_parser("index"); s=sub.add_parser("search"); s.add_argument("query"); s.add_argument("--limit",type=int,default=20)
    x=sub.add_parser("struct"); x.add_argument("target"); sub.add_parser("cpp")
    d=sub.add_parser("dispatch"); d.add_argument("target"); sub.add_parser("modules")
    o=sub.add_parser("deobfuscate"); o.add_argument("target")
    a=ap.parse_args()
    with open_database(a.binary) as db:
        root=ensure_state(a.binary,ida_query._metadata(db))
        if a.cmd=="rank": result=rank(db,a.limit,a.regex)
        elif a.cmd=="packet": result=packet(db,a.target)
        elif a.cmd=="index": result={"index":build_index(db,root)}
        elif a.cmd=="search": result=semantic_search(root,a.query,a.limit)
        elif a.cmd=="struct": result=recover_struct(db,a.target)
        elif a.cmd=="cpp": result=cpp_classes(db)
        elif a.cmd=="dispatch": result=dispatch(db,a.target)
        elif a.cmd=="modules": result=modules(db)
        elif a.cmd=="deobfuscate": result=deobfuscation_score(db,a.target)
        out=root/"queries"/f"intel_{a.cmd}.json"; out.write_text(json.dumps(result,indent=2,ensure_ascii=False,default=str)+"\n",encoding="utf-8")
        print(json.dumps({"saved":str(out),"command":a.cmd,"result":result if a.cmd in {"search","deobfuscate"} else None},indent=2,ensure_ascii=False,default=str))
    return 0
if __name__=="__main__": raise SystemExit(main())
