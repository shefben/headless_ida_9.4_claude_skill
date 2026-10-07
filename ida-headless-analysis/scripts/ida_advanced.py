"""Advanced autonomous-analysis helpers for the IDA 9.4 Claude skill.

Covers cost-aware planning, function summaries, IDA indexer search, compilation-unit/runtime
recovery, stack/transformed-string discovery, semantic constant/API knowledge, verification,
specialist investigators, and a persistent investigation frontier.
"""
from __future__ import annotations
import argparse, json, re, sqlite3, time
from collections import defaultdict
from pathlib import Path
from _ida_session import open_database
from _common import ensure_state, safe_text
import ida_query, ida_intel

COSTS={"cache":1,"metadata":1,"search":2,"string":2,"callers":3,"callees":3,"packet":4,"ctree":5,"cfg":5,"pseudocode":8,"microcode":10,"taint":12,"deobfuscate":12}
API_SEMANTICS={
 "recv":{"category":"network_input","writes":[1],"length_arg":2},"recvfrom":{"category":"network_input","writes":[1],"length_arg":2},
 "ReadFile":{"category":"file_input","writes":[1],"length_arg":2},"fread":{"category":"file_input","writes":[0],"length_args":[1,2]},
 "memcpy":{"category":"memory_copy","reads":[1],"writes":[0],"length_arg":2},"memmove":{"category":"memory_copy","reads":[1],"writes":[0],"length_arg":2},
 "strcpy":{"category":"memory_copy","reads":[1],"writes":[0]},"CreateProcessA":{"category":"process_execution","reads":[0,1]},"CreateProcessW":{"category":"process_execution","reads":[0,1]},
 "BCryptDecrypt":{"category":"crypto_transform","reads":[1],"writes":[6]},"BCryptEncrypt":{"category":"crypto_transform","reads":[1],"writes":[6]},
}
CONSTANTS={0x10000000:"MEM_COMMIT",0x2000:"MEM_RESERVE",0x40:"PAGE_EXECUTE_READWRITE",0x80000000:"GENERIC_READ",0x40000000:"GENERIC_WRITE",0x2:"AF_INET",0x17:"IPPROTO_UDP",0x6:"IPPROTO_TCP",200:"HTTP_OK",404:"HTTP_NOT_FOUND"}


def plan(goal:str, known:list[str]|None=None):
    g=goal.lower(); steps=[]
    if known: steps.append({"op":"cache","cost":1,"reason":"reuse established evidence"})
    steps.append({"op":"search","cost":2,"reason":"find semantic/string/name seeds"})
    if any(x in g for x in ("field","class","struct","object")): steps += [{"op":"packet","cost":4,"reason":"collect compact field/call evidence"},{"op":"ctree","cost":5,"reason":"recover member accesses"}]
    elif any(x in g for x in ("flow","source","sink","where did","comes from")): steps += [{"op":"callers","cost":3,"reason":"bound candidate path"},{"op":"taint","cost":12,"reason":"prove value dependence"}]
    elif any(x in g for x in ("protocol","packet","opcode","handler")): steps += [{"op":"packet","cost":4,"reason":"extract constants/calls"},{"op":"cfg","cost":5,"reason":"find dispatch shape"}]
    else: steps += [{"op":"packet","cost":4,"reason":"cheap semantic function summary"},{"op":"pseudocode","cost":8,"reason":"fallback only if structured facts insufficient"}]
    return sorted(steps,key=lambda x:(x["cost"],steps.index(x)))


def summary(db,target):
    p=ida_intel.packet(db,target,100); facts=p["facts"]
    effects=[]
    for c in facts.get("calls",[]):
        n=c.get("target","").split("!")[-1]
        if n in API_SEMANTICS: effects.append({"call":n,**API_SEMANTICS[n]})
    return {"ea":p["ea"],"name":p["name"],"semantic_tags":p["semantic_tags"],"effects":effects,"member_offsets":facts.get("member_offsets",[]),"constants":facts.get("constants",[]),"fingerprint":p["fingerprint"]}


def indexer_search(db,text,limit=50):
    # Prefer IDA 9.4 indexer when available; fall back to bounded names/functions.
    try:
        import ida_indexer
        rows=[]
        # API names vary across 9.4 point builds, so discover callable fuzzy/search entry points.
        for attr in ("search","find","fuzzy_search"):
            fn=getattr(ida_indexer,attr,None)
            if callable(fn):
                try:
                    vals=fn(text)
                    for x in vals:
                        rows.append({"value":safe_text(x)[:500],"api":f"ida_indexer.{attr}"})
                        if len(rows)>=limit: return rows
                except Exception: pass
        if rows: return rows
    except Exception: pass
    rx=re.compile(re.escape(text),re.I); rows=[]
    for f in db.functions.get_all():
        ea=int(f.start_ea); n=ida_query._function_name(db,ea)
        if rx.search(n): rows.append({"ea":hex(ea),"value":n,"api":"fallback-functions"})
        if len(rows)>=limit: break
    return rows


def compilation_units(db,limit=200):
    rows=[]
    for owner_name in ("compilation_units","source_files","debug_info"):
        api=getattr(db,owner_name,None)
        if api is None: continue
        for method in ("get_all","all","units"):
            fn=getattr(api,method,None)
            if callable(fn):
                try:
                    for u in fn():
                        rows.append({"name":safe_text(getattr(u,"name",u)),"start":safe_text(getattr(u,"start_ea","")),"end":safe_text(getattr(u,"end_ea","")),"source":owner_name})
                        if len(rows)>=limit: return rows
                except Exception: pass
    return rows


def runtime(db,limit=100):
    imports=ida_query._imports(db,500).get("items",[]); names=" ".join(x.get("name","") for x in imports)
    langs=[]
    rules=[("go",r"runtime\.|GoBuild|runtime_morestack"),("rust",r"rust_|core::|alloc::|panic"),("swift",r"swift_|\$s[A-Za-z0-9_]"),("objc",r"objc_msgSend|objc_retain|NS[A-Z]"),("msvc",r"__CxxFrameHandler|RTTI|\?\?")]
    for lang,pat in rules:
        if re.search(pat,names,re.I): langs.append(lang)
    samples=[]
    for f in db.functions.get_all():
        n=ida_query._function_name(db,int(f.start_ea))
        if any(re.search(pat,n,re.I) for _,pat in rules): samples.append({"ea":hex(int(f.start_ea)),"name":n})
        if len(samples)>=limit: break
    return {"languages":langs,"samples":samples}


def recover_stack_strings(db,target,limit=100):
    ea=ida_query._resolve_function(db,target); f=db.functions.get_at(ea); out=[]
    try:
        import idautils, ida_ua
        run=[]
        for h in idautils.Heads(int(f.start_ea),int(f.end_ea)):
            m=ida_ua.print_insn_mnem(h).lower(); op1=ida_ua.print_operand(h,0); op2=ida_ua.print_operand(h,1)
            if m.startswith("mov") and ("sp" in op1.lower() or "bp" in op1.lower()) and re.search(r"0x[0-9a-f]+|\d+",op2,re.I):
                run.append({"ea":hex(int(h)),"dst":op1,"src":op2})
                if len(run)>=4:
                    out.append({"kind":"stack-store-run","stores":run[-16:]})
                    if len(out)>=limit: break
            else:
                if len(run)<4: run=[]
    except Exception: pass
    return {"ea":hex(ea),"candidates":out,"note":"Candidates require decoding/verification; transformed strings are not treated as literals."}


def semantic_constants(db,target):
    p=ida_intel.packet(db,target,200); out=[]
    for c in p["facts"].get("constants",[]):
        try: v=int(c["value"],0)
        except Exception: continue
        meaning=CONSTANTS.get(v) or c.get("meaning")
        if meaning: out.append({**c,"meaning":meaning})
    return {"ea":p["ea"],"constants":out}


def verify(db,target):
    p=ida_intel.packet(db,target,120); warnings=[]
    if not p["facts"].get("calls") and p["size"]>100: warnings.append("no structured calls recovered; inspect CFG/disassembly")
    offs=defaultdict(set)
    for m in p["facts"].get("member_offsets",[]): offs[m["offset"]].add(m.get("size"))
    conflicts=[{"offset":o,"sizes":sorted(str(x) for x in s)} for o,s in offs.items() if len(s)>1]
    return {"ea":p["ea"],"name":p["name"],"field_width_conflicts":conflicts,"warnings":warnings,"recommended":"redecompile after applying types and compare structured facts"}


def frontier_db(root):
    p=root/"frontier.sqlite"; con=sqlite3.connect(p)
    con.execute("CREATE TABLE IF NOT EXISTS questions(id INTEGER PRIMARY KEY,text TEXT,ea TEXT,priority REAL,cost REAL,status TEXT DEFAULT 'open',investigator TEXT,created REAL,unknown_id TEXT,required_authority TEXT,evidence_ids_json TEXT DEFAULT '[]')")
    cols={r[1] for r in con.execute("PRAGMA table_info(questions)")}
    for name,decl in (("unknown_id","TEXT"),("required_authority","TEXT"),("evidence_ids_json","TEXT DEFAULT '[]'")):
        if name not in cols: con.execute(f"ALTER TABLE questions ADD COLUMN {name} {decl}")
    con.commit(); return p,con

def frontier_add(con,text,ea,priority,cost,investigator,unknown_id=None,required_authority=None):
    con.execute("INSERT INTO questions(text,ea,priority,cost,investigator,created,unknown_id,required_authority,evidence_ids_json) VALUES(?,?,?,?,?,?,?,?,?)",(text,ea,priority,cost,investigator,time.time(),unknown_id,required_authority,"[]")); con.commit()

def frontier_next(con,limit=20):
    return [{"id":r[0],"text":r[1],"ea":r[2],"priority":r[3],"cost":r[4],"investigator":r[5],"unknown_id":r[6],"required_authority":r[7],"evidence_ids":json.loads(r[8] or "[]"),"utility":round(r[3]/max(r[4],.1),3)} for r in con.execute("SELECT id,text,ea,priority,cost,investigator,unknown_id,required_authority,evidence_ids_json FROM questions WHERE status='open' ORDER BY priority/cost DESC LIMIT ?",(limit,))]


def specialist(kind,goal):
    recipes={
      "protocol":["semantic search for packet/opcode/dispatch seeds","extract canonical packets","recover dispatch table","taint input buffer to handlers"],
      "cpp-class":["find RTTI/vtables","resolve indirect calls","aggregate this+offset accesses","verify constructors/destructors"],
      "crypto":["find crypto imports/constants","identify callers","trace input/output buffers","verify algorithm assumptions"],
      "filesystem":["find path/file APIs","trace filename and buffers","group wrappers","verify modes/error paths"],
      "rendering":["find graphics API imports","rank high fan-in wrappers","recover object layouts","trace frame/update entry points"],
      "version-diff":["build profile-matched semantic indexes","exact fingerprint matches","weighted unmatched matching","record changed/unknown behavior separately","propagate only verified names/types"],
      "crash":["record exact crash symptom/build identity","locate static candidate paths","inspect exception/error handling","use a bounded controlled process scenario when static evidence cannot answer reachability","record unresolved alternatives"],
      "reconstruction":["turn required behaviors into reconstruction obligations","bind each obligation to an implementation owner","capture positive/negative/malformed original cases","capture reconstruction cases","close only with comparable verifier evidence"],
      "unknown-audit":["list non-resolved unknown heads","prioritize contradicted/high-severity items","choose the cheapest probe meeting required authority","update by expected revision","do not mark resolved without qualifying evidence"],
      "process-capture":["declare exact command/cwd/environment and snapshot paths","run bounded capture","preserve truncation as unknown","compare original and candidate by dimension","localize first divergence"],
    }
    return {"investigator":kind,"goal":goal,"steps":recipes.get(kind,recipes["protocol"])}


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); sub=ap.add_subparsers(dest="cmd",required=True)
    p=sub.add_parser("plan"); p.add_argument("goal"); p.add_argument("--known",action="append")
    s=sub.add_parser("summary"); s.add_argument("target")
    i=sub.add_parser("index-search"); i.add_argument("text"); i.add_argument("--limit",type=int,default=50)
    sub.add_parser("compilation-units"); sub.add_parser("runtime")
    st=sub.add_parser("stack-strings"); st.add_argument("target")
    c=sub.add_parser("constants"); c.add_argument("target")
    v=sub.add_parser("verify"); v.add_argument("target")
    sp=sub.add_parser("investigator"); sp.add_argument("kind",choices=("protocol","cpp-class","crypto","filesystem","rendering","version-diff","crash","reconstruction","unknown-audit","process-capture")); sp.add_argument("goal")
    fa=sub.add_parser("frontier-add"); fa.add_argument("text"); fa.add_argument("--ea"); fa.add_argument("--priority",type=float,default=1.0); fa.add_argument("--cost",type=float,default=1.0); fa.add_argument("--investigator",default="general"); fa.add_argument("--unknown-id"); fa.add_argument("--required-authority")
    fn=sub.add_parser("frontier-next"); fn.add_argument("--limit",type=int,default=20)
    a=ap.parse_args()
    with open_database(a.binary) as db:
        root=ensure_state(a.binary,ida_query._metadata(db))
        if a.cmd=="plan": result=plan(a.goal,a.known)
        elif a.cmd=="summary": result=summary(db,a.target)
        elif a.cmd=="index-search": result=indexer_search(db,a.text,a.limit)
        elif a.cmd=="compilation-units": result=compilation_units(db)
        elif a.cmd=="runtime": result=runtime(db)
        elif a.cmd=="stack-strings": result=recover_stack_strings(db,a.target)
        elif a.cmd=="constants": result=semantic_constants(db,a.target)
        elif a.cmd=="verify": result=verify(db,a.target)
        elif a.cmd=="investigator": result=specialist(a.kind,a.goal)
        else:
            path,con=frontier_db(root)
            if a.cmd=="frontier-add": frontier_add(con,a.text,a.ea,a.priority,a.cost,a.investigator,a.unknown_id,a.required_authority); result={"added":True,"database":str(path),"unknown_id":a.unknown_id}
            else: result=frontier_next(con,a.limit)
            con.close()
        out=root/"queries"/f"advanced_{a.cmd}.json"; out.write_text(json.dumps(result,indent=2,ensure_ascii=False,default=str)+"\n",encoding="utf-8")
        print(json.dumps({"saved":str(out),"result":result},indent=2,ensure_ascii=False,default=str))
    return 0
if __name__=="__main__": raise SystemExit(main())
