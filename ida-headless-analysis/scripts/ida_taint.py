"""Bounded microcode def-use, backward slicing, and lightweight taint propagation.

This is deliberately conservative. It follows register/stack/global operand identities through
microcode instructions, call arguments, and return-like uses. Memory aliasing is approximate and
all output carries that caveat. The goal is to prove substantially more than a call-path while
remaining token-bounded.
"""
from __future__ import annotations
import argparse, json, re
from collections import defaultdict, deque
from _ida_session import open_database
from _common import ensure_state, safe_text
import ida_query, ida_dataflow


def op_id(op):
    if getattr(op,"is_register",False): return "reg:"+safe_text(getattr(op,"register_name",""))
    if getattr(op,"is_stack_variable",False): return "stk:"+str(getattr(op,"stack_offset",0))
    if getattr(op,"is_global_address",False):
        try: return "glob:"+hex(int(getattr(op,"global_address")))
        except Exception: return None
    try:
        t=safe_text(op.to_text()).strip()
        if t and len(t)<120: return "txt:"+t
    except Exception: pass
    return None


def analyze(db,target,maturity="locopt",max_events=600):
    ea=ida_query._resolve_function(db,target); f=db.functions.get_at(ea); mba=db.microcode.generate(f,ida_dataflow.maturity_from_name(maturity))
    events=[]; defs=defaultdict(list); uses=defaultdict(list)
    for idx,insn in enumerate(mba.instructions()):
        if idx>=max_events: break
        ops=list(insn.operands()); ids=[op_id(x) for x in ops]
        rec={"idx":idx,"ea":hex(int(getattr(insn,"ea",0))),"opcode":safe_text(getattr(getattr(insn,"opcode",None),"name",getattr(insn,"opcode",""))),"operands":ids,"is_call":bool(insn.is_call())}
        events.append(rec)
        # Heuristic convention: operand 0 is destination for move/arithmetic-like operations.
        if ids:
            opc=rec["opcode"].lower()
            if ids[0] and any(k in opc for k in ("mov","add","sub","xor","or","and","shl","shr","ldx")): defs[ids[0]].append(idx)
            for oid in ids[1:] if len(ids)>1 else ids:
                if oid: uses[oid].append(idx)
            if rec["is_call"]:
                for oid in ids:
                    if oid: uses[oid].append(idx)
    return ea,events,defs,uses


def backward(events,defs,uses,seed,max_nodes=200):
    q=deque([seed]); seen_vals={seed}; seen_events=set(); out=[]
    while q and len(out)<max_nodes:
        v=q.popleft()
        for idx in defs.get(v,[]):
            if idx in seen_events: continue
            seen_events.add(idx); ev=events[idx]; out.append(ev)
            for oid in ev["operands"][1:]:
                if oid and oid not in seen_vals: seen_vals.add(oid); q.append(oid)
    out.sort(key=lambda x:x["idx"]); return out


def forward(events,defs,uses,seed,max_nodes=200):
    q=deque([seed]); seen_vals={seed}; seen_events=set(); out=[]
    while q and len(out)<max_nodes:
        v=q.popleft()
        for idx in uses.get(v,[]):
            if idx in seen_events: continue
            seen_events.add(idx); ev=events[idx]; out.append(ev)
            if ev["operands"]:
                dst=ev["operands"][0]
                if dst and dst not in seen_vals: seen_vals.add(dst); q.append(dst)
    out.sort(key=lambda x:x["idx"]); return out


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); ap.add_argument("target"); ap.add_argument("seed",help="operand identity, e.g. reg:rax, stk:-32, glob:0x140...")
    ap.add_argument("--direction",choices=("backward","forward"),default="backward"); ap.add_argument("--maturity",default="locopt",choices=("generated","preoptimized","calls","locopt","glbopt1","glbopt2","glbopt3","lvars")); ap.add_argument("--max-nodes",type=int,default=200)
    a=ap.parse_args()
    with open_database(a.binary) as db:
        root=ensure_state(a.binary,ida_query._metadata(db)); ea,events,defs,uses=analyze(db,a.target,a.maturity)
        sliced=backward(events,defs,uses,a.seed,a.max_nodes) if a.direction=="backward" else forward(events,defs,uses,a.seed,a.max_nodes)
        result={"ea":hex(ea),"seed":a.seed,"direction":a.direction,"maturity":a.maturity,"events":sliced,"approximate_aliasing":True}
        out=root/"queries"/f"taint_{ea:x}_{a.direction}.json"; out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({"saved":str(out),"events":len(sliced),"seed":a.seed},indent=2))
    return 0
if __name__=="__main__": raise SystemExit(main())
