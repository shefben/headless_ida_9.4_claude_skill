"""Bounded interprocedural microcode value/call graph with explicit unknowns.

Local def/use edges are derived from Hex-Rays microcode operand identities. Cross-function traversal
follows only direct or uniquely resolved-indirect call edges. Ambiguous candidates, alias effects,
missing formal bindings, budget exhaustion, and omitted data remain explicit unknowns.
"""
from __future__ import annotations
import argparse, json
from collections import deque
from _ida_session import open_database
from _common import ensure_state
import ida_query, ida_taint, ida_indirect


def trace(db, seed, *, maturity="locopt", max_depth=3, max_functions=16, max_calls=256, max_nodes=5000, max_edges=10000, events_per_function=1200):
    seed_ea=ida_query._resolve_function(db,seed); pending=deque([(seed_ea,0)]); visited=set(); nodes=[]; edges=[]; procedures=[]; unknowns=[]; call_sites=0; truncated=False
    while pending:
        ea,depth=pending.popleft()
        if ea in visited: continue
        if len(procedures)>=max_functions:
            truncated=True; unknowns.append({"procedure":hex(ea),"address":None,"reason":"function budget reached"}); break
        visited.add(ea)
        try: fea,events,defs,uses=ida_taint.analyze(db,hex(ea),maturity,events_per_function)
        except Exception as exc:
            unknowns.append({"procedure":hex(ea),"address":None,"reason":f"microcode unavailable: {exc}"}); continue
        procedures.append({"address":hex(ea),"name":ida_query._function_name(db,ea),"depth":depth,"events_observed":len(events)})
        event_ids={}
        for ev in events:
            if len(nodes)>=max_nodes: truncated=True; break
            nid=f"{ea:x}/op:{ev['idx']}"; event_ids[ev['idx']]=nid; nodes.append({"id":nid,"procedure":hex(ea),"kind":"operation","event":ev})
        # Connect each use to the closest preceding observed definition of the same microcode identity.
        for value,use_idxs in uses.items():
            dlist=sorted(defs.get(value,[]))
            for use_idx in sorted(use_idxs):
                prior=[d for d in dlist if d<use_idx]
                if not prior: continue
                d=prior[-1]
                if d not in event_ids or use_idx not in event_ids: continue
                if len(edges)>=max_edges: truncated=True; break
                edges.append({"source":event_ids[d],"target":event_ids[use_idx],"kind":"def-use","status":"derived","value":value})
            if truncated and len(edges)>=max_edges: break
        if truncated and (len(nodes)>=max_nodes or len(edges)>=max_edges): break
        try: call_info=ida_indirect.resolve(db,hex(ea),limit=max_calls-call_sites)
        except Exception as exc:
            unknowns.append({"procedure":hex(ea),"address":None,"reason":f"call resolution unavailable: {exc}"}); continue
        for call in call_info.get("call_edges",[]):
            if call_sites>=max_calls:
                truncated=True; unknowns.append({"procedure":hex(ea),"address":call.get("callsite"),"reason":"call-site budget reached"}); break
            call_sites+=1; resolution=call.get("resolution","unresolved")
            if resolution=="candidate":
                unknowns.append({"procedure":hex(ea),"address":call.get("callsite"),"reason":"ambiguous indirect-call candidates not traversed","candidates":call.get("candidates",[])})
                continue
            if resolution=="unresolved":
                unknowns.append({"procedure":hex(ea),"address":call.get("callsite"),"reason":"unresolved call target"}); continue
            for target in call.get("targets",[])[:16]:
                try: dst=int(target["ea"],0)
                except Exception: continue
                if len(edges)>=max_edges: truncated=True; break
                # Link from a synthetic callsite node when the exact microcode event was omitted/unmatched.
                call_nid=f"{ea:x}/call:{call.get('callsite')}"
                if not any(n["id"]==call_nid for n in nodes):
                    if len(nodes)>=max_nodes: truncated=True; break
                    nodes.append({"id":call_nid,"procedure":hex(ea),"kind":"callsite","event":{"ea":call.get("callsite"),"operand":call.get("operand")}})
                edges.append({"source":call_nid,"target":hex(dst),"kind":"call","status":resolution,"value":None})
                if depth<max_depth: pending.append((dst,depth+1))
                elif dst not in visited:
                    truncated=True; unknowns.append({"procedure":hex(ea),"address":call.get("callsite"),"reason":"call-depth budget reached","target":hex(dst)})
    return {"seed":hex(seed_ea),"maturity":maturity,"nodes":nodes,"edges":edges,"procedures":procedures,"unknowns":unknowns,"total_nodes":len(nodes),"total_edges":len(edges),"call_sites":call_sites,"truncated":truncated,"limitations":["local def/use identities are decompiler-derived","memory aliasing and persistent/global side effects are approximate","cross-function argument/return bindings are not claimed unless separately proven"]}


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); ap.add_argument("procedure")
    ap.add_argument("--maturity",choices=("generated","preoptimized","calls","locopt","glbopt1","glbopt2","glbopt3","lvars"),default="locopt")
    ap.add_argument("--max-depth",type=int,default=3); ap.add_argument("--max-functions",type=int,default=16); ap.add_argument("--max-call-sites",type=int,default=256); ap.add_argument("--max-nodes",type=int,default=5000); ap.add_argument("--max-edges",type=int,default=10000); ap.add_argument("--events-per-function",type=int,default=1200)
    a=ap.parse_args()
    for name,val,lo,hi in (("max-depth",a.max_depth,0,16),("max-functions",a.max_functions,1,64),("max-call-sites",a.max_call_sites,1,4096),("max-nodes",a.max_nodes,1,20000),("max-edges",a.max_edges,1,40000)):
        if not lo<=val<=hi: raise SystemExit(f"--{name} must be {lo}..{hi}")
    with open_database(a.binary) as db:
        root=ensure_state(a.binary,ida_query._metadata(db)); result=trace(db,a.procedure,maturity=a.maturity,max_depth=a.max_depth,max_functions=a.max_functions,max_calls=a.max_call_sites,max_nodes=a.max_nodes,max_edges=a.max_edges,events_per_function=a.events_per_function)
        out=root/"queries"/f"value_trace_{int(result['seed'],0):x}.json"; out.write_text(json.dumps(result,indent=2,ensure_ascii=False,default=str)+"\n",encoding="utf-8")
        print(json.dumps({"saved":str(out),"procedures":len(result["procedures"]),"nodes":result["total_nodes"],"edges":result["total_edges"],"unknowns":len(result["unknowns"]),"truncated":result["truncated"]},indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
