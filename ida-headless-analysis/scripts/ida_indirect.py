"""Resolve likely indirect calls, vtables, callbacks, and registration tables.

The resolver is intentionally evidence-oriented: it records the instruction, operand text, nearby
data references, and candidate code pointers. It never invents a concrete target when IDA cannot
support one. Useful for C++ call graphs where direct xrefs alone miss the interesting edges.
"""
from __future__ import annotations
import argparse, json
from _ida_session import open_database
from _common import ensure_state, safe_text
import ida_query


def resolve(db,target,limit=200):
    ea=ida_query._resolve_function(db,target); f=db.functions.get_at(ea); out=[]
    import idautils, ida_ua, ida_funcs, ida_name, ida_bytes, ida_idaapi
    for head in idautils.Heads(int(f.start_ea),int(f.end_ea)):
        ins=ida_ua.insn_t()
        if not ida_ua.decode_insn(ins,head): continue
        mnem=safe_text(ida_ua.print_insn_mnem(head)).lower()
        if not (mnem.startswith("call") or mnem in {"jmp","blr","br","jalr"}): continue
        direct=list(idautils.CodeRefsFrom(head,False))
        text=safe_text(ida_ua.print_operand(head,0)); data_refs=[int(x) for x in idautils.DataRefsFrom(head)]
        if direct:
            targets=[]
            for dst in direct[:16]:
                fn=ida_funcs.get_func(dst); fea=int(fn.start_ea) if fn else int(dst)
                targets.append({"ea":hex(fea),"name":ida_name.get_name(fea) or f"sub_{fea:x}","resolution":"direct"})
            out.append({"callsite":hex(int(head)),"operand":text,"data_refs":[],"targets":targets,"candidates":[],"resolution":"direct"})
            if len(out)>=limit: break
            continue
        candidates=[]
        for dr in data_refs[:16]:
            val=ida_bytes.get_qword(dr) if ida_bytes.is_loaded(dr) else ida_idaapi.BADADDR
            if val!=ida_idaapi.BADADDR:
                fn=ida_funcs.get_func(val)
                if fn: candidates.append({"ea":hex(int(fn.start_ea)),"name":ida_name.get_name(int(fn.start_ea)) or f"sub_{int(fn.start_ea):x}","via":hex(dr)})
        resolution="resolved-indirect" if len(candidates)==1 else ("candidate" if candidates else "unresolved")
        targets=candidates if resolution=="resolved-indirect" else []
        out.append({"callsite":hex(int(head)),"operand":text,"data_refs":[hex(x) for x in data_refs[:16]],"targets":targets,"candidates":candidates,"resolution":resolution})
        if len(out)>=limit: break
    return {"ea":hex(ea),"call_edges":out,"indirect_calls":[x for x in out if x.get("resolution")!="direct"],"resolved_indirect":sum(x.get("resolution")=="resolved-indirect" for x in out),"ambiguous_candidates":sum(x.get("resolution")=="candidate" for x in out),"unresolved":sum(x.get("resolution")=="unresolved" for x in out),"note":"Only direct and uniquely resolved-indirect edges are concrete. Candidate edges remain frontier hypotheses."}


def vtables(db,limit=200):
    import idautils, ida_name, ida_bytes, ida_funcs
    rows=[]
    for ea,name in idautils.Names():
        low=name.lower()
        if not any(x in low for x in ("vftable","vtable","`vftable'")): continue
        slots=[]
        ptr=8 if safe_text(getattr(db.metadata,"bitness",64)) in {"64","64-bit"} else 4
        for i in range(64):
            p=ida_bytes.get_qword(ea+i*ptr) if ptr==8 else ida_bytes.get_dword(ea+i*ptr)
            f=ida_funcs.get_func(p)
            if not f: break
            slots.append({"slot":i,"ea":hex(int(f.start_ea)),"name":ida_name.get_name(int(f.start_ea)) or f"sub_{int(f.start_ea):x}"})
        rows.append({"ea":hex(int(ea)),"name":name,"slots":slots})
        if len(rows)>=limit: break
    return rows


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); sub=ap.add_subparsers(dest="cmd",required=True)
    r=sub.add_parser("resolve"); r.add_argument("target"); r.add_argument("--limit",type=int,default=200)
    v=sub.add_parser("vtables"); v.add_argument("--limit",type=int,default=200)
    a=ap.parse_args()
    with open_database(a.binary) as db:
        root=ensure_state(a.binary,ida_query._metadata(db)); result=resolve(db,a.target,a.limit) if a.cmd=="resolve" else vtables(db,a.limit)
        out=root/"queries"/f"indirect_{a.cmd}.json"; out.write_text(json.dumps(result,indent=2,ensure_ascii=False,default=str)+"\n",encoding="utf-8")
        print(json.dumps({"saved":str(out),"command":a.cmd,"count":len(result) if isinstance(result,list) else len(result.get("call_edges",[]))},indent=2))
    return 0
if __name__=="__main__": raise SystemExit(main())
