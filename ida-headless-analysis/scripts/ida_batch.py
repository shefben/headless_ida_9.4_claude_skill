"""Execute many IDA queries in one mandatory IDA/Hex-Rays session.

Plan format:
{"steps":[{"id":"triage","op":"triage"},{"id":"s","op":"string","text":"error"},
          {"id":"f","op":"ctree","target":"0x140001000"}]}

The process opens IDA once, runs every step, and writes one bounded result packet.  This is the
preferred path for multi-step Claude investigations because repeated idalib startup is expensive.
"""
from __future__ import annotations
import argparse, json, re
from pathlib import Path
from typing import Any
from _ida_session import open_database
from _common import ensure_state, safe_text
import ida_query


def _ctree(db, target: str, limit: int) -> dict[str, Any]:
    ea = ida_query._resolve_function(db, target)
    fn = db.pseudocode.decompile(ea)
    out: dict[str, Any] = {"ea":hex(ea),"name":ida_query._function_name(db,ea),
                           "calls":[],"strings":[],"constants":[],"member_offsets":[]}
    seen = set()
    for expr in fn.walk_expressions():
        if getattr(expr,"is_call",False) and len(out["calls"]) < limit:
            callee = getattr(expr,"x",None)
            name = safe_text(getattr(callee,"obj_name", "")) or safe_text(getattr(callee,"helper_name", ""))
            key=(int(getattr(expr,"ea",0)),name)
            if key not in seen:
                seen.add(key); out["calls"].append({"ea":hex(key[0]),"target":name})
        if getattr(expr,"is_string",False) and len(out["strings"]) < limit:
            v=safe_text(getattr(expr,"string",""))
            if v: out["strings"].append({"ea":hex(int(getattr(expr,"ea",0))),"value":v[:500]})
        if getattr(expr,"is_number",False) and len(out["constants"]) < limit:
            n=getattr(expr,"number",None)
            try: out["constants"].append({"ea":hex(int(getattr(expr,"ea",0))),"value":hex(int(n.unsigned_value))})
            except Exception: pass
        off=getattr(expr,"member_offset",None)
        if off is not None and len(out["member_offsets"]) < limit:
            out["member_offsets"].append({"ea":hex(int(getattr(expr,"ea",0))),"offset":hex(int(off))})
    return out


def execute_step(db, step: dict[str, Any]) -> Any:
    op=step["op"]; limit=max(1,int(step.get("limit",30)))
    if op=="metadata": return ida_query._metadata(db)
    if op=="triage":
        return {"metadata":ida_query._metadata(db),"segments":ida_query._segments(db,min(limit,30)),
                "imports":ida_query._imports(db,limit),"exports":ida_query._entries(db,limit)}
    if op=="string": return ida_query._fast_string_search(db,step["text"],limit,step.get("encoding","auto"),bool(step.get("nul",False)))
    if op=="strings": return ida_query._strings_discovery(db,limit,step.get("regex"),step.get("contains"))
    if op=="functions": return ida_query._functions(db,limit,step.get("regex"))
    if op=="ctree": return _ctree(db,step["target"],limit)
    ea=ida_query._resolve_function(db,step["target"])
    if op=="function": return ida_query._function_summary(db,ea,limit)
    if op=="callers": return ida_query._callers(db,ea,limit)
    if op=="callees": return ida_query._callees(db,ea,limit)
    if op=="cfg": return ida_query._cfg(db,ea,limit)
    if op=="pseudocode": return ida_query._pseudocode(db,ea,int(step.get("lines",180)))
    if op=="disasm": return ida_query._disasm(db,ea,int(step.get("lines",80)))
    if op=="microcode": return ida_query._microcode(db,ea,int(step.get("lines",120)),step.get("match"),step.get("maturity","locopt"))
    raise ValueError(f"unknown batch operation: {op}")


def run_plan(binary: str, plan: dict[str, Any]) -> dict[str, Any]:
    steps=plan.get("steps",[])
    if not isinstance(steps,list) or not steps: raise ValueError("plan requires non-empty steps[]")
    if len(steps)>100: raise ValueError("batch limited to 100 steps")
    with open_database(binary) as db:
        root=ensure_state(binary,ida_query._metadata(db)); results={}; errors=[]
        for i,step in enumerate(steps):
            sid=safe_text(step.get("id") or f"step_{i}")
            try: results[sid]=execute_step(db,step)
            except Exception as exc:
                errors.append({"id":sid,"op":step.get("op"),"error":f"{type(exc).__name__}: {exc}"})
                if step.get("required",False): break
        payload={"binary":binary,"steps":len(steps),"results":results,"errors":errors}
        out=root/"queries"/"batch_latest.json"; out.write_text(json.dumps(payload,indent=2,ensure_ascii=False,default=str)+"\n",encoding="utf-8")
        payload["saved"]=str(out); return payload


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); ap.add_argument("plan_json")
    a=ap.parse_args(); plan=json.loads(Path(a.plan_json).read_text(encoding="utf-8")); r=run_plan(a.binary,plan)
    print(json.dumps({"saved":r["saved"],"steps":r["steps"],"errors":r["errors"],"result_ids":list(r["results"])},indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
