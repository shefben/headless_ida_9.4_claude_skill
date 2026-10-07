"""Plan, preview, apply, verify, and roll back high-confidence semantic findings.

Database writes are explicit. Default mode is `plan`, which records proposed changes and current
names/comments without modifying the IDB. `apply` writes the changes and stores a rollback manifest.
`rollback` restores recorded names/comments from a previous manifest. Prototypes are verified after
application but rollback of complex type graphs is intentionally not guessed.
"""
from __future__ import annotations
import argparse, json, time
from pathlib import Path
from _ida_session import open_database
from _common import ensure_state, bump_analysis_epoch
import ida_query

def current(ea:int):
    import ida_name, ida_bytes
    return {"name":ida_name.get_name(ea) or "","comment":ida_bytes.get_cmt(ea,False) or ""}

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); ap.add_argument("findings_json")
    ap.add_argument("--mode",choices=("plan","apply","rollback"),default="plan"); ap.add_argument("--min-confidence",type=float,default=.90); ap.add_argument("--manifest")
    args=ap.parse_args(); source=Path(args.findings_json); payload=json.loads(source.read_text(encoding="utf-8")) if args.mode!="rollback" else {}
    writing=args.mode in {"apply","rollback"}; results=[]; skipped=[]
    with open_database(args.binary,save_on_close=writing) as db:
        root=ensure_state(args.binary,ida_query._metadata(db)); import ida_name, ida_bytes
        if args.mode=="rollback":
            mp=Path(args.manifest or args.findings_json); man=json.loads(mp.read_text(encoding="utf-8"))
            for item in man.get("changes",[]):
                ea=int(item["ea"],0); before=item.get("before",{})
                ok_name=ida_name.set_name(ea,before.get("name","") or f"sub_{ea:x}",ida_name.SN_FORCE)
                ok_cmt=ida_bytes.set_cmt(ea,before.get("comment","") or "",False)
                results.append({"ea":hex(ea),"restored_name":bool(ok_name),"restored_comment":bool(ok_cmt)})
            epoch=bump_analysis_epoch(args.binary)
            print(json.dumps({"mode":"rollback","results":results,"analysis_epoch":epoch},indent=2)); return 0
        planned=[]
        for item in payload.get("functions",[]):
            conf=float(item.get("confidence",0)); ea=int(str(item["ea"]),0)
            if conf<args.min_confidence: skipped.append({"ea":hex(ea),"reason":"low_confidence","confidence":conf}); continue
            planned.append({"ea":hex(ea),"confidence":conf,"before":current(ea),"after":{"name":item.get("name"),"comment":item.get("comment"),"prototype":item.get("prototype")}})
        manifest=root/"queries"/f"apply_manifest_{int(time.time())}.json"
        manifest.write_text(json.dumps({"source":str(source.resolve()),"mode":args.mode,"changes":planned},indent=2)+"\n",encoding="utf-8")
        if args.mode=="plan": print(json.dumps({"mode":"plan","manifest":str(manifest),"planned":planned,"skipped":skipped},indent=2)); return 0
        for rec in planned:
            ea=int(rec["ea"],0); after=rec["after"]; changes=[]; verify=[]
            if after.get("name"):
                ok=ida_name.set_name(ea,after["name"],ida_name.SN_FORCE); changes.append("name") if ok else None; verify.append({"name":ida_name.get_name(ea),"expected":after["name"],"ok":ida_name.get_name(ea)==after["name"]})
            if after.get("comment"):
                ok=ida_bytes.set_cmt(ea,after["comment"],False); changes.append("comment") if ok else None; verify.append({"comment_ok":(ida_bytes.get_cmt(ea,False) or "")==after["comment"]})
            if after.get("prototype"):
                f=db.functions.get_at(ea)
                try:
                    ok=bool(f and hasattr(db.functions,"apply_declaration") and db.functions.apply_declaration(f,after["prototype"])); changes.append("prototype") if ok else None; verify.append({"prototype_applied":ok})
                except Exception as exc: verify.append({"prototype_applied":False,"error":str(exc)})
            results.append({"ea":hex(ea),"changes":changes,"verification":verify})
        epoch=bump_analysis_epoch(args.binary); final={"mode":"apply","manifest":str(manifest),"results":results,"skipped":skipped,"analysis_epoch":epoch}; (root/"queries"/"applied_findings.json").write_text(json.dumps(final,indent=2)+"\n",encoding="utf-8"); print(json.dumps(final,indent=2))
    return 0
if __name__=="__main__": raise SystemExit(main())
