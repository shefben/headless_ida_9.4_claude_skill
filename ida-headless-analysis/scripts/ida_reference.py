"""Import a historical/reference source tree without confusing it with current-binary evidence."""
from __future__ import annotations
import argparse, fnmatch, json
from pathlib import Path
from typing import Any
from _common import ensure_state
from _provenance import sha256_file, semantic_id
from ida_evidence import record_evidence

DEFAULT_IGNORES = [".git/*", ".ida-re/*", "__pycache__/*", "*.pyc"]


def inventory(source: Path, patterns: list[str], max_files: int) -> dict[str, Any]:
    rows=[]; truncated=False
    for p in sorted(source.rglob("*")):
        if not p.is_file() or p.is_symlink(): continue
        rel=p.relative_to(source).as_posix()
        if any(fnmatch.fnmatch(rel, pat) for pat in patterns): continue
        if len(rows)>=max_files: truncated=True; break
        try: rows.append({"path":rel,"size":p.stat().st_size,"sha256":sha256_file(p)})
        except Exception as exc: rows.append({"path":rel,"error":str(exc)})
    root_digest=semantic_id("ref", rows)
    return {"source_root":str(source),"reference_id":root_digest,"files":rows,"truncated":truncated,"ignore_patterns":patterns}


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); ap.add_argument("source")
    ap.add_argument("--ignore",action="append",default=[]); ap.add_argument("--max-files",type=int,default=20000)
    a=ap.parse_args(); src=Path(a.source).expanduser().resolve()
    if not src.is_dir(): raise NotADirectoryError(src)
    result=inventory(src,DEFAULT_IGNORES+a.ignore,a.max_files); root=ensure_state(a.binary); out=root/"queries"/f"historical_reference_{result['reference_id'].split('_',1)[1][:16]}.json"
    out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    evidence_result={k:v for k,v in result.items() if k!="source_root"}
    ev=record_evidence(a.binary,operation="import_reference_source",result=evidence_result,parameters={"ignore_patterns":result["ignore_patterns"],"max_files":a.max_files},confidence="observed",authority="historical-reference",predicate_type="ida.reference.inventory",limitations=["reference source is historical context, not proof of current binary behavior"] + (["inventory truncated"] if result["truncated"] else []))
    print(json.dumps({"saved":str(out),"reference_id":result["reference_id"],"evidence_id":ev["evidence_id"],"files":len(result["files"]),"truncated":result["truncated"]},indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
